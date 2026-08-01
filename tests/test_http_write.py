"""Tests for the HTTP write path: submit_transaction and produce_block.

The node never signs participant transactions — the client signs, the node
validates and relays. These tests build **client-signed** transactions with real
keypairs and drive the pure write helpers against real communities (the same
MockIPv8 harness the gossip tests use), so the security-critical acceptance gate
is exercised for real. The HTTP/CORS layer itself is a thin wrapper over these
helpers and is verified live (curl) at the step's hard stop.
"""

from ipv8.peer import Peer
from ipv8.test.base import TestBase

from attestation.aggregator import make_certificate
from attestation.attestation import make_attestation
from attestation.submission import make_submission
from blockchain.blockchain import Blockchain
from crypto.keys import generate_keypair
from network.community import AttestationCommunity, AttestationSettings
from network.http_bridge import produce_block, submit_transaction


def signed_attestation(subject="subject", rubric="rubric", item_index=0):
    """A client-signed attestation whose sender is a fresh public key."""
    private_key, public_key = generate_keypair()
    tx = make_attestation(public_key, subject, rubric, item_index, True, 1, "aa")
    tx.sign(private_key)
    return tx


class HttpWriteTests(TestBase):
    def setUp(self):
        super().setUp()
        self.overlay_class = AttestationCommunity
        self.nodes = [
            self.create_node(AttestationSettings(blockchain=Blockchain()))
            for _ in range(2)
        ]
        for node in self.nodes:
            for other in self.nodes:
                if other is node:
                    continue
                public_peer = Peer(other.my_peer.public_key, other.my_peer.address)
                node.network.add_verified_peer(public_peer)
                node.network.discover_services(
                    public_peer, [AttestationCommunity.community_id]
                )
        for i in range(len(self.nodes)):
            self.patch_overlays(i)

    def chain(self, i):
        return self.overlay(i).blockchain

    # ------------------------------------------------------------- submit_transaction

    async def test_signed_attestation_is_pooled_and_gossiped(self):
        tx = signed_attestation()

        status, result = submit_transaction(self.overlay(0), tx.to_dict())
        await self.deliver_messages()

        self.assertEqual(status, 201)
        self.assertEqual(result["status"], "pooled")
        self.assertEqual(result["broadcast_to"], 1)
        self.assertTrue(result["transaction"]["signature_valid"])
        # Pooled locally and propagated to the peer.
        self.assertEqual(self.chain(0).mempool[0].hash, tx.hash)
        self.assertEqual(self.chain(1).mempool[0].hash, tx.hash)

    async def test_signed_submission_is_pooled(self):
        private_key, public_key = generate_keypair()
        tx = make_submission(public_key, "domain", "rubric", "Title", "aa", "f.pdf")
        tx.sign(private_key)

        status, result = submit_transaction(self.overlay(0), tx.to_dict())

        self.assertEqual(status, 201)
        self.assertEqual(result["transaction"]["type"], "submission")
        self.assertEqual(self.chain(0).mempool[0].hash, tx.hash)

    async def test_unsigned_transaction_is_rejected(self):
        tx = make_attestation("some-pubkey", "subject", "rubric", 0, True, 1, "aa")  # unsigned

        status, result = submit_transaction(self.overlay(0), tx.to_dict())

        self.assertEqual(status, 400)
        self.assertIn("error", result)
        self.assertEqual(len(self.chain(0).mempool), 0)

    async def test_wrong_signature_is_rejected(self):
        """A tx signed by a key other than its sender must not be accepted."""
        _, public_key = generate_keypair()
        other_private, _ = generate_keypair()
        tx = make_attestation(public_key, "subject", "rubric", 0, True, 1, "aa")
        tx.sign(other_private)  # signed, but not by `public_key`

        status, _ = submit_transaction(self.overlay(0), tx.to_dict())

        self.assertEqual(status, 400)
        self.assertEqual(len(self.chain(0).mempool), 0)

    async def test_non_participant_transaction_is_rejected(self):
        """A certificate is protocol-generated, not a participant submission."""
        cert = make_certificate("subject", "rubric", "domain", "aa", ["a"])

        status, _ = submit_transaction(self.overlay(0), cert.to_dict())

        self.assertEqual(status, 400)
        self.assertEqual(len(self.chain(0).mempool), 0)

    async def test_malformed_bodies_are_rejected(self):
        self.assertEqual(submit_transaction(self.overlay(0), "not a dict")[0], 400)
        self.assertEqual(submit_transaction(self.overlay(0), {"sender": "a"})[0], 400)
        self.assertEqual(len(self.chain(0).mempool), 0)

    async def test_duplicate_submission_is_idempotent(self):
        tx = signed_attestation()

        first, _ = submit_transaction(self.overlay(0), tx.to_dict())
        second, result = submit_transaction(self.overlay(0), tx.to_dict())

        self.assertEqual(first, 201)
        self.assertEqual(second, 200)
        self.assertEqual(result["status"], "already_known")
        self.assertEqual(len(self.chain(0).mempool), 1)  # not double-pooled

    # ------------------------------------------------------------------ produce_block

    async def test_produce_block_on_empty_mempool_makes_nothing(self):
        status, result = produce_block(self.overlay(0))
        self.assertEqual(status, 200)
        self.assertEqual(result["status"], "empty")
        self.assertEqual(len(self.chain(0).blocks), 1)  # only genesis

    async def test_produce_block_mines_pooled_and_validates(self):
        submit_transaction(self.overlay(0), signed_attestation().to_dict())

        status, result = produce_block(self.overlay(0))
        await self.deliver_messages()

        self.assertEqual(status, 201)
        self.assertEqual(result["status"], "produced")
        self.assertEqual(len(self.chain(0).blocks), 2)
        self.assertTrue(self.chain(0).is_valid_chain())
        # The produced block gossiped; the peer appended it.
        self.assertEqual(len(self.chain(1).blocks), 2)
        self.assertTrue(self.chain(1).is_valid_chain())
