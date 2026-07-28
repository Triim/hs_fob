"""Integration tests for the IPv8 attestation transport.

These run on IPv8's in-memory mock harness (``TestBase`` / ``MockIPv8``), which
delivers real serialized packets between simulated nodes without touching the
network. That lets us assert the full path — encode, send, receive, decode,
validate, apply — for both message types.

Note on identity: the harness gives every node a real keypair, so the
public-key-based identity used in the handlers (``peer.mid``) is exercised
exactly as it would be on a live network.
"""

from ipv8.peer import Peer
from ipv8.test.base import TestBase

from attestation.attestation import make_attestation
from blockchain.blockchain import Blockchain
from network.community import AttestationCommunity, AttestationSettings


class AttestationCommunityTests(TestBase):
    def setUp(self):
        super().setUp()
        self.overlay_class = AttestationCommunity
        # Distinct difficulty-0 chain per node (mimics TestBase.initialize but
        # with per-node settings), so gossip between separate chains is real and
        # mining stays instant.
        self.nodes = [
            self.create_node(AttestationSettings(blockchain=Blockchain(difficulty=0)))
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

    def chain(self, i: int) -> Blockchain:
        return self.overlay(i).blockchain

    async def test_attestation_is_gossiped_and_pooled(self):
        """Node 0 broadcasts an attestation; node 1 validates and pools it."""
        tx = make_attestation("attester", "subject", "rubric", 0, True, 1)

        sent_to = self.overlay(0).broadcast_attestation(tx)
        await self.deliver_messages()

        self.assertEqual(sent_to, 1)
        self.assertEqual(len(self.chain(1).mempool), 1)
        self.assertEqual(self.chain(1).mempool[0].hash, tx.hash)

    async def test_non_attestation_is_rejected(self):
        """A generic transaction gossiped as an attestation is not pooled."""
        from blockchain.transaction import Transaction

        tx = Transaction(sender="alice", payload={"amount": 5})
        self.overlay(0).broadcast_attestation(tx)
        await self.deliver_messages()

        self.assertEqual(len(self.chain(1).mempool), 0)

    async def test_duplicate_attestation_pooled_once(self):
        """Re-broadcasting the same attestation does not double-pool it."""
        tx = make_attestation("attester", "subject", "rubric", 0, True, 1)

        self.overlay(0).broadcast_attestation(tx)
        await self.deliver_messages()
        self.overlay(0).broadcast_attestation(tx)
        await self.deliver_messages()

        self.assertEqual(len(self.chain(1).mempool), 1)

    async def test_block_is_gossiped_and_appended(self):
        """Node 0 mines a block; node 1 verifies the link and appends it."""
        tx = make_attestation("attester", "subject", "rubric", 0, True, 1)
        self.chain(0).add_transaction(tx)

        block = self.overlay(0).mine_and_broadcast_block()
        await self.deliver_messages()

        # Node 1 started from an identical genesis, so the block links cleanly.
        self.assertEqual(len(self.chain(1).blocks), 2)
        self.assertEqual(self.chain(1).last_block.hash, block.hash)
        self.assertTrue(self.chain(1).is_valid_chain())

    async def test_non_linking_block_is_rejected(self):
        """A block that does not extend node 1's chain is refused."""
        # Advance node 1 so node 0's block (index 1) no longer links to its tip.
        self.chain(1).add_transaction(
            make_attestation("x", "s", "r", 0, True, 1)
        )
        self.chain(1).add_block()
        self.assertEqual(len(self.chain(1).blocks), 2)

        self.chain(0).add_transaction(
            make_attestation("attester", "subject", "rubric", 0, True, 1)
        )
        self.overlay(0).mine_and_broadcast_block()  # index 1, wrong previous_hash
        await self.deliver_messages()

        # Node 1 keeps its own chain; the foreign block is dropped.
        self.assertEqual(len(self.chain(1).blocks), 2)
        self.assertTrue(self.chain(1).is_valid_chain())
