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
from crypto.keys import generate_keypair
from network.community import AttestationCommunity, AttestationSettings
from reputation.genesis import GENESIS_AUTHORITY_KEYS

AUTHORITY_KEY = GENESIS_AUTHORITY_KEYS["genesis-authority"][0]

# Each logical attester name gets a stable keypair, so distinct names stay
# distinct senders (keeping genuine forks) while every attestation is validly
# signed — participant transactions must be signed for the chain to be valid.
_ATTESTER_KEYS: dict[str, tuple] = {}


def signed_attestation(name, subject, rubric, item_index, verdict=True, stake=1):
    """A signed attestation whose sender is ``name``'s reproducible public key."""
    if name not in _ATTESTER_KEYS:
        _ATTESTER_KEYS[name] = generate_keypair()
    private_key, public_key = _ATTESTER_KEYS[name]
    tx = make_attestation(public_key, subject, rubric, item_index, verdict, stake)
    tx.sign(private_key)
    return tx


class AttestationCommunityTests(TestBase):
    def setUp(self):
        super().setUp()
        self.overlay_class = AttestationCommunity
        # Distinct chain per node (mimics TestBase.initialize but with per-node
        # settings), so gossip between separate chains is real.
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

    def chain(self, i: int) -> Blockchain:
        return self.overlay(i).blockchain

    async def test_attestation_is_gossiped_and_pooled(self):
        """Node 0 broadcasts an attestation; node 1 validates and pools it."""
        tx = signed_attestation("attester", "subject", "rubric", 0, True, 1)

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
        tx = signed_attestation("attester", "subject", "rubric", 0, True, 1)

        self.overlay(0).broadcast_attestation(tx)
        await self.deliver_messages()
        self.overlay(0).broadcast_attestation(tx)
        await self.deliver_messages()

        self.assertEqual(len(self.chain(1).mempool), 1)

    async def test_block_is_gossiped_and_appended(self):
        """Node 0 mines a block; node 1 verifies the link and appends it."""
        tx = signed_attestation("attester", "subject", "rubric", 0, True, 1)
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
            signed_attestation("x", "s", "r", 0, True, 1)
        )
        self.chain(1).add_block(producer_key=AUTHORITY_KEY)  # signed so it validates
        self.assertEqual(len(self.chain(1).blocks), 2)

        self.chain(0).add_transaction(
            signed_attestation("attester", "subject", "rubric", 0, True, 1)
        )
        self.overlay(0).mine_and_broadcast_block()  # index 1, wrong previous_hash
        await self.deliver_messages()

        # Node 1 keeps its own chain; the foreign block is dropped.
        self.assertEqual(len(self.chain(1).blocks), 2)
        self.assertTrue(self.chain(1).is_valid_chain())

    async def test_forked_nodes_converge_on_the_longer_chain(self):
        """Two nodes fork at height 1; with neither fork finalized, length breaks
        the tie and the shorter adopts the longer via sync."""
        # Each node independently produces a competing block at height 1 (no
        # exchange yet), so their chains diverge.
        self.chain(0).add_transaction(signed_attestation("a0", "s", "r", 0, True, 1))
        self.chain(0).add_block(producer_key=AUTHORITY_KEY)
        self.chain(1).add_transaction(signed_attestation("a1", "s", "r", 0, True, 1))
        self.chain(1).add_block(producer_key=AUTHORITY_KEY)
        # Node 0 extends its fork so it is strictly longer.
        self.chain(0).add_transaction(signed_attestation("a2", "s", "r", 1, True, 1))
        self.chain(0).add_block(producer_key=AUTHORITY_KEY)
        self.assertEqual(len(self.chain(0).blocks), 3)
        self.assertEqual(len(self.chain(1).blocks), 2)

        # Node 0 advertises its tip; node 1 cannot append it (fork), requests the
        # whole chain, and adopts the longer one.
        self.overlay(0).broadcast_block(self.chain(0).last_block)
        await self.deliver_messages()

        self.assertEqual(len(self.chain(1).blocks), 3)
        self.assertEqual(self.chain(1).last_block.hash, self.chain(0).last_block.hash)
        self.assertTrue(self.chain(1).is_valid_chain())

    async def test_shorter_candidate_is_refused_on_divergence(self):
        """A node offered a shorter forked chain keeps its own (with neither fork
        finalized, the longer chain wins the length tiebreak)."""
        # Node 0 builds a length-3 chain; node 1 a length-2 fork.
        for i in range(2):
            self.chain(0).add_transaction(signed_attestation(f"a{i}", "s", "r", i, True, 1))
            self.chain(0).add_block(producer_key=AUTHORITY_KEY)
        self.chain(1).add_transaction(signed_attestation("b", "s", "r", 0, True, 1))
        self.chain(1).add_block(producer_key=AUTHORITY_KEY)
        tip_before = self.chain(0).last_block.hash

        # Node 1 advertises its shorter tip; node 0 requests node 1's chain and
        # refuses it as not strictly longer.
        self.overlay(1).broadcast_block(self.chain(1).last_block)
        await self.deliver_messages()

        self.assertEqual(len(self.chain(0).blocks), 3)
        self.assertEqual(self.chain(0).last_block.hash, tip_before)

    async def test_reputation_is_derived_from_the_nodes_own_chain(self):
        """The node's ``reputation`` reflects certificates committed to its chain."""
        from attestation.aggregator import make_certificate
        from reputation.derive import CERTIFICATE_REWARD

        subject = "subject-x"
        self.chain(0).add_transaction(
            make_certificate(subject, "r", "bioinformatics", ["genesis-alice"])
        )
        self.chain(0).add_block(producer_key=AUTHORITY_KEY)

        self.assertEqual(
            self.overlay(0).reputation.weight(subject, "bioinformatics"),
            CERTIFICATE_REWARD,
        )
