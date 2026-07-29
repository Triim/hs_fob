"""Tests for the Blockchain: producing, linking, and Proof-of-Authority validation."""

import unittest

from blockchain.blockchain import AUTHORITY_THRESHOLD, Blockchain
from blockchain.transaction import Transaction
from crypto.keys import generate_keypair
from reputation.genesis import GENESIS_AUTHORITY_KEYS

# The reproducible genesis authority: its private key signs blocks, its public
# key carries consensus weight, so blocks it produces pass PoA validation.
AUTHORITY_KEY, AUTHORITY_PUBKEY = GENESIS_AUTHORITY_KEYS["genesis-authority"]


def tx(i: int) -> Transaction:
    return Transaction(sender=f"peer{i}", payload={"i": i}, timestamp=float(i))


def build_chain(num_blocks: int = 3) -> Blockchain:
    chain = Blockchain(difficulty=0)
    for b in range(num_blocks):
        chain.add_transaction(tx(2 * b))
        chain.add_transaction(tx(2 * b + 1))
        chain.add_block(producer_key=AUTHORITY_KEY)
    return chain


class ChainStructureTests(unittest.TestCase):
    def test_starts_with_only_genesis(self):
        chain = Blockchain(difficulty=0)
        self.assertEqual(len(chain.blocks), 1)
        self.assertEqual(chain.blocks[0].index, 0)
        self.assertEqual(chain.blocks[0].previous_hash, "0" * 64)

    def test_add_block_produces_links_signs_and_clears_mempool(self):
        chain = Blockchain(difficulty=0)
        chain.add_transaction(tx(1))
        block = chain.add_block(producer_key=AUTHORITY_KEY)

        self.assertEqual(len(chain.blocks), 2)
        self.assertEqual(block.index, 1)
        self.assertEqual(block.previous_hash, chain.blocks[0].hash)
        # PoA replaces PoW: the block is signed by its producer, not mined.
        self.assertEqual(block.producer, AUTHORITY_PUBKEY)
        self.assertTrue(block.verify_producer_signature())
        self.assertEqual(chain.mempool, [])  # emptied after production

    def test_produced_block_ignores_later_mempool_activity(self):
        """A block snapshots the mempool at production time, so transactions pooled
        afterwards do not retroactively join it."""
        chain = Blockchain(difficulty=0)
        chain.add_transaction(tx(1))
        block = chain.add_block(producer_key=AUTHORITY_KEY)
        self.assertEqual(len(block.transactions), 1)

        chain.add_transaction(tx(2))  # pooled after the block was produced
        self.assertEqual(len(block.transactions), 1)  # unchanged
        self.assertEqual(len(chain.mempool), 1)


class ValidationTests(unittest.TestCase):
    def test_fresh_chain_is_valid(self):
        self.assertTrue(build_chain(3).is_valid_chain())

    def test_tampering_past_transaction_invalidates_chain(self):
        """Editing a transaction in an earlier block breaks the next block's
        previous-hash link, so the chain no longer validates."""
        chain = build_chain(3)
        self.assertTrue(chain.is_valid_chain())

        chain.blocks[1].transactions[0].payload = {"i": -1}  # tamper block 1

        self.assertFalse(chain.is_valid_chain())

    def test_tampering_last_block_invalidates_via_signature(self):
        """Editing the last block's transaction changes its header, so the
        producer's signature no longer verifies (PoA's tamper check, replacing
        the old proof-of-work one)."""
        chain = build_chain(2)
        self.assertTrue(chain.is_valid_chain())

        chain.blocks[-1].transactions[0].payload = {"i": -1}  # tamper tip

        self.assertFalse(chain.is_valid_chain())

    def test_breaking_a_link_invalidates_chain(self):
        chain = build_chain(3)
        chain.blocks[2].previous_hash = "f" * 64
        self.assertFalse(chain.is_valid_chain())


class ProofOfAuthorityTests(unittest.TestCase):
    def _chain_with_block_by(self, producer_key) -> Blockchain:
        chain = Blockchain(difficulty=0)
        chain.add_transaction(tx(1))
        chain.add_block(producer_key=producer_key)
        return chain

    def test_genesis_authority_block_validates(self):
        """A block signed by a genesis authority is accepted."""
        self.assertTrue(self._chain_with_block_by(AUTHORITY_KEY).is_valid_chain())

    def test_non_authority_producer_is_rejected(self):
        """A block signed by a key with zero reputation is rejected — it is validly
        signed but its producer is not an authority."""
        stranger, _ = generate_keypair()  # a real key, but no genesis weight
        chain = self._chain_with_block_by(stranger)

        self.assertTrue(chain.blocks[-1].verify_producer_signature())  # signature is fine
        self.assertFalse(chain.is_valid_chain())                       # authority is not

    def test_bad_producer_signature_is_rejected(self):
        """A block whose producer signature does not verify is rejected."""
        chain = self._chain_with_block_by(AUTHORITY_KEY)
        chain.blocks[-1].producer_signature = "00" * 64  # corrupt the signature

        self.assertFalse(chain.is_valid_chain())

    def test_unproduced_block_is_rejected(self):
        """A block that was never signed at all is rejected under PoA."""
        chain = self._chain_with_block_by(None)  # add_block without a key

        self.assertEqual(chain.blocks[-1].producer, "")
        self.assertFalse(chain.is_valid_chain())

    def test_authority_is_judged_by_prefix_not_the_block_itself(self):
        """A producer who would only become an authority *because of their own
        block* is still rejected — authority is derived from blocks 0..N-1.

        A fresh key has no genesis weight. We hand it enough certificate rewards
        in an earlier block to cross the threshold, then have it produce a *later*
        block: that later block validates. But when the very block that would earn
        it authority is also the one it produces, the prefix (which excludes that
        block) still shows zero weight, so it is refused.
        """
        newcomer, newcomer_pub = generate_keypair()
        from attestation.aggregator import make_certificate
        from reputation.derive import CERTIFICATE_REWARD

        # How many certificate rewards it takes to reach the authority threshold.
        needed = -(-AUTHORITY_THRESHOLD // CERTIFICATE_REWARD)  # ceil division

        # Case A — the newcomer produces the block that would grant its authority.
        # That block's own certificates do not count toward its own authority
        # (prefix rule), so the block is rejected.
        chain = Blockchain(difficulty=0)
        for _ in range(needed):
            chain.add_transaction(
                make_certificate(newcomer_pub, "rubric", "consensus", ["genesis-alice"])
            )
        chain.add_block(producer_key=newcomer)  # produced BY the newcomer
        self.assertFalse(chain.is_valid_chain())

        # Case B — the same rewards are committed by a genesis authority first,
        # and only in a *later* block does the newcomer produce. Now the prefix
        # already credits it, so its block validates.
        chain2 = Blockchain(difficulty=0)
        for _ in range(needed):
            chain2.add_transaction(
                make_certificate(newcomer_pub, "rubric", "consensus", ["genesis-alice"])
            )
        chain2.add_block(producer_key=AUTHORITY_KEY)  # block 1, by a genesis authority
        chain2.add_transaction(tx(1))
        chain2.add_block(producer_key=newcomer)       # block 2, now the newcomer is an authority
        self.assertTrue(chain2.is_valid_chain())

    def test_slash_affects_authority_only_after_its_block(self):
        """Slashing a producer below threshold gates only *later* blocks (prefix).

        Block 1 *contains* the slash of the genesis authority, but its own
        producer is judged against the prefix (genesis, full weight), so it is
        valid. A block 2 by the same, now-slashed authority is judged against a
        prefix that includes the slash, so it is rejected.
        """
        from reputation.slashing import make_slash

        chain = Blockchain(difficulty=0)
        chain.add_transaction(
            make_slash(AUTHORITY_PUBKEY, "consensus", "misbehaviour", "ref", amount=100)
        )
        chain.add_block(producer_key=AUTHORITY_KEY)  # block 1 carries the slash
        self.assertTrue(chain.is_valid_chain())      # judged by the pre-slash prefix

        chain.add_transaction(tx(1))
        chain.add_block(producer_key=AUTHORITY_KEY)  # block 2, producer now slashed to 0
        self.assertFalse(chain.is_valid_chain())


class ReplaceChainTests(unittest.TestCase):
    def test_adopts_strictly_longer_valid_chain(self):
        """A longer valid PoA chain replaces the current one (longest wins)."""
        short = build_chain(1)   # genesis + 1
        long = build_chain(3)    # genesis + 3

        self.assertTrue(short.replace_chain(long.blocks))
        self.assertEqual(len(short.blocks), 4)
        self.assertEqual(short.last_block.hash, long.last_block.hash)

    def test_refuses_equal_length_chain(self):
        """Ties keep the current chain, so a node never churns at equal height."""
        a = build_chain(2)
        b = build_chain(2)
        self.assertFalse(a.replace_chain(b.blocks))

    def test_refuses_shorter_chain(self):
        long = build_chain(3)
        short = build_chain(1)
        self.assertFalse(long.replace_chain(short.blocks))

    def test_refuses_longer_but_invalid_chain(self):
        """Length alone is not enough — an invalid candidate is refused."""
        current = build_chain(1)
        candidate = build_chain(3)
        candidate.blocks[-1].producer_signature = "00" * 64  # corrupt the tip

        self.assertFalse(current.replace_chain(candidate.blocks))
        self.assertEqual(len(current.blocks), 2)  # unchanged

    def test_adopting_recomputes_mempool(self):
        """Pending txs the adopted chain already commits are dropped."""
        current = build_chain(1)
        longer = build_chain(3)
        # Pool a tx that the longer chain already committed in one of its blocks.
        committed_tx = longer.blocks[2].transactions[0]
        loose_tx = tx(999)
        current.mempool = [committed_tx, loose_tx]

        self.assertTrue(current.replace_chain(longer.blocks))
        pooled = {t.hash for t in current.mempool}
        self.assertNotIn(committed_tx.hash, pooled)  # dropped: now on-chain
        self.assertIn(loose_tx.hash, pooled)          # kept: still pending


if __name__ == "__main__":
    unittest.main()
