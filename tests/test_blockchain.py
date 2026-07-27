"""Tests for the Blockchain: mining, linking, and validation."""

import unittest

from blockchain.blockchain import Blockchain
from blockchain.proof_of_work import hash_meets_target
from blockchain.transaction import Transaction


LOW_DIFFICULTY = 8  # keep mining fast in tests


def tx(i: int) -> Transaction:
    return Transaction(sender=f"peer{i}", payload={"i": i}, timestamp=float(i))


def build_chain(num_blocks: int = 3) -> Blockchain:
    chain = Blockchain(difficulty=LOW_DIFFICULTY)
    for b in range(num_blocks):
        chain.add_transaction(tx(2 * b))
        chain.add_transaction(tx(2 * b + 1))
        chain.add_block()
    return chain


class ChainStructureTests(unittest.TestCase):
    def test_starts_with_only_genesis(self):
        chain = Blockchain(difficulty=LOW_DIFFICULTY)
        self.assertEqual(len(chain.blocks), 1)
        self.assertEqual(chain.blocks[0].index, 0)
        self.assertEqual(chain.blocks[0].previous_hash, "0" * 64)

    def test_add_block_mines_links_and_clears_mempool(self):
        chain = Blockchain(difficulty=LOW_DIFFICULTY)
        chain.add_transaction(tx(1))
        block = chain.add_block()

        self.assertEqual(len(chain.blocks), 2)
        self.assertEqual(block.index, 1)
        self.assertEqual(block.previous_hash, chain.blocks[0].hash)
        self.assertTrue(hash_meets_target(block.hash, LOW_DIFFICULTY))
        self.assertEqual(chain.mempool, [])  # emptied after mining

    def test_mined_block_ignores_later_mempool_activity(self):
        """A block snapshots the mempool at mining time, so transactions pooled
        afterwards do not retroactively join it."""
        chain = Blockchain(difficulty=LOW_DIFFICULTY)
        chain.add_transaction(tx(1))
        block = chain.add_block()
        self.assertEqual(len(block.transactions), 1)

        chain.add_transaction(tx(2))  # pooled after the block was mined
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

    def test_tampering_last_block_invalidates_via_pow(self):
        """Editing the last block's transaction changes its hash so it no longer
        meets the difficulty target."""
        chain = build_chain(2)
        self.assertTrue(chain.is_valid_chain())

        chain.blocks[-1].transactions[0].payload = {"i": -1}  # tamper tip

        self.assertFalse(chain.is_valid_chain())

    def test_breaking_a_link_invalidates_chain(self):
        chain = build_chain(3)
        chain.blocks[2].previous_hash = "f" * 64
        self.assertFalse(chain.is_valid_chain())


if __name__ == "__main__":
    unittest.main()
