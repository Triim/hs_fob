"""Tests for proof-of-work helpers and Block.mine()."""

import unittest

from blockchain.block import Block
from blockchain.proof_of_work import count_leading_zero_bits, hash_meets_target
from blockchain.transaction import Transaction


def make_block() -> Block:
    txs = [Transaction(sender="alice", payload={"amount": 10}, timestamp=1.0)]
    return Block(index=1, previous_hash="0" * 64, transactions=txs, timestamp=100.0)


class LeadingZeroTests(unittest.TestCase):
    def test_count_leading_zero_bits(self):
        # 64 hex chars = 256 bits total.
        self.assertEqual(count_leading_zero_bits("0" * 64), 256)  # all zero
        self.assertEqual(count_leading_zero_bits("f" + "0" * 63), 0)  # leading 1111
        self.assertEqual(count_leading_zero_bits("1" + "0" * 63), 3)  # 0001...
        self.assertEqual(count_leading_zero_bits("8" + "0" * 63), 0)  # 1000...

    def test_hash_meets_target(self):
        h = "0" * 4 + "f" + "0" * 59  # 16 leading zero bits (four zero nibbles)
        self.assertTrue(hash_meets_target(h, 16))
        self.assertTrue(hash_meets_target(h, 8))
        self.assertFalse(hash_meets_target(h, 17))


class MiningTests(unittest.TestCase):
    def test_mined_block_meets_target(self):
        """After mining, the block hash satisfies the difficulty target."""
        difficulty = 12  # low: fast, but non-trivial
        block = make_block()
        block.mine(difficulty)
        self.assertTrue(hash_meets_target(block.hash, difficulty))
        self.assertGreaterEqual(count_leading_zero_bits(block.hash), difficulty)

    def test_higher_difficulty_produces_more_leading_zeros(self):
        """A block mined at a higher difficulty has at least that many leading
        zero bits — i.e. more work was required."""
        low, high = 8, 16

        block_low = make_block()
        block_low.mine(low)
        block_high = make_block()
        block_high.mine(high)

        self.assertGreaterEqual(count_leading_zero_bits(block_low.hash), low)
        self.assertGreaterEqual(count_leading_zero_bits(block_high.hash), high)
        # The harder target forces at least as many leading zeros as the easier.
        self.assertGreaterEqual(
            count_leading_zero_bits(block_high.hash),
            count_leading_zero_bits(block_low.hash),
        )

    def test_difficulty_zero_needs_no_work(self):
        """Difficulty 0 is met by any hash, so the nonce need not move."""
        block = make_block()
        attempts = block.mine(0)
        self.assertEqual(attempts, 1)
        self.assertEqual(block.nonce, 0)


if __name__ == "__main__":
    unittest.main()
