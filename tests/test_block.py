"""Tests for the Block: header hashing and Merkle commitment."""

import unittest

from blockchain.block import Block
from blockchain.transaction import Transaction
from crypto.keys import generate_keypair, public_hex


def make_block() -> Block:
    txs = [
        Transaction(sender="alice", payload={"amount": 10}, timestamp=1.0),
        Transaction(sender="bob", payload={"amount": 20}, timestamp=2.0),
    ]
    return Block(index=1, previous_hash="0" * 64, transactions=txs, timestamp=100.0)


class BlockHashTests(unittest.TestCase):
    def test_hash_is_stable_and_hex(self):
        """Identical blocks produce identical 64-char hex hashes."""
        self.assertEqual(make_block().hash, make_block().hash)
        self.assertEqual(len(make_block().hash), 64)
        int(make_block().hash, 16)

    def test_changing_a_transaction_changes_root_and_hash(self):
        """Tampering with any transaction changes both the Merkle root and the
        block hash (the core tamper-evidence property)."""
        block = make_block()
        root_before, hash_before = block.merkle_root, block.hash

        block.transactions[0].payload = {"amount": 9999}  # tamper

        self.assertNotEqual(root_before, block.merkle_root)
        self.assertNotEqual(hash_before, block.hash)

    def test_changing_previous_hash_changes_hash(self):
        """The previous-hash link is part of the header."""
        block = make_block()
        hash_before = block.hash
        block.previous_hash = "f" * 64
        self.assertNotEqual(hash_before, block.hash)

    def test_to_dict_contains_header_and_transactions(self):
        block = make_block()
        as_dict = block.to_dict()
        self.assertEqual(
            set(as_dict),
            {
                "index", "previous_hash", "merkle_root", "timestamp",
                "producer", "producer_signature", "commit_signatures",
                "hash", "transactions",
            },
        )
        self.assertEqual(len(as_dict["transactions"]), 2)
        self.assertEqual(as_dict["hash"], block.hash)


class ProducerSignatureTests(unittest.TestCase):
    def test_sign_sets_producer_and_verifies(self):
        """Signing records the producer's pubkey and yields a valid signature."""
        private_key, pubkey = generate_keypair()
        block = make_block()

        block.sign_as_producer(private_key)

        self.assertEqual(block.producer, pubkey)
        self.assertTrue(block.verify_producer_signature())

    def test_unsigned_block_does_not_verify(self):
        """A block that was never produced has no valid signature."""
        self.assertFalse(make_block().verify_producer_signature())

    def test_tampering_header_breaks_signature(self):
        """Editing any header field after signing invalidates the signature."""
        private_key, _ = generate_keypair()
        block = make_block()
        block.sign_as_producer(private_key)

        block.transactions[0].payload = {"amount": 9999}  # changes merkle_root

        self.assertFalse(block.verify_producer_signature())

    def test_signature_is_not_part_of_the_hash(self):
        """The producer signature lives outside the header, so it never moves the hash."""
        private_key, _ = generate_keypair()
        block = make_block()
        hash_before = block.hash

        block.sign_as_producer(private_key)

        # producer IS in the header (hash changes), but attaching the signature
        # itself does not further change the hash.
        hash_after_producer = block.hash
        block.producer_signature = "00" * 64  # overwrite with garbage
        self.assertEqual(block.hash, hash_after_producer)
        # And setting the producer is what moved the hash off its unproduced value.
        self.assertNotEqual(hash_before, hash_after_producer)

    def test_foreign_signature_does_not_verify(self):
        """A signature by a different key than ``producer`` is rejected."""
        signer, _ = generate_keypair()
        other, other_pub = generate_keypair()
        block = make_block()
        block.sign_as_producer(signer)

        block.producer = other_pub  # claim a producer who did not sign

        self.assertFalse(block.verify_producer_signature())
        self.assertNotEqual(public_hex(signer), other_pub)


if __name__ == "__main__":
    unittest.main()
