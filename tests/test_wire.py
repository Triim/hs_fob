"""Tests for the wire serialization bridge (the core/network seam)."""

import unittest

from attestation.attestation import is_attestation, make_attestation
from blockchain.block import Block
from blockchain.blockchain import Blockchain
from blockchain.transaction import Transaction
from network.wire import (
    block_to_wire,
    tx_to_wire,
    wire_to_block,
    wire_to_tx,
)


class TransactionWireTests(unittest.TestCase):
    def test_attestation_round_trips_equal(self):
        """An attestation survives to_wire -> from_wire with an identical hash."""
        tx = make_attestation("attester", "subject", "rubric", 2, True, 7)

        restored = wire_to_tx(tx_to_wire(tx))

        self.assertEqual(restored.hash, tx.hash)
        self.assertEqual(restored.to_dict(), tx.to_dict())
        self.assertTrue(is_attestation(restored))

    def test_wire_is_a_string(self):
        tx = make_attestation("attester", "subject", "rubric", 0, False, 0)
        self.assertIsInstance(tx_to_wire(tx), str)

    def test_malformed_json_raises(self):
        with self.assertRaises(ValueError):
            wire_to_tx("{not valid json")

    def test_missing_field_raises(self):
        with self.assertRaises(ValueError):
            wire_to_tx('{"sender": "a", "payload": {}}')  # no timestamp


class BlockWireTests(unittest.TestCase):
    def _mined_block(self) -> Block:
        # A real mined block (difficulty 0 for speed) carrying an attestation.
        chain = Blockchain(difficulty=0)
        chain.add_transaction(
            make_attestation("attester", "subject", "rubric", 1, True, 3)
        )
        chain.add_transaction(Transaction(sender="alice", payload={"amount": 5}))
        return chain.add_block()

    def test_mined_block_round_trips_equal(self):
        """A mined block survives to_wire -> from_wire with an identical hash."""
        block = self._mined_block()

        restored = wire_to_block(block_to_wire(block))

        self.assertEqual(restored.hash, block.hash)
        self.assertEqual(restored.merkle_root, block.merkle_root)
        self.assertEqual(restored.to_dict(), block.to_dict())

    def test_transactions_are_preserved(self):
        block = self._mined_block()
        restored = wire_to_block(block_to_wire(block))

        self.assertEqual(len(restored.transactions), len(block.transactions))
        self.assertTrue(is_attestation(restored.transactions[0]))

    def test_empty_block_round_trips(self):
        """Genesis (no transactions) also survives the round-trip."""
        genesis = Blockchain(difficulty=0).blocks[0]
        restored = wire_to_block(block_to_wire(genesis))
        self.assertEqual(restored.hash, genesis.hash)

    def test_tampered_hash_is_rejected(self):
        """A wire block whose committed hash was altered fails the integrity gate."""
        block = self._mined_block()
        wire = block_to_wire(block)
        tampered = wire.replace(block.hash, "0" * 64)

        with self.assertRaises(ValueError):
            wire_to_block(tampered)

    def test_tampered_transaction_is_rejected(self):
        """Changing a transaction shifts merkle_root/hash away from the committed
        values, so the recompute-and-compare gate rejects it."""
        block = self._mined_block()
        wire = block_to_wire(block)
        tampered = wire.replace('"amount":5', '"amount":9999')
        self.assertNotEqual(tampered, wire)  # the substitution actually happened

        with self.assertRaises(ValueError):
            wire_to_block(tampered)

    def test_missing_field_raises(self):
        with self.assertRaises(ValueError):
            wire_to_block('{"index": 1}')


if __name__ == "__main__":
    unittest.main()
