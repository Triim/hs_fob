"""Tests for the Transaction domain object."""

import json
import unittest

from blockchain.transaction import Transaction
from crypto.keys import generate_keypair


class TransactionHashTests(unittest.TestCase):
    def test_hash_is_stable(self):
        """Identical contents (incl. timestamp) hash identically and yield a
        64-char hex digest."""
        tx_a = Transaction(sender="alice", payload={"amount": 10}, timestamp=1000.0)
        tx_b = Transaction(sender="alice", payload={"amount": 10}, timestamp=1000.0)

        self.assertEqual(tx_a.hash, tx_b.hash)
        self.assertEqual(len(tx_a.hash), 64)
        # Hex string: every char is a valid hex digit.
        int(tx_a.hash, 16)

    def test_hash_is_deterministic_across_payload_key_order(self):
        """Canonical (sorted-key) JSON means dict insertion order is irrelevant."""
        tx_a = Transaction(sender="alice", payload={"a": 1, "b": 2}, timestamp=1000.0)
        tx_b = Transaction(sender="alice", payload={"b": 2, "a": 1}, timestamp=1000.0)

        self.assertEqual(tx_a.hash, tx_b.hash)

    def test_hash_changes_on_field_change(self):
        """Changing sender, payload, or timestamp each changes the hash."""
        baseline = Transaction(sender="alice", payload={"amount": 10}, timestamp=1000.0)

        changed_sender = Transaction(sender="bob", payload={"amount": 10}, timestamp=1000.0)
        changed_payload = Transaction(sender="alice", payload={"amount": 11}, timestamp=1000.0)
        changed_time = Transaction(sender="alice", payload={"amount": 10}, timestamp=1001.0)

        self.assertNotEqual(baseline.hash, changed_sender.hash)
        self.assertNotEqual(baseline.hash, changed_payload.hash)
        self.assertNotEqual(baseline.hash, changed_time.hash)

    def test_to_dict_roundtrip(self):
        """to_dict() is JSON-serializable and contains all fields."""
        tx = Transaction(sender="alice", payload={"amount": 10}, timestamp=1000.0)
        as_dict = tx.to_dict()

        self.assertEqual(set(as_dict), {"sender", "payload", "timestamp"})
        self.assertEqual(as_dict["sender"], "alice")
        self.assertEqual(as_dict["payload"], {"amount": 10})
        self.assertEqual(as_dict["timestamp"], 1000.0)

        # Serializes and deserializes without loss.
        restored = json.loads(json.dumps(as_dict))
        self.assertEqual(restored, as_dict)


class TransactionSignatureTests(unittest.TestCase):
    def _signed_tx(self):
        """A transaction whose sender is its own signer's public key."""
        private_key, public_key_hex = generate_keypair()
        tx = Transaction(sender=public_key_hex, payload={"amount": 10}, timestamp=1000.0)
        tx.sign(private_key)
        return tx

    def test_unsigned_by_default(self):
        tx = Transaction(sender="alice", payload={"amount": 10}, timestamp=1000.0)
        self.assertIsNone(tx.signature)
        self.assertFalse(tx.is_signed())
        self.assertFalse(tx.verify_signature())  # unsigned -> False, not an error

    def test_signed_transaction_verifies(self):
        tx = self._signed_tx()
        self.assertTrue(tx.is_signed())
        self.assertTrue(tx.verify_signature())

    def test_tampering_payload_after_signing_fails_verification(self):
        tx = self._signed_tx()
        tx.payload = {"amount": 9999}  # mutate the content the signature covers
        self.assertFalse(tx.verify_signature())

    def test_hash_is_identical_whether_or_not_signed(self):
        """The key invariant: signing must not change the transaction hash."""
        private_key, public_key_hex = generate_keypair()
        tx = Transaction(sender=public_key_hex, payload={"amount": 10}, timestamp=1000.0)

        hash_before = tx.hash
        tx.sign(private_key)
        hash_after = tx.hash

        self.assertTrue(tx.is_signed())
        self.assertEqual(hash_before, hash_after)

    def test_signature_is_outside_signing_bytes(self):
        """signing_bytes covers content only, so it is unchanged by signing."""
        private_key, public_key_hex = generate_keypair()
        tx = Transaction(sender=public_key_hex, payload={"amount": 10}, timestamp=1000.0)

        bytes_before = tx.signing_bytes()
        tx.sign(private_key)
        self.assertEqual(bytes_before, tx.signing_bytes())


if __name__ == "__main__":
    unittest.main()
