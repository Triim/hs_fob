"""Tests for the attestation application layer."""

import json
import unittest

from attestation.attestation import (
    ATTESTATION_TYPE,
    is_attestation,
    make_attestation,
)
from blockchain.transaction import Transaction


def _sample_attestation() -> Transaction:
    return make_attestation(
        attester="attester-node",
        subject="ab12cd",
        rubric_root="deadbeef",
        item_index=3,
        verdict=True,
        stake=5,
    )


class MakeAttestationTests(unittest.TestCase):
    def test_returns_plain_transaction(self):
        """The factory produces an ordinary Transaction, not a new type."""
        tx = _sample_attestation()
        self.assertIsInstance(tx, Transaction)

    def test_payload_matches_schema(self):
        """All attestation fields land in the payload with the right values."""
        tx = _sample_attestation()
        self.assertEqual(tx.sender, "attester-node")
        self.assertEqual(
            tx.payload,
            {
                "type": ATTESTATION_TYPE,
                "subject": "ab12cd",
                "rubric_root": "deadbeef",
                "item_index": 3,
                "verdict": True,
                "stake": 5,
            },
        )


class RoundTripTests(unittest.TestCase):
    def test_survives_transaction_serialization(self):
        """An attestation round-trips through Transaction.to_dict without loss."""
        tx = _sample_attestation()

        restored_dict = json.loads(json.dumps(tx.to_dict()))
        restored = Transaction(
            sender=restored_dict["sender"],
            payload=restored_dict["payload"],
            timestamp=restored_dict["timestamp"],
        )

        self.assertEqual(restored.to_dict(), tx.to_dict())
        self.assertTrue(is_attestation(restored))

    def test_hash_is_stable(self):
        """Two attestations with identical fields and timestamp hash alike."""
        a = make_attestation("n", "s", "r", 1, False, 0)
        a.timestamp = 1000.0
        b = make_attestation("n", "s", "r", 1, False, 0)
        b.timestamp = 1000.0

        self.assertEqual(a.hash, b.hash)
        self.assertEqual(len(a.hash), 64)


class IsAttestationTests(unittest.TestCase):
    def test_accepts_well_formed_attestation(self):
        self.assertTrue(is_attestation(_sample_attestation()))

    def test_rejects_plain_transaction(self):
        """A generic (non-attestation) transaction is not accepted."""
        tx = Transaction(sender="alice", payload={"amount": 10})
        self.assertFalse(is_attestation(tx))

    def test_rejects_missing_field(self):
        tx = Transaction(
            sender="n",
            payload={
                "type": ATTESTATION_TYPE,
                "subject": "s",
                "rubric_root": "r",
                "item_index": 0,
                "verdict": True,
                # "stake" omitted
            },
        )
        self.assertFalse(is_attestation(tx))

    def test_rejects_extra_field(self):
        tx = _sample_attestation()
        tx.payload["unexpected"] = 1
        self.assertFalse(is_attestation(tx))

    def test_rejects_bool_in_numeric_field(self):
        """bool is a subclass of int, so it must be rejected where int is meant."""
        tx = _sample_attestation()
        tx.payload["item_index"] = True
        self.assertFalse(is_attestation(tx))

    def test_rejects_wrong_verdict_type(self):
        tx = _sample_attestation()
        tx.payload["verdict"] = "yes"
        self.assertFalse(is_attestation(tx))

    def test_rejects_wrong_type_discriminator(self):
        tx = _sample_attestation()
        tx.payload["type"] = "transfer"
        self.assertFalse(is_attestation(tx))


if __name__ == "__main__":
    unittest.main()
