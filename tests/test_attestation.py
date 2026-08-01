"""Tests for the attestation application layer."""

import json
import unittest

from attestation.attestation import (
    ABSTAIN,
    ATTESTATION_TYPE,
    is_abstain,
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
        domain="bioinformatics",
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
                "domain": "bioinformatics",
                "item_index": 3,
                "verdict": True,
                "stake": 5,
            },
        )

    def test_domain_defaults_when_unspecified(self):
        """Omitting domain yields a valid attestation with the default domain."""
        tx = make_attestation("n", "s", "r", 0, True, 1)
        self.assertEqual(tx.payload["domain"], "general")
        self.assertTrue(is_attestation(tx))


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

    def test_rejects_empty_domain(self):
        """An empty-string domain names no domain and must be rejected."""
        tx = _sample_attestation()
        tx.payload["domain"] = ""
        self.assertFalse(is_attestation(tx))

    def test_rejects_non_string_domain(self):
        tx = _sample_attestation()
        tx.payload["domain"] = 123
        self.assertFalse(is_attestation(tx))

    def test_rejects_wrong_type_discriminator(self):
        tx = _sample_attestation()
        tx.payload["type"] = "transfer"
        self.assertFalse(is_attestation(tx))


class AbstainTests(unittest.TestCase):
    """The third verdict state: an explicit abstain (verdict is None)."""

    def test_abstain_is_a_valid_attestation(self):
        """verdict=None (ABSTAIN) is well-formed, alongside True/False."""
        tx = make_attestation("n", "s", "r", 0, ABSTAIN, 0, domain="bio")
        self.assertIsNone(tx.payload["verdict"])
        self.assertTrue(is_attestation(tx))

    def test_make_abstain_forces_zero_stake(self):
        """An abstain risks nothing: any stake passed is coerced to 0."""
        tx = make_attestation("n", "s", "r", 0, ABSTAIN, 99, domain="bio")
        self.assertEqual(tx.payload["stake"], 0)
        self.assertTrue(is_attestation(tx))

    def test_rejects_abstain_carrying_stake(self):
        """A hand-built abstain with a non-zero bond is malformed (stake-free rule)."""
        tx = make_attestation("n", "s", "r", 0, ABSTAIN, 0, domain="bio")
        tx.payload["stake"] = 5
        self.assertFalse(is_attestation(tx))

    def test_is_abstain_distinguishes_abstain_from_verdicts(self):
        """is_abstain is True only for the None-verdict state."""
        self.assertTrue(is_abstain(make_attestation("n", "s", "r", 0, ABSTAIN, 0)))
        self.assertFalse(is_abstain(make_attestation("n", "s", "r", 0, True, 1)))
        self.assertFalse(is_abstain(make_attestation("n", "s", "r", 0, False, 1)))


if __name__ == "__main__":
    unittest.main()
