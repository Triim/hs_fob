"""Tests for the submission application layer."""

import hashlib
import unittest

from attestation.attestation import make_attestation, is_attestation
from attestation.submission import (
    SUBMISSION_TYPE,
    hash_artifact,
    is_submission,
    make_submission,
)
from blockchain.blockchain import Blockchain
from blockchain.transaction import Transaction
from crypto.keys import generate_keypair
from network.wire import tx_to_wire, wire_to_tx
from reputation.derive import derive_registry


def _sample_submission() -> Transaction:
    return make_submission(
        subject="ab12cd",
        domain="bioinformatics",
        rubric_root="deadbeef",
        title="Genome assembler",
        artifact_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        artifact_name="assembler.zip",
    )


class MakeSubmissionTests(unittest.TestCase):
    def test_returns_plain_transaction(self):
        """The factory produces an ordinary Transaction, not a new type."""
        self.assertIsInstance(_sample_submission(), Transaction)

    def test_payload_matches_schema(self):
        """All submission fields land in the payload with the right values."""
        tx = _sample_submission()
        self.assertEqual(tx.sender, "ab12cd")  # sender is the submitting subject
        self.assertEqual(
            tx.payload,
            {
                "type": SUBMISSION_TYPE,
                "subject": "ab12cd",
                "domain": "bioinformatics",
                "rubric_root": "deadbeef",
                "title": "Genome assembler",
                "artifact_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "artifact_name": "assembler.zip",
            },
        )

    def test_artifact_name_defaults_to_empty(self):
        """Omitting artifact_name yields a valid submission with an empty name."""
        tx = make_submission("s", "d", "r", "t", "aa")
        self.assertEqual(tx.payload["artifact_name"], "")
        self.assertTrue(is_submission(tx))


class IsSubmissionTests(unittest.TestCase):
    def test_accepts_well_formed_submission(self):
        self.assertTrue(is_submission(_sample_submission()))

    def test_accepts_empty_artifact_name(self):
        tx = _sample_submission()
        tx.payload["artifact_name"] = ""
        self.assertTrue(is_submission(tx))

    def test_rejects_plain_transaction(self):
        """A generic (non-submission) transaction is not accepted."""
        tx = Transaction(sender="alice", payload={"amount": 10})
        self.assertFalse(is_submission(tx))

    def test_rejects_missing_field(self):
        tx = Transaction(
            sender="s",
            payload={
                "type": SUBMISSION_TYPE,
                "subject": "s",
                "domain": "d",
                "rubric_root": "r",
                "title": "t",
                # "artifact_hash" omitted
                "artifact_name": "",
            },
        )
        self.assertFalse(is_submission(tx))

    def test_rejects_extra_field(self):
        tx = _sample_submission()
        tx.payload["unexpected"] = 1
        self.assertFalse(is_submission(tx))

    def test_rejects_empty_required_string(self):
        """Every required field is meaningless when empty and must be rejected."""
        for key in ("subject", "domain", "rubric_root", "title", "artifact_hash"):
            tx = _sample_submission()
            tx.payload[key] = ""
            self.assertFalse(is_submission(tx), f"empty {key} should be rejected")

    def test_rejects_wrong_type_field(self):
        """A non-string where a string is required is rejected."""
        for key in ("subject", "domain", "rubric_root", "title", "artifact_hash",
                    "artifact_name"):
            tx = _sample_submission()
            tx.payload[key] = 123
            self.assertFalse(is_submission(tx), f"non-string {key} should be rejected")

    def test_rejects_wrong_type_discriminator(self):
        tx = _sample_submission()
        tx.payload["type"] = "attestation"
        self.assertFalse(is_submission(tx))


class CrossTypeTests(unittest.TestCase):
    def test_attestation_is_not_a_submission(self):
        att = make_attestation("n", "s", "r", 0, True, 1, "aa", domain="bioinformatics")
        self.assertFalse(is_submission(att))

    def test_submission_is_not_an_attestation(self):
        self.assertFalse(is_attestation(_sample_submission()))


class SignAndRoundTripTests(unittest.TestCase):
    def test_signed_submission_verifies_and_round_trips(self):
        """A signed submission survives the wire with an identical hash and a
        still-valid signature."""
        private_key, public_key_hex = generate_keypair()
        tx = make_submission(public_key_hex, "bioinformatics", "r", "Thesis", "aa", "t.pdf")
        tx.timestamp = 1000.0
        tx.sign(private_key)

        restored = wire_to_tx(tx_to_wire(tx))

        self.assertEqual(restored.hash, tx.hash)
        self.assertEqual(restored.signature, tx.signature)
        self.assertTrue(restored.verify_signature())
        self.assertTrue(is_submission(restored))

    def test_hash_is_stable(self):
        """Two submissions with identical fields and timestamp hash alike."""
        a = make_submission("s", "d", "r", "t", "aa")
        a.timestamp = 1000.0
        b = make_submission("s", "d", "r", "t", "aa")
        b.timestamp = 1000.0

        self.assertEqual(a.hash, b.hash)
        self.assertEqual(len(a.hash), 64)


class HashArtifactTests(unittest.TestCase):
    def test_matches_hashlib(self):
        data = b"some artifact bytes"
        self.assertEqual(hash_artifact(data), hashlib.sha256(data).hexdigest())

    def test_is_stable_and_hex(self):
        data = b"repeatable"
        self.assertEqual(hash_artifact(data), hash_artifact(data))
        self.assertEqual(len(hash_artifact(data)), 64)
        int(hash_artifact(data), 16)  # valid hex

    def test_empty_bytes(self):
        self.assertEqual(hash_artifact(b""), hashlib.sha256(b"").hexdigest())


class ReputationNeutralTests(unittest.TestCase):
    def test_submission_grants_no_reputation(self):
        """A chain with a submission derives the same reputation as one without."""
        without = Blockchain()
        without.add_block()  # an empty block

        with_sub = Blockchain()
        with_sub.add_transaction(_sample_submission())
        with_sub.add_block()

        base = derive_registry(without)
        derived = derive_registry(with_sub)

        # The submission's subject earns nothing, and the anchor is untouched.
        self.assertEqual(derived.weight("ab12cd", "bioinformatics"), 0)
        self.assertEqual(
            derived.weight("genesis-alice", "bioinformatics"),
            base.weight("genesis-alice", "bioinformatics"),
        )


if __name__ == "__main__":
    unittest.main()
