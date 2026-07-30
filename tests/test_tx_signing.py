"""Tests for the participant-signature policy (requires_signature)."""

import unittest

from attestation.aggregator import make_certificate
from attestation.attestation import make_attestation
from attestation.submission import make_submission
from blockchain.transaction import Transaction
from blockchain.tx_signing import requires_signature
from reputation.slashing import make_slash


class RequiresSignatureTests(unittest.TestCase):
    def test_participant_types_require_signature(self):
        self.assertTrue(requires_signature(make_attestation("n", "s", "r", 0, True, 1)))
        self.assertTrue(requires_signature(make_submission("s", "d", "r", "t", "aa")))
        self.assertTrue(requires_signature(make_slash("off", "d", "reason", "ref")))

    def test_certificate_is_exempt(self):
        """A certificate is protocol-generated, so it does not require a signature."""
        self.assertFalse(requires_signature(make_certificate("s", "r", "d", ["a"])))

    def test_unknown_payload_is_exempt(self):
        self.assertFalse(
            requires_signature(Transaction(sender="alice", payload={"amount": 5}))
        )

    def test_non_dict_payload_is_exempt(self):
        self.assertFalse(requires_signature(Transaction(sender="alice", payload="oops")))


if __name__ == "__main__":
    unittest.main()
