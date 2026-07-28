"""Tests for attestation aggregation and the acceptance threshold."""

import unittest

from attestation.aggregator import (
    CERTIFICATE_TYPE,
    DEFAULT_ISSUER,
    certify,
    make_certificate,
)
from attestation.attestation import is_attestation, make_attestation
from blockchain.blockchain import Blockchain

SUBJECT = "student-pubkey"
RUBRIC = "rubric-root-hex"


def _chain() -> Blockchain:
    # Difficulty 0 keeps mining instant: hash_meets_target with 0 required bits
    # is trivially true, so tests stay fast while exercising real blocks.
    return Blockchain(difficulty=0)


def _mine(chain: Blockchain, *transactions) -> None:
    for tx in transactions:
        chain.add_transaction(tx)
    chain.add_block()


class CertifyThresholdTests(unittest.TestCase):
    def test_sunny_path_enough_distinct_attesters(self):
        """Three distinct positive attesters meet a threshold of 3."""
        chain = _chain()
        _mine(
            chain,
            make_attestation("attester-a", SUBJECT, RUBRIC, 0, True, 1),
            make_attestation("attester-b", SUBJECT, RUBRIC, 0, True, 1),
            make_attestation("attester-c", SUBJECT, RUBRIC, 1, True, 1),
        )

        cert = certify(chain, SUBJECT, RUBRIC, threshold=3)

        self.assertIsNotNone(cert)
        self.assertFalse(is_attestation(cert))  # it's a certificate, not an attestation
        self.assertEqual(cert.payload["type"], CERTIFICATE_TYPE)
        self.assertEqual(cert.payload["subject"], SUBJECT)
        self.assertEqual(cert.payload["rubric_root"], RUBRIC)
        self.assertEqual(
            cert.payload["granted_by"], ["attester-a", "attester-b", "attester-c"]
        )
        self.assertEqual(cert.sender, DEFAULT_ISSUER)

    def test_rainy_path_too_few_attesters(self):
        """Two attesters do not meet a threshold of 3 → no certificate."""
        chain = _chain()
        _mine(
            chain,
            make_attestation("attester-a", SUBJECT, RUBRIC, 0, True, 1),
            make_attestation("attester-b", SUBJECT, RUBRIC, 0, True, 1),
        )

        self.assertIsNone(certify(chain, SUBJECT, RUBRIC, threshold=3))

    def test_rainy_path_duplicate_attester_counted_once(self):
        """The same attester voting repeatedly counts once, missing threshold."""
        chain = _chain()
        _mine(
            chain,
            make_attestation("attester-a", SUBJECT, RUBRIC, 0, True, 1),
            make_attestation("attester-a", SUBJECT, RUBRIC, 1, True, 1),
            make_attestation("attester-a", SUBJECT, RUBRIC, 2, True, 1),
        )

        # Only one distinct attester, so a threshold of 2 is not met.
        self.assertIsNone(certify(chain, SUBJECT, RUBRIC, threshold=2))
        # A threshold of 1 is met by that single distinct attester.
        cert = certify(chain, SUBJECT, RUBRIC, threshold=1)
        self.assertIsNotNone(cert)
        self.assertEqual(cert.payload["granted_by"], ["attester-a"])

    def test_negative_verdicts_do_not_count(self):
        """verdict=False attestations never push toward acceptance."""
        chain = _chain()
        _mine(
            chain,
            make_attestation("attester-a", SUBJECT, RUBRIC, 0, True, 1),
            make_attestation("attester-b", SUBJECT, RUBRIC, 0, False, 1),
        )

        self.assertIsNone(certify(chain, SUBJECT, RUBRIC, threshold=2))
        cert = certify(chain, SUBJECT, RUBRIC, threshold=1)
        self.assertEqual(cert.payload["granted_by"], ["attester-a"])

    def test_other_subject_or_rubric_is_ignored(self):
        """Votes are pooled only within one (subject, rubric_root) pair."""
        chain = _chain()
        _mine(
            chain,
            make_attestation("attester-a", SUBJECT, RUBRIC, 0, True, 1),
            make_attestation("attester-b", "other-subject", RUBRIC, 0, True, 1),
            make_attestation("attester-c", SUBJECT, "other-rubric", 0, True, 1),
        )

        # Only attester-a matches this subject *and* rubric.
        self.assertIsNone(certify(chain, SUBJECT, RUBRIC, threshold=2))

    def test_votes_span_multiple_blocks(self):
        """Attesters in different mined blocks are all counted."""
        chain = _chain()
        _mine(chain, make_attestation("attester-a", SUBJECT, RUBRIC, 0, True, 1))
        _mine(chain, make_attestation("attester-b", SUBJECT, RUBRIC, 0, True, 1))

        cert = certify(chain, SUBJECT, RUBRIC, threshold=2)
        self.assertIsNotNone(cert)
        self.assertEqual(cert.payload["granted_by"], ["attester-a", "attester-b"])


class MakeCertificateTests(unittest.TestCase):
    def test_granted_by_is_sorted_for_determinism(self):
        """granted_by is stored sorted so the certificate hash is stable.

        Timestamps are pinned equal so the only thing that could differ between
        the two certificates is attester ordering — which sorting removes.
        """
        a = make_certificate(SUBJECT, RUBRIC, ["c", "a", "b"])
        b = make_certificate(SUBJECT, RUBRIC, ["a", "b", "c"])
        a.timestamp = b.timestamp = 1000.0

        self.assertEqual(a.payload["granted_by"], ["a", "b", "c"])
        self.assertEqual(a.hash, b.hash)


if __name__ == "__main__":
    unittest.main()
