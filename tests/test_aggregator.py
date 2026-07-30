"""Tests for attestation aggregation and the weighted acceptance threshold."""

import unittest

from attestation.aggregator import (
    CERTIFICATE_TYPE,
    DEFAULT_ISSUER,
    certify,
    make_certificate,
)
from attestation.attestation import is_attestation, make_attestation
from blockchain.blockchain import Blockchain
from reputation.registry import ReputationRegistry

SUBJECT = "student-pubkey"
RUBRIC = "rubric-root-hex"
DOMAIN = "bioinformatics"


def _registry() -> ReputationRegistry:
    # A small, self-contained registry with known domain weights so the tests
    # assert on weighted support rather than a head count. attester-c has weight
    # in the domain but small; attester-zero is deliberately weightless there.
    return ReputationRegistry(
        {
            "attester-a": {DOMAIN: 100},
            "attester-b": {DOMAIN: 80},
            "attester-c": {DOMAIN: 30},
            "attester-zero": {DOMAIN: 0, "other-domain": 500},
        }
    )


def _chain() -> Blockchain:
    return Blockchain()


def _mine(chain: Blockchain, *transactions) -> None:
    for tx in transactions:
        chain.add_transaction(tx)
    chain.add_block()


def _attest(attester: str, verdict: bool = True, domain: str = DOMAIN):
    return make_attestation(attester, SUBJECT, RUBRIC, 0, verdict, 1, domain=domain)


class CertifyThresholdTests(unittest.TestCase):
    def test_sunny_path_enough_weighted_support(self):
        """Weights 100 + 80 = 180 meet a threshold of 150 → certificate."""
        chain = _chain()
        _mine(chain, _attest("attester-a"), _attest("attester-b"))

        cert = certify(chain, _registry(), SUBJECT, RUBRIC, DOMAIN, threshold=150)

        self.assertIsNotNone(cert)
        self.assertFalse(is_attestation(cert))  # it's a certificate, not an attestation
        self.assertEqual(cert.payload["type"], CERTIFICATE_TYPE)
        self.assertEqual(cert.payload["subject"], SUBJECT)
        self.assertEqual(cert.payload["rubric_root"], RUBRIC)
        self.assertEqual(cert.payload["domain"], DOMAIN)
        self.assertEqual(cert.payload["granted_by"], ["attester-a", "attester-b"])
        self.assertEqual(cert.sender, DEFAULT_ISSUER)

    def test_rainy_path_same_attesters_below_higher_threshold(self):
        """The same 100 + 80 = 180 does not meet a threshold of 200 → None."""
        chain = _chain()
        _mine(chain, _attest("attester-a"), _attest("attester-b"))

        self.assertIsNone(
            certify(chain, _registry(), SUBJECT, RUBRIC, DOMAIN, threshold=200)
        )

    def test_rainy_path_too_little_weight(self):
        """A single small-weight attester (30) misses a threshold of 100 → None."""
        chain = _chain()
        _mine(chain, _attest("attester-c"))

        self.assertIsNone(
            certify(chain, _registry(), SUBJECT, RUBRIC, DOMAIN, threshold=100)
        )

    def test_duplicate_attester_weight_counted_once(self):
        """One attester voting repeatedly contributes its weight only once."""
        chain = _chain()
        _mine(
            chain,
            make_attestation("attester-a", SUBJECT, RUBRIC, 0, True, 1, domain=DOMAIN),
            make_attestation("attester-a", SUBJECT, RUBRIC, 1, True, 1, domain=DOMAIN),
            make_attestation("attester-a", SUBJECT, RUBRIC, 2, True, 1, domain=DOMAIN),
        )

        # Weight 100 counted once: misses 150 but meets 100.
        self.assertIsNone(
            certify(chain, _registry(), SUBJECT, RUBRIC, DOMAIN, threshold=150)
        )
        cert = certify(chain, _registry(), SUBJECT, RUBRIC, DOMAIN, threshold=100)
        self.assertIsNotNone(cert)
        self.assertEqual(cert.payload["granted_by"], ["attester-a"])

    def test_negative_verdicts_do_not_count(self):
        """verdict=False attestations never add weight toward acceptance."""
        chain = _chain()
        _mine(chain, _attest("attester-a"), _attest("attester-b", verdict=False))

        # Only attester-a's 100 counts: misses 150, meets 100.
        self.assertIsNone(
            certify(chain, _registry(), SUBJECT, RUBRIC, DOMAIN, threshold=150)
        )
        cert = certify(chain, _registry(), SUBJECT, RUBRIC, DOMAIN, threshold=100)
        self.assertEqual(cert.payload["granted_by"], ["attester-a"])

    def test_other_domain_is_excluded(self):
        """An attestation in a different domain adds no weight to this domain."""
        chain = _chain()
        _mine(
            chain,
            _attest("attester-a"),                      # 100 in DOMAIN
            _attest("attester-b", domain="statistics"),  # not this domain
        )

        # attester-b's vote is in another domain, so only 100 counts → misses 150.
        self.assertIsNone(
            certify(chain, _registry(), SUBJECT, RUBRIC, DOMAIN, threshold=150)
        )

    def test_other_subject_or_rubric_is_ignored(self):
        """Support is pooled only within one (subject, rubric_root, domain)."""
        chain = _chain()
        _mine(
            chain,
            _attest("attester-a"),
            make_attestation("attester-b", "other-subject", RUBRIC, 0, True, 1, domain=DOMAIN),
            make_attestation("attester-c", SUBJECT, "other-rubric", 0, True, 1, domain=DOMAIN),
        )

        # Only attester-a matches subject *and* rubric *and* domain → 100 < 150.
        self.assertIsNone(
            certify(chain, _registry(), SUBJECT, RUBRIC, DOMAIN, threshold=150)
        )

    def test_votes_span_multiple_blocks(self):
        """Attesters in different mined blocks all contribute their weight."""
        chain = _chain()
        _mine(chain, _attest("attester-a"))
        _mine(chain, _attest("attester-b"))

        cert = certify(chain, _registry(), SUBJECT, RUBRIC, DOMAIN, threshold=180)
        self.assertIsNotNone(cert)
        self.assertEqual(cert.payload["granted_by"], ["attester-a", "attester-b"])

    def test_zero_weight_attester_excluded_from_granted_by(self):
        """A zero-weight attester adds no weight and is not credited.

        attester-zero attests positively but has weight 0 in the domain (its 500
        is in another domain). It contributes nothing to support and, by design,
        does not appear in granted_by — the certificate credits only who carried
        it.
        """
        chain = _chain()
        _mine(chain, _attest("attester-a"), _attest("attester-zero"))

        cert = certify(chain, _registry(), SUBJECT, RUBRIC, DOMAIN, threshold=100)
        self.assertIsNotNone(cert)
        self.assertEqual(cert.payload["granted_by"], ["attester-a"])


class MakeCertificateTests(unittest.TestCase):
    def test_records_domain(self):
        cert = make_certificate(SUBJECT, RUBRIC, DOMAIN, ["a", "b"])
        self.assertEqual(cert.payload["domain"], DOMAIN)

    def test_granted_by_is_sorted_for_determinism(self):
        """granted_by is stored sorted so the certificate hash is stable.

        Timestamps are pinned equal so the only thing that could differ between
        the two certificates is attester ordering — which sorting removes.
        """
        a = make_certificate(SUBJECT, RUBRIC, DOMAIN, ["c", "a", "b"])
        b = make_certificate(SUBJECT, RUBRIC, DOMAIN, ["a", "b", "c"])
        a.timestamp = b.timestamp = 1000.0

        self.assertEqual(a.payload["granted_by"], ["a", "b", "c"])
        self.assertEqual(a.hash, b.hash)


if __name__ == "__main__":
    unittest.main()
