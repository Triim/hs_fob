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
from reputation.tally import weighted_support

SUBJECT = "student-pubkey"
RUBRIC = "rubric-root-hex"
DOMAIN = "bioinformatics"
SUB = "5ab" + "0" * 61


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
    return make_attestation(attester, SUBJECT, RUBRIC, 0, verdict, 1, SUB, domain=domain)


class CertifyThresholdTests(unittest.TestCase):
    def test_sunny_path_enough_weighted_support(self):
        """Weights 100 + 80 = 180 meet a threshold of 150 → certificate."""
        chain = _chain()
        _mine(chain, _attest("attester-a"), _attest("attester-b"))

        cert = certify(chain, _registry(), SUBJECT, RUBRIC, DOMAIN, SUB, threshold=150)

        self.assertIsNotNone(cert)
        self.assertFalse(is_attestation(cert))  # it's a certificate, not an attestation
        self.assertEqual(cert.payload["type"], CERTIFICATE_TYPE)
        self.assertEqual(cert.payload["subject"], SUBJECT)
        self.assertEqual(cert.payload["rubric_root"], RUBRIC)
        self.assertEqual(cert.payload["domain"], DOMAIN)
        self.assertEqual(cert.payload["submission_tx_hash"], SUB)
        self.assertEqual(cert.payload["granted_by"], ["attester-a", "attester-b"])
        self.assertEqual(cert.sender, DEFAULT_ISSUER)

    def test_rainy_path_same_attesters_below_higher_threshold(self):
        """The same 100 + 80 = 180 does not meet a threshold of 200 → None."""
        chain = _chain()
        _mine(chain, _attest("attester-a"), _attest("attester-b"))

        self.assertIsNone(
            certify(chain, _registry(), SUBJECT, RUBRIC, DOMAIN, SUB, threshold=200)
        )

    def test_rainy_path_too_little_weight(self):
        """A single small-weight attester (30) misses a threshold of 100 → None."""
        chain = _chain()
        _mine(chain, _attest("attester-c"))

        self.assertIsNone(
            certify(chain, _registry(), SUBJECT, RUBRIC, DOMAIN, SUB, threshold=100)
        )

    def test_duplicate_attester_weight_counted_once(self):
        """One attester voting repeatedly contributes its weight only once."""
        chain = _chain()
        _mine(
            chain,
            make_attestation("attester-a", SUBJECT, RUBRIC, 0, True, 1, SUB, domain=DOMAIN),
            make_attestation("attester-a", SUBJECT, RUBRIC, 1, True, 1, SUB, domain=DOMAIN),
            make_attestation("attester-a", SUBJECT, RUBRIC, 2, True, 1, SUB, domain=DOMAIN),
        )

        # Weight 100 counted once: misses 150 but meets 100.
        self.assertIsNone(
            certify(chain, _registry(), SUBJECT, RUBRIC, DOMAIN, SUB, threshold=150)
        )
        cert = certify(chain, _registry(), SUBJECT, RUBRIC, DOMAIN, SUB, threshold=100)
        self.assertIsNotNone(cert)
        self.assertEqual(cert.payload["granted_by"], ["attester-a"])

    def test_negative_verdicts_do_not_count(self):
        """verdict=False attestations never add weight toward acceptance."""
        chain = _chain()
        _mine(chain, _attest("attester-a"), _attest("attester-b", verdict=False))

        # Only attester-a's 100 counts: misses 150, meets 100.
        self.assertIsNone(
            certify(chain, _registry(), SUBJECT, RUBRIC, DOMAIN, SUB, threshold=150)
        )
        cert = certify(chain, _registry(), SUBJECT, RUBRIC, DOMAIN, SUB, threshold=100)
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
            certify(chain, _registry(), SUBJECT, RUBRIC, DOMAIN, SUB, threshold=150)
        )

    def test_other_subject_or_rubric_is_ignored(self):
        """Support is pooled only within one (subject, rubric_root, domain)."""
        chain = _chain()
        _mine(
            chain,
            _attest("attester-a"),
            make_attestation("attester-b", "other-subject", RUBRIC, 0, True, 1, SUB, domain=DOMAIN),
            make_attestation("attester-c", SUBJECT, "other-rubric", 0, True, 1, SUB, domain=DOMAIN),
        )

        # Only attester-a matches subject *and* rubric *and* domain → 100 < 150.
        self.assertIsNone(
            certify(chain, _registry(), SUBJECT, RUBRIC, DOMAIN, SUB, threshold=150)
        )

    def test_votes_span_multiple_blocks(self):
        """Attesters in different mined blocks all contribute their weight."""
        chain = _chain()
        _mine(chain, _attest("attester-a"))
        _mine(chain, _attest("attester-b"))

        cert = certify(chain, _registry(), SUBJECT, RUBRIC, DOMAIN, SUB, threshold=180)
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

        cert = certify(chain, _registry(), SUBJECT, RUBRIC, DOMAIN, SUB, threshold=100)
        self.assertIsNotNone(cert)
        self.assertEqual(cert.payload["granted_by"], ["attester-a"])


    def test_other_submission_does_not_co_count(self):
        """Reviews of a different submission of the same subject/rubric/domain are
        not pooled: attester-b's vote on another submission can't help certify SUB."""
        other_sub = "5cd" + "0" * 61
        chain = _chain()
        _mine(
            chain,
            make_attestation("attester-a", SUBJECT, RUBRIC, 0, True, 1, SUB, domain=DOMAIN),
            make_attestation("attester-b", SUBJECT, RUBRIC, 0, True, 1, other_sub, domain=DOMAIN),
        )

        # For SUB, only attester-a (100) counts → misses 150.
        self.assertIsNone(
            certify(chain, _registry(), SUBJECT, RUBRIC, DOMAIN, SUB, threshold=150)
        )
        cert = certify(chain, _registry(), SUBJECT, RUBRIC, DOMAIN, SUB, threshold=100)
        self.assertIsNotNone(cert)
        self.assertEqual(cert.payload["submission_tx_hash"], SUB)
        self.assertEqual(cert.payload["granted_by"], ["attester-a"])


class CollusionCapTests(unittest.TestCase):
    """A single cross-attesting cluster cannot contribute more than ALPHA of the
    counted support, so a cartel that cross-attests to farm reputation cannot pool
    it to force a certificate — while genuinely independent attesters are unaffected.
    """

    # Three attesters at weight 100 each (raw support 300). The cap is
    # floor(0.34 * 300) = 102, so a single cluster of all three contributes 102 —
    # well below a 250 threshold — whereas three singletons contribute the full 300.
    def _registry(self) -> ReputationRegistry:
        return ReputationRegistry(
            {name: {DOMAIN: 100} for name in ("a", "b", "c", "x", "y", "z")}
        )

    def _cross(self, attester: str, other: str):
        """``attester`` positively attests ``other`` as subject (a cross-attestation)."""
        return make_attestation(attester, other, RUBRIC, 0, True, 1, SUB, domain=DOMAIN)

    def test_three_independent_attesters_certify_normally(self):
        """No two of a, b, c cross-attest, so each is its own singleton cluster and
        carries full weight: 100 + 100 + 100 = 300 clears threshold 250."""
        chain = _chain()
        _mine(chain, _attest("a"), _attest("b"), _attest("c"))

        cert = certify(chain, self._registry(), SUBJECT, RUBRIC, DOMAIN, SUB, threshold=250)

        self.assertIsNotNone(cert)
        self.assertEqual(cert.payload["granted_by"], ["a", "b", "c"])

    def test_cross_attesting_cartel_is_capped_and_fails(self):
        """x, y, z mutually cross-attest, so they collapse into one cluster whose
        joint contribution is clamped to 102 (< 250) — the certificate is denied,
        even though their raw weighted support (300) would clear the threshold."""
        chain = _chain()
        _mine(
            chain,
            # Mutual cross-attestations weld x, y, z into a single cluster.
            self._cross("x", "y"), self._cross("y", "x"),
            self._cross("x", "z"), self._cross("z", "x"),
            self._cross("y", "z"), self._cross("z", "y"),
            # The whole cartel then backs the paying subject.
            _attest("x"), _attest("y"), _attest("z"),
        )

        # Raw (uncapped) support would pass; the cap is what denies it.
        self.assertEqual(
            weighted_support(chain, self._registry(), SUBJECT, RUBRIC, DOMAIN, SUB), 300
        )
        self.assertIsNone(
            certify(chain, self._registry(), SUBJECT, RUBRIC, DOMAIN, SUB, threshold=250)
        )

    def test_partial_cartel_still_capped_but_independent_counts_full(self):
        """A mixed field: x and y collude (one capped cluster) while c is
        independent. Cluster {x, y} raw 200 is clamped to floor(0.34*300)=102;
        singleton c adds its full 100 → 202, still short of 250."""
        chain = _chain()
        _mine(
            chain,
            self._cross("x", "y"), self._cross("y", "x"),
            _attest("x"), _attest("y"), _attest("c"),
        )

        self.assertIsNone(
            certify(chain, self._registry(), SUBJECT, RUBRIC, DOMAIN, SUB, threshold=250)
        )
        # Drop the threshold below the capped total (202) and it certifies, crediting
        # every genuine attester — the cap governs how much counts, not who is credited.
        cert = certify(chain, self._registry(), SUBJECT, RUBRIC, DOMAIN, SUB, threshold=200)
        self.assertIsNotNone(cert)
        self.assertEqual(cert.payload["granted_by"], ["c", "x", "y"])


class RequiredItemCoverageTests(unittest.TestCase):
    """A certificate needs BOTH enough weighted support AND coverage of every
    required rubric item by a weight-bearing positive attester. Enough total
    weight while a required item is left uncovered must NOT certify.

    Default: ``required_items`` unspecified means "no per-item requirement" at the
    ``certify`` API level (threshold-only, preserving prior behaviour); the
    "all items required unless specified" default lives on :class:`Rubric`, whose
    ``required_items`` the caller passes in (see ``test_rubric.py``).
    """

    def test_enough_weight_but_required_item_uncovered_no_certificate(self):
        """attester-a covers item 0 (weight 100 ≥ threshold 100) but item 1 is
        attested by nobody → the required item is uncovered → no certificate."""
        chain = _chain()
        _mine(chain, _attest("attester-a"))  # item 0 only

        self.assertIsNone(
            certify(
                chain, _registry(), SUBJECT, RUBRIC, DOMAIN, SUB,
                threshold=100, required_items=[0, 1],
            )
        )

    def test_full_coverage_and_threshold_issues(self):
        """Items 0 and 1 each covered by a weight-bearing attester and weight
        100 + 80 = 180 ≥ threshold 150 → certificate, recording required_items."""
        chain = _chain()
        _mine(
            chain,
            make_attestation("attester-a", SUBJECT, RUBRIC, 0, True, 1, SUB, domain=DOMAIN),
            make_attestation("attester-b", SUBJECT, RUBRIC, 1, True, 1, SUB, domain=DOMAIN),
        )

        cert = certify(
            chain, _registry(), SUBJECT, RUBRIC, DOMAIN, SUB,
            threshold=150, required_items=[0, 1],
        )
        self.assertIsNotNone(cert)
        self.assertEqual(cert.payload["required_items"], [0, 1])
        self.assertEqual(cert.payload["granted_by"], ["attester-a", "attester-b"])

    def test_zero_weight_attester_does_not_cover_a_required_item(self):
        """attester-a (100) covers item 0 and clears threshold 100, but item 1 is
        covered only by attester-zero (weight 0 in DOMAIN) → item 1 uncovered → None.

        Coverage, like support, must come from a weight-bearing attester, so a
        reputation-less reviewer cannot manufacture coverage of a required item."""
        chain = _chain()
        _mine(
            chain,
            make_attestation("attester-a", SUBJECT, RUBRIC, 0, True, 1, SUB, domain=DOMAIN),
            make_attestation("attester-zero", SUBJECT, RUBRIC, 1, True, 1, SUB, domain=DOMAIN),
        )

        self.assertIsNone(
            certify(
                chain, _registry(), SUBJECT, RUBRIC, DOMAIN, SUB,
                threshold=100, required_items=[0, 1],
            )
        )

    def test_default_no_required_items_is_threshold_only(self):
        """Unspecified required_items ⇒ no coverage constraint: item 0 alone
        certifies on weight, and the payload records an explicit empty list."""
        chain = _chain()
        _mine(chain, _attest("attester-a"), _attest("attester-b"))  # both on item 0

        cert = certify(chain, _registry(), SUBJECT, RUBRIC, DOMAIN, SUB, threshold=150)
        self.assertIsNotNone(cert)
        self.assertEqual(cert.payload["required_items"], [])

    def test_negative_verdict_does_not_cover_a_required_item(self):
        """A verdict=False on a required item is not coverage: item 1 is opposed,
        not passed, so it stays uncovered even though weight on item 0 suffices."""
        chain = _chain()
        _mine(
            chain,
            make_attestation("attester-a", SUBJECT, RUBRIC, 0, True, 1, SUB, domain=DOMAIN),
            make_attestation("attester-b", SUBJECT, RUBRIC, 1, False, 1, SUB, domain=DOMAIN),
        )

        self.assertIsNone(
            certify(
                chain, _registry(), SUBJECT, RUBRIC, DOMAIN, SUB,
                threshold=100, required_items=[0, 1],
            )
        )


class MakeCertificateTests(unittest.TestCase):
    def test_records_domain_and_submission(self):
        cert = make_certificate(SUBJECT, RUBRIC, DOMAIN, SUB, ["a", "b"])
        self.assertEqual(cert.payload["domain"], DOMAIN)
        self.assertEqual(cert.payload["submission_tx_hash"], SUB)

    def test_granted_by_is_sorted_for_determinism(self):
        """granted_by is stored sorted so the certificate hash is stable.

        Timestamps are pinned equal so the only thing that could differ between
        the two certificates is attester ordering — which sorting removes.
        """
        a = make_certificate(SUBJECT, RUBRIC, DOMAIN, SUB, ["c", "a", "b"])
        b = make_certificate(SUBJECT, RUBRIC, DOMAIN, SUB, ["a", "b", "c"])
        a.timestamp = b.timestamp = 1000.0

        self.assertEqual(a.payload["granted_by"], ["a", "b", "c"])
        self.assertEqual(a.hash, b.hash)


if __name__ == "__main__":
    unittest.main()
