"""Tests for the weighted tally over the reputation registry."""

import unittest

from attestation.attestation import make_attestation
from blockchain.blockchain import Blockchain
from reputation.registry import ReputationRegistry
from reputation.tally import (
    ALPHA_DEN,
    ALPHA_NUM,
    attester_clusters,
    capped_support,
    weighted_support,
)

SUBJECT = "student-pubkey"
RUBRIC = "rubric-root-hex"
DOMAIN = "bioinformatics"

# Genesis anchors used by the default registry (see reputation/genesis.py):
#   genesis-alice: bioinformatics=100, statistics=40
#   genesis-bob:   bioinformatics=60
ALICE = "genesis-alice"
BOB = "genesis-bob"


def _chain() -> Blockchain:
    return Blockchain()


def _mine(chain: Blockchain, *transactions) -> None:
    for tx in transactions:
        chain.add_transaction(tx)
    chain.add_block()


class WeightedSupportTests(unittest.TestCase):
    def test_two_genesis_attesters_weights_sum(self):
        """Support is the sum of the attesters' domain weights, not a headcount."""
        chain = _chain()
        _mine(
            chain,
            make_attestation(ALICE, SUBJECT, RUBRIC, 0, True, 1, domain=DOMAIN),
            make_attestation(BOB, SUBJECT, RUBRIC, 1, True, 1, domain=DOMAIN),
        )
        registry = ReputationRegistry()

        self.assertEqual(
            weighted_support(chain, registry, SUBJECT, RUBRIC, DOMAIN), 160
        )

    def test_zero_weight_attester_contributes_nothing(self):
        """An attester with no weight in the domain adds 0 to the support."""
        chain = _chain()
        _mine(
            chain,
            make_attestation(ALICE, SUBJECT, RUBRIC, 0, True, 1, domain=DOMAIN),
            make_attestation("stranger", SUBJECT, RUBRIC, 1, True, 1, domain=DOMAIN),
        )
        registry = ReputationRegistry()

        # Only alice's 100 counts; "stranger" has weight 0 in bioinformatics.
        self.assertEqual(
            weighted_support(chain, registry, SUBJECT, RUBRIC, DOMAIN), 100
        )

    def test_same_attester_twice_counts_once(self):
        """Repeat attestations by one attester are deduplicated by sender."""
        chain = _chain()
        _mine(
            chain,
            make_attestation(ALICE, SUBJECT, RUBRIC, 0, True, 1, domain=DOMAIN),
            make_attestation(ALICE, SUBJECT, RUBRIC, 1, True, 1, domain=DOMAIN),
        )
        registry = ReputationRegistry()

        self.assertEqual(
            weighted_support(chain, registry, SUBJECT, RUBRIC, DOMAIN), 100
        )

    def test_other_domain_is_excluded(self):
        """An attestation in a different domain is outside the tally's scope."""
        chain = _chain()
        _mine(
            chain,
            make_attestation(ALICE, SUBJECT, RUBRIC, 0, True, 1, domain=DOMAIN),
            # alice also attests in statistics, but we tally bioinformatics.
            make_attestation(ALICE, SUBJECT, RUBRIC, 1, True, 1, domain="statistics"),
            make_attestation(BOB, SUBJECT, RUBRIC, 2, True, 1, domain="statistics"),
        )
        registry = ReputationRegistry()

        # Only the bioinformatics attestation counts -> alice's 100.
        self.assertEqual(
            weighted_support(chain, registry, SUBJECT, RUBRIC, DOMAIN), 100
        )

    def test_negative_verdict_is_excluded(self):
        """Only positive verdicts contribute to support."""
        chain = _chain()
        _mine(
            chain,
            make_attestation(ALICE, SUBJECT, RUBRIC, 0, False, 1, domain=DOMAIN),
            make_attestation(BOB, SUBJECT, RUBRIC, 1, True, 1, domain=DOMAIN),
        )
        registry = ReputationRegistry()

        self.assertEqual(
            weighted_support(chain, registry, SUBJECT, RUBRIC, DOMAIN), 60
        )

    def test_abstain_contributes_zero_support(self):
        """An abstain (verdict=None) adds no weight, even from a high-weight attester."""
        chain = _chain()
        _mine(
            chain,
            # Alice abstains (would carry 100 if positive); only Bob's True counts.
            make_attestation(ALICE, SUBJECT, RUBRIC, 0, None, 0, domain=DOMAIN),
            make_attestation(BOB, SUBJECT, RUBRIC, 1, True, 1, domain=DOMAIN),
        )
        registry = ReputationRegistry()

        self.assertEqual(
            weighted_support(chain, registry, SUBJECT, RUBRIC, DOMAIN), 60
        )


class CollusionClusterTests(unittest.TestCase):
    """Clusters are connected components of the mutual-cross-attestation graph, and
    the cap clamps each multi-member cluster to ALPHA of the raw total. Everything
    is a pure function of the chain, so it is deterministic across nodes."""

    def _cross(self, attester, other):
        return make_attestation(attester, other, RUBRIC, 0, True, 1, domain=DOMAIN)

    def _cartel_chain(self):
        """A chain where x, y, z mutually cross-attest (one cluster) and w does not."""
        chain = _chain()
        _mine(
            chain,
            self._cross("x", "y"), self._cross("y", "x"),
            self._cross("y", "z"), self._cross("z", "y"),
            self._cross("x", "z"), self._cross("z", "x"),
            # w only attests a subject, never reciprocated -> stays a singleton.
            make_attestation("w", "some-subject", RUBRIC, 0, True, 1, domain=DOMAIN),
        )
        return chain

    def test_mutual_cross_attesters_form_one_cluster(self):
        chain = self._cartel_chain()
        clusters = attester_clusters(chain, {"x", "y", "z"})
        self.assertEqual(clusters, [{"x", "y", "z"}])

    def test_one_way_attestation_is_not_a_cluster(self):
        """An edge needs BOTH directions: x attests y but y never attests x."""
        chain = _chain()
        _mine(chain, self._cross("x", "y"))  # one direction only
        clusters = attester_clusters(chain, {"x", "y"})
        self.assertEqual(sorted(sorted(c) for c in clusters), [["x"], ["y"]])

    def test_independent_attesters_are_singletons(self):
        chain = _chain()
        _mine(chain, make_attestation("p", SUBJECT, RUBRIC, 0, True, 1, domain=DOMAIN))
        clusters = attester_clusters(chain, {"p", "q"})
        self.assertEqual(sorted(sorted(c) for c in clusters), [["p"], ["q"]])

    def test_capped_support_clamps_a_cluster_but_not_singletons(self):
        chain = self._cartel_chain()
        # Cluster {x,y,z} raw 300 -> clamped to floor(0.34*400)=136; singleton w
        # (weight 100) is uncapped. total=400, cap = 34*400//100 = 136.
        weights = {"x": 100, "y": 100, "z": 100, "w": 100}
        expected = (ALPHA_NUM * 400) // ALPHA_DEN + 100  # 136 + 100 = 236
        self.assertEqual(capped_support(chain, set(weights), weights), expected)

    def test_single_strong_attester_is_never_capped(self):
        """A lone high-weight attester (no ties) carries full weight — the honest
        'one authoritative reviewer' path is unaffected by the cap."""
        chain = _chain()
        _mine(chain, make_attestation("solo", SUBJECT, RUBRIC, 0, True, 1, domain=DOMAIN))
        self.assertEqual(capped_support(chain, {"solo"}, {"solo": 300}), 300)

    def test_cap_is_deterministic_across_identical_chains(self):
        """Two nodes replaying the same chain derive byte-identical clusters and cap."""
        weights = {"x": 100, "y": 100, "z": 100, "w": 100}
        a = capped_support(self._cartel_chain(), set(weights), weights)
        b = capped_support(self._cartel_chain(), set(weights), weights)
        self.assertEqual(a, b)
        # And the partition itself is order-independent / reproducible.
        self.assertEqual(
            attester_clusters(self._cartel_chain(), {"x", "y", "z"}),
            attester_clusters(self._cartel_chain(), {"z", "y", "x"}),
        )


if __name__ == "__main__":
    unittest.main()
