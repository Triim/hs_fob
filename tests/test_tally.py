"""Tests for the weighted tally over the reputation registry."""

import unittest

from attestation.attestation import make_attestation
from blockchain.blockchain import Blockchain
from reputation.registry import ReputationRegistry
from reputation.tally import weighted_support

SUBJECT = "student-pubkey"
RUBRIC = "rubric-root-hex"
DOMAIN = "bioinformatics"

# Genesis anchors used by the default registry (see reputation/genesis.py):
#   genesis-alice: bioinformatics=100, statistics=40
#   genesis-bob:   bioinformatics=60
ALICE = "genesis-alice"
BOB = "genesis-bob"


def _chain() -> Blockchain:
    return Blockchain(difficulty=0)


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


if __name__ == "__main__":
    unittest.main()
