"""Tests for the domain-scoped reputation registry."""

import copy
import unittest

from reputation.genesis import GENESIS_REPUTATION
from reputation.registry import ReputationRegistry


class GenesisLoadingTests(unittest.TestCase):
    def test_genesis_weights_load(self):
        reg = ReputationRegistry()
        self.assertEqual(reg.weight("genesis-alice", "bioinformatics"), 100)
        self.assertEqual(reg.weight("genesis-alice", "statistics"), 40)
        self.assertEqual(reg.weight("genesis-bob", "bioinformatics"), 60)

    def test_unknown_pubkey_is_zero(self):
        reg = ReputationRegistry()
        self.assertEqual(reg.weight("nobody", "bioinformatics"), 0)

    def test_unknown_domain_is_zero(self):
        reg = ReputationRegistry()
        self.assertEqual(reg.weight("genesis-bob", "statistics"), 0)

    def test_accepts_custom_genesis(self):
        reg = ReputationRegistry({"x": {"d": 7}})
        self.assertEqual(reg.weight("x", "d"), 7)
        self.assertEqual(reg.weight("genesis-alice", "bioinformatics"), 0)


class CreditDebitTests(unittest.TestCase):
    def test_credit_adds_weight(self):
        reg = ReputationRegistry()
        reg.credit("genesis-alice", "bioinformatics", 25)
        self.assertEqual(reg.weight("genesis-alice", "bioinformatics"), 125)

    def test_credit_creates_new_participant(self):
        reg = ReputationRegistry()
        reg.credit("newcomer", "statistics", 15)
        self.assertEqual(reg.weight("newcomer", "statistics"), 15)

    def test_debit_reduces_weight(self):
        reg = ReputationRegistry()
        reg.debit("genesis-alice", "statistics", 10)
        self.assertEqual(reg.weight("genesis-alice", "statistics"), 30)

    def test_debit_clamps_at_zero(self):
        """An over-large debit floors the weight at 0, never negative."""
        reg = ReputationRegistry()
        reg.debit("genesis-bob", "bioinformatics", 1000)
        self.assertEqual(reg.weight("genesis-bob", "bioinformatics"), 0)

    def test_debit_unknown_stays_zero(self):
        reg = ReputationRegistry()
        reg.debit("nobody", "d", 5)
        self.assertEqual(reg.weight("nobody", "d"), 0)


class GenesisImmutabilityTests(unittest.TestCase):
    def test_genesis_constant_not_mutated(self):
        """Registry operations must not leak back into the shared constant."""
        before = copy.deepcopy(GENESIS_REPUTATION)

        reg = ReputationRegistry()
        reg.credit("genesis-alice", "bioinformatics", 500)
        reg.debit("genesis-bob", "bioinformatics", 60)
        reg.credit("brand-new", "statistics", 3)

        self.assertEqual(GENESIS_REPUTATION, before)


class AuthorityTests(unittest.TestCase):
    def test_authority_true_when_any_domain_meets_threshold(self):
        reg = ReputationRegistry()
        # genesis-alice: statistics=40. Threshold 50 fails statistics but her
        # bioinformatics=100 clears it -> authority (any-domain rule).
        self.assertTrue(reg.is_authority("genesis-alice", 50))

    def test_authority_false_when_no_domain_meets_threshold(self):
        reg = ReputationRegistry()
        self.assertFalse(reg.is_authority("genesis-alice", 101))

    def test_authority_false_for_unknown(self):
        reg = ReputationRegistry()
        self.assertFalse(reg.is_authority("nobody", 1))


class TotalWeightTests(unittest.TestCase):
    def test_total_sums_across_domains(self):
        reg = ReputationRegistry()
        self.assertEqual(reg.total_weight("genesis-alice"), 140)

    def test_total_unknown_is_zero(self):
        reg = ReputationRegistry()
        self.assertEqual(reg.total_weight("nobody"), 0)


if __name__ == "__main__":
    unittest.main()
