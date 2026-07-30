"""Tests for reputation derived from the chain (the prefix rule)."""

import unittest

from attestation.aggregator import make_certificate
from blockchain.blockchain import Blockchain
from reputation.derive import CERTIFICATE_REWARD, derive_registry
from reputation.slashing import make_slash

SUBJECT = "student-pubkey"
RUBRIC = "rubric-root-hex"
DOMAIN = "bioinformatics"


def _chain() -> Blockchain:
    return Blockchain()


def _mine(chain: Blockchain, *transactions) -> None:
    for tx in transactions:
        chain.add_transaction(tx)
    chain.add_block()


class DeriveRegistryTests(unittest.TestCase):
    def test_genesis_only_chain_yields_genesis_weights(self):
        """With no events, the derived registry is exactly the genesis anchor."""
        chain = _chain()  # only the genesis block, no transactions

        registry = derive_registry(chain)

        self.assertEqual(registry.weight("genesis-alice", "bioinformatics"), 100)
        self.assertEqual(registry.weight("genesis-bob", "bioinformatics"), 60)
        # Someone the anchor never mentioned still has zero.
        self.assertEqual(registry.weight(SUBJECT, DOMAIN), 0)

    def test_certificate_credits_subject_in_its_domain(self):
        """A committed certificate credits its subject by CERTIFICATE_REWARD."""
        chain = _chain()
        cert = make_certificate(SUBJECT, RUBRIC, DOMAIN, ["genesis-alice"])
        _mine(chain, cert)

        registry = derive_registry(chain)

        self.assertEqual(registry.weight(SUBJECT, DOMAIN), CERTIFICATE_REWARD)
        # The credit is domain-scoped: no leakage into another domain.
        self.assertEqual(registry.weight(SUBJECT, "statistics"), 0)

    def test_two_certificates_accumulate(self):
        """Reputation accrues additively as certificates are committed."""
        chain = _chain()
        _mine(chain, make_certificate(SUBJECT, RUBRIC, DOMAIN, ["genesis-alice"]))
        _mine(chain, make_certificate(SUBJECT, "other-rubric", DOMAIN, ["genesis-bob"]))

        registry = derive_registry(chain)

        self.assertEqual(registry.weight(SUBJECT, DOMAIN), 2 * CERTIFICATE_REWARD)

    def test_upto_index_excludes_later_blocks_prefix_rule(self):
        """Deriving up to index N ignores a certificate committed in block N.

        This pins the prefix rule that consensus depends on: the state *before*
        a block never reflects that block's own contents.
        """
        chain = _chain()
        # Block 1 carries the certificate; genesis is block 0.
        _mine(chain, make_certificate(SUBJECT, RUBRIC, DOMAIN, ["genesis-alice"]))
        cert_block_index = chain.last_block.index  # == 1

        # Derived up to (excluding) the certificate's block -> subject has 0.
        before = derive_registry(chain, upto_index=cert_block_index)
        self.assertEqual(before.weight(SUBJECT, DOMAIN), 0)

        # Derived including it -> the credit is present.
        after = derive_registry(chain, upto_index=cert_block_index + 1)
        self.assertEqual(after.weight(SUBJECT, DOMAIN), CERTIFICATE_REWARD)


class SlashDerivationTests(unittest.TestCase):
    def test_slash_reduces_derived_weight(self):
        """A slash event debits the offender in its domain."""
        chain = _chain()
        _mine(
            chain,
            make_slash("genesis-alice", "bioinformatics", "double vote", "ref", amount=40),
        )

        registry = derive_registry(chain)

        self.assertEqual(registry.weight("genesis-alice", "bioinformatics"), 60)
        # Domain-scoped: an unrelated domain is untouched.
        self.assertEqual(registry.weight("genesis-alice", "statistics"), 40)

    def test_over_slash_clamps_at_zero(self):
        """Debiting more than the offender holds floors the weight at 0."""
        chain = _chain()
        _mine(
            chain,
            make_slash("genesis-alice", "bioinformatics", "grave fault", "ref", amount=500),
        )

        registry = derive_registry(chain)

        self.assertEqual(registry.weight("genesis-alice", "bioinformatics"), 0)

    def test_slash_prefix_rule_excludes_its_own_block(self):
        """A slash in block N is applied only from N onward (prefix rule)."""
        chain = _chain()
        _mine(
            chain,
            make_slash("genesis-alice", "bioinformatics", "double vote", "ref", amount=40),
        )
        slash_block_index = chain.last_block.index

        before = derive_registry(chain, upto_index=slash_block_index)
        self.assertEqual(before.weight("genesis-alice", "bioinformatics"), 100)

        after = derive_registry(chain, upto_index=slash_block_index + 1)
        self.assertEqual(after.weight("genesis-alice", "bioinformatics"), 60)


if __name__ == "__main__":
    unittest.main()
