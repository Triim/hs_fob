"""Tests for reputation derived from the chain (the prefix rule)."""

import unittest

from attestation.aggregator import make_certificate
from attestation.attestation import make_attestation
from blockchain.blockchain import Blockchain
from crypto.keys import keypair_from_seed
from reputation.derive import CERTIFICATE_REWARD, derive_registry
from reputation.genesis import CONSENSUS_DOMAIN
from reputation.slashing import MAX_SLASH, approve_slash, make_slash

SUBJECT = "student-pubkey"
RUBRIC = "rubric-root-hex"
DOMAIN = "bioinformatics"

# Real keypairs for the slash tests: an OFFENDER who will equivocate, and a
# VALIDATOR who approves slashes. The slash model is evidence-based and
# quorum-approved, so both need real keys (the offender must sign the two
# conflicting attestations; the validator must sign the approval).
_OFFENDER_PRIV, OFFENDER = keypair_from_seed(bytes.fromhex("0f" * 32))
_VALIDATOR_PRIV, VALIDATOR = keypair_from_seed(bytes.fromhex("02" * 32))


def _chain() -> Blockchain:
    return Blockchain()


def _mine(chain: Blockchain, *transactions) -> None:
    for tx in transactions:
        chain.add_transaction(tx)
    chain.add_block()


def _slash_anchor(offender_weight: int = 100) -> dict:
    """Anchor with an OFFENDER holding competence and a VALIDATOR holding consensus.

    The offender's DOMAIN weight is what a slash debits; the validator's
    CONSENSUS_DOMAIN weight makes it the sole (N=1, quorum=1) approving validator.
    """
    return {
        OFFENDER: {DOMAIN: offender_weight},
        VALIDATOR: {CONSENSUS_DOMAIN: 100},
    }


def _equivocation(subject="subj", rubric="rub", item_index=0):
    """Two contradictory attestations by the OFFENDER on the same claim."""
    yes = make_attestation(OFFENDER, subject, rubric, item_index, True, 1, DOMAIN)
    yes.sign(_OFFENDER_PRIV)
    no = make_attestation(OFFENDER, subject, rubric, item_index, False, 1, DOMAIN)
    no.sign(_OFFENDER_PRIV)
    return yes, no


def _slash_chain(amount: int, offender_weight: int = 100):
    """A chain whose block 1 carries the offender's equivocation and block 2 a
    valid, quorum-approved slash referencing it. Returns ``(chain, anchor)``."""
    anchor = _slash_anchor(offender_weight)
    chain = Blockchain(genesis=anchor)
    yes, no = _equivocation()
    chain.add_transaction(yes)
    chain.add_transaction(no)
    chain.add_block(producer_key=_VALIDATOR_PRIV)  # block 1: the evidence
    evidence = sorted([yes.hash, no.hash])
    approvals = dict([approve_slash(_VALIDATOR_PRIV, OFFENDER, DOMAIN, amount, evidence)])
    chain.add_transaction(make_slash(OFFENDER, DOMAIN, evidence, approvals, amount=amount))
    chain.add_block(producer_key=_VALIDATOR_PRIV)  # block 2: the slash
    return chain, anchor


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


class InjectedGenesisTests(unittest.TestCase):
    def test_injected_anchor_replaces_the_canonical_one(self):
        """A supplied genesis seeds the registry instead of GENESIS_REPUTATION."""
        chain = _chain()
        custom = {"newcomer": {"robotics": 70}}

        registry = derive_registry(chain, genesis=custom)

        self.assertEqual(registry.weight("newcomer", "robotics"), 70)
        # The canonical participants are absent under the injected anchor.
        self.assertEqual(registry.weight("genesis-alice", "bioinformatics"), 0)

    def test_default_is_the_canonical_anchor(self):
        """Omitting genesis preserves the canonical behaviour for all callers."""
        registry = derive_registry(_chain())
        self.assertEqual(registry.weight("genesis-alice", "bioinformatics"), 100)

    def test_injected_events_apply_on_top_of_injected_anchor(self):
        """Chain events accrue over the injected anchor, not the canonical one."""
        chain = _chain()
        _mine(chain, make_certificate(SUBJECT, RUBRIC, "robotics", ["newcomer"]))

        registry = derive_registry(chain, genesis={"newcomer": {"robotics": 70}})

        self.assertEqual(registry.weight("newcomer", "robotics"), 70)
        self.assertEqual(registry.weight(SUBJECT, "robotics"), CERTIFICATE_REWARD)


class SlashDerivationTests(unittest.TestCase):
    """Slashing is evidence-based and quorum-approved: derivation debits the
    offender **only** for a valid slash, capped at MAX_SLASH and floored at 0.

    These replace the former single-authority slash tests (which passed a
    free-text reason + reference and were applied unconditionally) with the
    evidence + quorum model, keeping the debit/clamp assertions intact.
    """

    def test_valid_evidence_quorum_slash_debits(self):
        """A valid, quorum-approved slash debits the offender in its domain."""
        chain, anchor = _slash_chain(amount=40)

        registry = derive_registry(chain, genesis=anchor)

        self.assertEqual(registry.weight(OFFENDER, DOMAIN), 60)  # 100 - 40

    def test_slash_debit_obeys_max_cap(self):
        """A slash never debits more than MAX_SLASH, even if a larger amount is signed."""
        # Offender holds 200; an approved amount of 500 must still debit only
        # MAX_SLASH (100), leaving 100 — proving the cap, not a clamp at 0.
        chain, anchor = _slash_chain(amount=500, offender_weight=200)

        registry = derive_registry(chain, genesis=anchor)

        self.assertEqual(MAX_SLASH, 100)
        self.assertEqual(registry.weight(OFFENDER, DOMAIN), 100)  # 200 - min(500, 100)

    def test_over_slash_clamps_at_zero(self):
        """Debiting (up to the cap) more than the offender holds floors weight at 0."""
        # Offender holds only 80; the capped debit of 100 exceeds it, so the
        # registry clamps the result at 0 rather than going negative.
        chain, anchor = _slash_chain(amount=100, offender_weight=80)

        registry = derive_registry(chain, genesis=anchor)

        self.assertEqual(registry.weight(OFFENDER, DOMAIN), 0)

    def test_fabricated_evidence_does_not_debit(self):
        """A slash whose evidence isn't on-chain (fabricated) has no effect."""
        anchor = _slash_anchor()
        chain = Blockchain(genesis=anchor)
        # No equivocation is ever committed; the slash cites hashes of nothing.
        evidence = sorted(["dead" * 16, "beef" * 16])
        approvals = dict([approve_slash(_VALIDATOR_PRIV, OFFENDER, DOMAIN, 40, evidence)])
        chain.add_transaction(make_slash(OFFENDER, DOMAIN, evidence, approvals, amount=40))
        chain.add_block(producer_key=_VALIDATOR_PRIV)

        registry = derive_registry(chain, genesis=anchor)

        self.assertEqual(registry.weight(OFFENDER, DOMAIN), 100)  # untouched

    def test_non_conflicting_evidence_does_not_debit(self):
        """Two real but *non*-contradictory attestations are not slashable evidence."""
        anchor = _slash_anchor()
        chain = Blockchain(genesis=anchor)
        # Same verdict on two *different* items — no contradiction.
        a0 = make_attestation(OFFENDER, "subj", "rub", 0, True, 1, DOMAIN)
        a0.sign(_OFFENDER_PRIV)
        a1 = make_attestation(OFFENDER, "subj", "rub", 1, True, 1, DOMAIN)
        a1.sign(_OFFENDER_PRIV)
        chain.add_transaction(a0)
        chain.add_transaction(a1)
        chain.add_block(producer_key=_VALIDATOR_PRIV)
        evidence = sorted([a0.hash, a1.hash])
        approvals = dict([approve_slash(_VALIDATOR_PRIV, OFFENDER, DOMAIN, 40, evidence)])
        chain.add_transaction(make_slash(OFFENDER, DOMAIN, evidence, approvals, amount=40))
        chain.add_block(producer_key=_VALIDATOR_PRIV)

        registry = derive_registry(chain, genesis=anchor)

        self.assertEqual(registry.weight(OFFENDER, DOMAIN), 100)  # untouched

    def test_evidence_not_the_offenders_does_not_debit(self):
        """Evidence signed by someone *other* than the offender is not slashable."""
        anchor = _slash_anchor()
        chain = Blockchain(genesis=anchor)
        # The two conflicting attestations are the VALIDATOR's, not the offender's.
        yes = make_attestation(VALIDATOR, "subj", "rub", 0, True, 1, DOMAIN)
        yes.sign(_VALIDATOR_PRIV)
        no = make_attestation(VALIDATOR, "subj", "rub", 0, False, 1, DOMAIN)
        no.sign(_VALIDATOR_PRIV)
        chain.add_transaction(yes)
        chain.add_transaction(no)
        chain.add_block(producer_key=_VALIDATOR_PRIV)
        evidence = sorted([yes.hash, no.hash])
        approvals = dict([approve_slash(_VALIDATOR_PRIV, OFFENDER, DOMAIN, 40, evidence)])
        chain.add_transaction(make_slash(OFFENDER, DOMAIN, evidence, approvals, amount=40))
        chain.add_block(producer_key=_VALIDATOR_PRIV)

        registry = derive_registry(chain, genesis=anchor)

        self.assertEqual(registry.weight(OFFENDER, DOMAIN), 100)  # untouched

    def test_slash_without_quorum_does_not_debit(self):
        """A slash lacking quorum approval (no valid approver signatures) is inert."""
        anchor = _slash_anchor()
        chain = Blockchain(genesis=anchor)
        yes, no = _equivocation()
        chain.add_transaction(yes)
        chain.add_transaction(no)
        chain.add_block(producer_key=_VALIDATOR_PRIV)
        evidence = sorted([yes.hash, no.hash])
        # Empty approvals -> 0 approvers, below quorum_size(1) = 1.
        chain.add_transaction(make_slash(OFFENDER, DOMAIN, evidence, {}, amount=40))
        chain.add_block(producer_key=_VALIDATOR_PRIV)

        registry = derive_registry(chain, genesis=anchor)

        self.assertEqual(registry.weight(OFFENDER, DOMAIN), 100)  # untouched

    def test_slash_prefix_rule_excludes_its_own_block(self):
        """A slash in block N is applied only from N onward (prefix rule)."""
        chain, anchor = _slash_chain(amount=40)
        slash_block_index = chain.last_block.index

        before = derive_registry(chain, upto_index=slash_block_index, genesis=anchor)
        self.assertEqual(before.weight(OFFENDER, DOMAIN), 100)

        after = derive_registry(chain, upto_index=slash_block_index + 1, genesis=anchor)
        self.assertEqual(after.weight(OFFENDER, DOMAIN), 60)


if __name__ == "__main__":
    unittest.main()
