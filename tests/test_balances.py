"""Tests for the token-balance / stake-bond layer.

Balances are chain-derived economic state (the counterpart of reputation): a
reviewer locks a real token stake to attest, gets it back plus a reward when the
review contributes to a certificate, and loses it to a burn when slashed. These
tests pin four properties:

* attesting without enough free balance is rejected by consensus;
* a contributing attestation releases its bond and pays REVIEW_REWARD;
* a slashed attestation's bond is burned (not just reputation); and
* balances are a **pure function of the chain prefix** — any node derives the
  same table from the same blocks.
"""

import unittest

from attestation.aggregator import make_certificate
from attestation.attestation import make_attestation
from blockchain.blockchain import Blockchain
from crypto.keys import keypair_from_seed
from reputation.balances import BalanceLedger
from reputation.derive import REVIEW_REWARD, derive_balances
from reputation.genesis import CONSENSUS_DOMAIN, DEFAULT_ENDOWMENT

# A genesis authority (consensus weight → may produce blocks) and two reviewers
# (real keys so their attestations sign/verify). Reputation weight and token
# balance are separate axes, so the anchors below are declared separately.
_AUTH_PRIV, AUTH = keypair_from_seed(bytes.fromhex("11" * 32))
_R1_PRIV, R1 = keypair_from_seed(bytes.fromhex("22" * 32))
_R2_PRIV, R2 = keypair_from_seed(bytes.fromhex("33" * 32))

DOMAIN = "general"
SUBJECT = "subject-pubkey"
RUBRIC = "rubric-root"
STAKE = 10

# Reputation anchor: the authority can produce blocks; reviewers carry competence
# weight (used only where a test also exercises certification/slashing quorum).
REP = {
    AUTH: {CONSENSUS_DOMAIN: 100},
    R1: {DOMAIN: 100},
    R2: {DOMAIN: 100},
}
# Token endowment anchor: reviewers start with 100 tokens to bond with.
BAL = {AUTH: 100, R1: 100, R2: 100}


def _att(priv, pubkey, item, verdict=True, stake=STAKE, subject=SUBJECT, rubric=RUBRIC):
    tx = make_attestation(pubkey, subject, rubric, item, verdict, stake, DOMAIN)
    tx.sign(priv)
    return tx


class LedgerUnitTests(unittest.TestCase):
    """The BalanceLedger primitive itself (total / locked / free / burn)."""

    def test_unknown_participant_holds_the_baseline_endowment(self):
        ledger = BalanceLedger(endowments={})
        self.assertEqual(ledger.free("nobody"), DEFAULT_ENDOWMENT)
        self.assertEqual(ledger.total("nobody"), DEFAULT_ENDOWMENT)
        self.assertEqual(ledger.locked("nobody"), 0)

    def test_lock_moves_from_free_but_not_total(self):
        ledger = BalanceLedger(endowments={R1: 100})
        ledger.lock(R1, 30)
        self.assertEqual(ledger.total(R1), 100)  # still owned
        self.assertEqual(ledger.locked(R1), 30)
        self.assertEqual(ledger.free(R1), 70)  # but unavailable

    def test_burn_drops_total_and_locked_leaving_free_unchanged(self):
        ledger = BalanceLedger(endowments={R1: 100})
        ledger.lock(R1, 30)  # free 70
        ledger.burn(R1, 30)  # the locked bond is destroyed permanently
        self.assertEqual(ledger.total(R1), 70)  # the loss is now real
        self.assertEqual(ledger.locked(R1), 0)
        self.assertEqual(ledger.free(R1), 70)  # free was already reduced by the lock


class LockOnAttestTests(unittest.TestCase):
    def test_attestation_locks_its_stake(self):
        """Committing an attestation locks the stake from the reviewer's free balance."""
        chain = Blockchain(genesis=REP, balances=BAL)
        chain.add_transaction(_att(_R1_PRIV, R1, 0))
        chain.add_block()

        ledger = derive_balances(chain, endowments=BAL, genesis=REP)

        self.assertEqual(ledger.total(R1), 100)
        self.assertEqual(ledger.locked(R1), STAKE)
        self.assertEqual(ledger.free(R1), 100 - STAKE)

    def test_uncontributing_bond_stays_locked(self):
        """With no certificate and no slash, the bond simply stays locked."""
        chain = Blockchain(genesis=REP, balances=BAL)
        chain.add_transaction(_att(_R1_PRIV, R1, 0))
        chain.add_block()
        # A second, unrelated block (no resolving event) leaves the bond locked.
        chain.add_transaction(_att(_R2_PRIV, R2, 1))
        chain.add_block()

        ledger = derive_balances(chain, endowments=BAL, genesis=REP)

        self.assertEqual(ledger.locked(R1), STAKE)
        self.assertEqual(ledger.free(R1), 100 - STAKE)


class AbstainTests(unittest.TestCase):
    """An abstain is weight-neutral, stake-free, and never slashable."""

    def test_abstain_locks_no_stake(self):
        """A committed abstain locks nothing from the reviewer's balance."""
        chain = Blockchain(genesis=REP, balances=BAL)
        chain.add_transaction(_att(_R1_PRIV, R1, 0, verdict=None))
        chain.add_block(producer_key=_AUTH_PRIV)

        # It rides into consensus (stake 0 is always coverable)...
        self.assertTrue(chain.is_valid_chain())
        # ...and derives no lock at all.
        ledger = derive_balances(chain, endowments=BAL, genesis=REP)
        self.assertEqual(ledger.locked(R1), 0)
        self.assertEqual(ledger.free(R1), 100)

    def test_abstain_can_never_be_slashed(self):
        """An abstain cannot form the conflicting evidence a slash requires."""
        from reputation.slashing import (
            approve_slash,
            make_slash,
            validate_slash,
        )
        from types import SimpleNamespace

        chain = Blockchain(genesis=REP, balances=BAL)
        yes = _att(_R1_PRIV, R1, 0, verdict=True)
        abstain = _att(_R1_PRIV, R1, 0, verdict=None)  # same claim, but an abstain
        chain.add_transaction(yes)
        chain.add_transaction(abstain)
        chain.add_block(producer_key=_AUTH_PRIV)

        evidence = sorted([yes.hash, abstain.hash])
        approvals = dict([approve_slash(_AUTH_PRIV, R1, DOMAIN, 40, evidence)])
        slash = make_slash(R1, DOMAIN, evidence, approvals, amount=40)

        # The abstain is honest, not equivocation, so the slash never validates.
        prefix = SimpleNamespace(blocks=chain.blocks[:])
        self.assertFalse(validate_slash(slash.payload, prefix, {AUTH}))

        # And a chain that tries to carry it is rejected outright (fail-closed).
        chain.add_transaction(slash)
        chain.add_block(producer_key=_AUTH_PRIV)
        self.assertFalse(chain.is_valid_chain())


class FreeBalanceConsensusTests(unittest.TestCase):
    """The free-balance rule is enforced by consensus (is_valid_chain)."""

    def test_attesting_without_free_balance_is_rejected(self):
        """A reviewer bonding more than they hold makes the chain invalid."""
        poor = {AUTH: 100, R1: 5}  # R1 endowed only 5, tries to bond 10
        chain = Blockchain(genesis=REP, balances=poor)
        chain.add_transaction(_att(_R1_PRIV, R1, 0, stake=10))
        chain.add_block(producer_key=_AUTH_PRIV)

        self.assertFalse(chain.is_valid_chain())

    def test_attesting_within_free_balance_is_accepted(self):
        """The same attestation is valid once the reviewer can cover the bond."""
        chain = Blockchain(genesis=REP, balances=BAL)  # R1 endowed 100
        chain.add_transaction(_att(_R1_PRIV, R1, 0, stake=10))
        chain.add_block(producer_key=_AUTH_PRIV)

        self.assertTrue(chain.is_valid_chain())

    def test_two_bonds_in_one_block_cannot_exceed_free_balance(self):
        """Within a single block, two bonds by one reviewer can't double-spend."""
        poor = {AUTH: 100, R1: 15}  # enough for one 10-bond, not two
        chain = Blockchain(genesis=REP, balances=poor)
        chain.add_transaction(_att(_R1_PRIV, R1, 0, stake=10))
        chain.add_transaction(_att(_R1_PRIV, R1, 1, stake=10))
        chain.add_block(producer_key=_AUTH_PRIV)

        self.assertFalse(chain.is_valid_chain())


class ReleaseAndRewardTests(unittest.TestCase):
    def test_contributing_attestation_releases_stake_and_pays_reward(self):
        """A certificate returns each credited reviewer's bond and pays REVIEW_REWARD."""
        chain = Blockchain(genesis=REP, balances=BAL)
        chain.add_transaction(_att(_R1_PRIV, R1, 0))
        chain.add_transaction(_att(_R2_PRIV, R2, 1))
        chain.add_block()
        # A certificate for the same (subject, rubric, domain) crediting both.
        chain.add_transaction(make_certificate(SUBJECT, RUBRIC, DOMAIN, [R1, R2]))
        chain.add_block()

        ledger = derive_balances(chain, endowments=BAL, genesis=REP)

        for reviewer in (R1, R2):
            self.assertEqual(ledger.locked(reviewer), 0)  # bond released
            self.assertEqual(ledger.total(reviewer), 100 + REVIEW_REWARD)  # + reward
            self.assertEqual(ledger.free(reviewer), 100 + REVIEW_REWARD)

    def test_reward_only_for_credited_reviewers(self):
        """An attester the certificate does not credit keeps their bond locked, no reward."""
        chain = Blockchain(genesis=REP, balances=BAL)
        chain.add_transaction(_att(_R1_PRIV, R1, 0))
        chain.add_transaction(_att(_R2_PRIV, R2, 1))
        chain.add_block()
        # Certificate credits only R1.
        chain.add_transaction(make_certificate(SUBJECT, RUBRIC, DOMAIN, [R1]))
        chain.add_block()

        ledger = derive_balances(chain, endowments=BAL, genesis=REP)

        self.assertEqual(ledger.total(R1), 100 + REVIEW_REWARD)
        self.assertEqual(ledger.locked(R1), 0)
        # R2 was not credited: still locked, no reward.
        self.assertEqual(ledger.total(R2), 100)
        self.assertEqual(ledger.locked(R2), STAKE)


class SlashBurnTests(unittest.TestCase):
    """A successful slash burns the offender's bonded stake, not just reputation."""

    def _slash_chain(self):
        """Chain where the offender (R1) equivocates and is validly slashed for it."""
        from reputation.slashing import approve_slash, make_slash

        # R1 is both offender and validator-approver here would be circular, so use
        # AUTH as the sole validator (N=1, quorum=1) and R1 as the offender.
        chain = Blockchain(genesis=REP, balances=BAL)
        yes = _att(_R1_PRIV, R1, 0, verdict=True)
        no = _att(_R1_PRIV, R1, 0, verdict=False)  # same claim, opposite verdict
        chain.add_transaction(yes)
        chain.add_transaction(no)
        chain.add_block(producer_key=_AUTH_PRIV)  # block 1: the evidence (two bonds)

        evidence = sorted([yes.hash, no.hash])
        approvals = dict([approve_slash(_AUTH_PRIV, R1, DOMAIN, 40, evidence)])
        chain.add_transaction(make_slash(R1, DOMAIN, evidence, approvals, amount=40))
        chain.add_block(producer_key=_AUTH_PRIV)  # block 2: the slash
        return chain

    def test_slashed_attestation_burns_the_bond(self):
        chain = self._slash_chain()

        ledger = derive_balances(chain, endowments=BAL, genesis=REP)

        # Both of R1's evidence bonds (2 × STAKE) are burned: total drops by 20,
        # nothing stays locked, and free reflects the permanent loss.
        self.assertEqual(ledger.total(R1), 100 - 2 * STAKE)
        self.assertEqual(ledger.locked(R1), 0)
        self.assertEqual(ledger.free(R1), 100 - 2 * STAKE)

    def test_slashed_chain_is_valid(self):
        """The whole slash chain (bonds + evidence + quorum slash) is consensus-valid."""
        self.assertTrue(self._slash_chain().is_valid_chain())


class PureFunctionTests(unittest.TestCase):
    """Balances are a deterministic pure function of the chain prefix."""

    def _chain_with_cert(self):
        chain = Blockchain(genesis=REP, balances=BAL)
        chain.add_transaction(_att(_R1_PRIV, R1, 0))
        chain.add_block()
        chain.add_transaction(make_certificate(SUBJECT, RUBRIC, DOMAIN, [R1]))
        cert_index = len(chain.blocks)  # the block about to be added
        chain.add_block()
        return chain, cert_index

    def test_same_chain_derives_identical_balances(self):
        """Deriving the same chain twice — as any two nodes would — is identical."""
        chain, _ = self._chain_with_cert()

        first = derive_balances(chain, endowments=BAL, genesis=REP).snapshot()
        second = derive_balances(chain, endowments=BAL, genesis=REP).snapshot()
        self.assertEqual(first, second)

        # And a *fresh* chain rebuilt from the same blocks (a second node syncing)
        # derives the same table — nothing depends on in-memory history.
        other = Blockchain(genesis=REP, balances=BAL)
        other.blocks = list(chain.blocks)
        self.assertEqual(
            derive_balances(other, endowments=BAL, genesis=REP).snapshot(), first
        )

    def test_prefix_rule_reward_appears_only_from_its_block(self):
        """The reward/release is absent before the certificate's block, present after."""
        chain, cert_index = self._chain_with_cert()

        before = derive_balances(chain, upto_index=cert_index, endowments=BAL, genesis=REP)
        self.assertEqual(before.locked(R1), STAKE)  # bond still locked
        self.assertEqual(before.total(R1), 100)  # no reward yet

        after = derive_balances(
            chain, upto_index=cert_index + 1, endowments=BAL, genesis=REP
        )
        self.assertEqual(after.locked(R1), 0)  # released
        self.assertEqual(after.total(R1), 100 + REVIEW_REWARD)  # rewarded


if __name__ == "__main__":
    unittest.main()
