"""Tests for endogenous validator promotion.

These pin down the design point the whole feature exists for: **consensus
authority is not automatic from competence**. A participant earns competence
reputation through attestations/certificates, but joining the validator set
(the right to produce/commit blocks) additionally requires a quorum of current
validators to approve a *promotion* transaction, subject to rate/fraction caps.

The three roles are kept distinct throughout:
  * competence reputation — per-domain skill weight (subject domain);
  * attester credibility — the same weight as it counts in weighted support;
  * consensus authority — membership in the validator set (CONSENSUS_DOMAIN or
    an approved promotion).
"""

import unittest

from blockchain.blockchain import (
    AUTHORITY_THRESHOLD,
    Blockchain,
    PROMOTION_THRESHOLD,
    quorum_size,
)
from blockchain.block import view_change_signing_bytes
from blockchain.promotion import approve_promotion, make_promotion
from crypto.keys import generate_keypair, keypair_from_seed, sign
from reputation.derive import derive_registry
from reputation.genesis import CONSENSUS_DOMAIN, GENESIS_AUTHORITY_KEYS

AUTHORITY_KEY, AUTHORITY_PUBKEY = GENESIS_AUTHORITY_KEYS["genesis-authority"]


def propose_scheduled(chain, priv_by_pub):
    """Append a block by the validator the schedule assigns to the next height (view 0).

    Once the scheduled-proposer rule is enforced, a block is only valid if its
    producer is whose turn it is; this resolves that producer from the prefix
    validator set and signs with its key, so promotion tests build valid chains
    without hard-coding a producer.
    """
    height = len(chain.blocks)
    return chain.add_block(producer_key=priv_by_pub[chain.proposer_for(height)])


def propose_as(chain, producer_priv, producer_pub, priv_by_pub):
    """Append a block by a SPECIFIC validator, advancing the view to its turn.

    Picks the smallest view whose scheduled proposer is ``producer_pub`` and, when
    that view is above 0, attaches the quorum view-change justification for it, so a
    chosen (e.g. freshly promoted) validator can produce even when it is not the
    view-0 leader for this height.
    """
    height = len(chain.blocks)
    ordered = sorted(chain.validator_set(height))
    view = (ordered.index(producer_pub) - height) % len(ordered)
    vc = None
    if view > 0:
        message = view_change_signing_bytes(height, view)
        vc = {
            pub: sign(priv_by_pub[pub], message)
            for pub in ordered[: quorum_size(len(ordered))]
        }
    return chain.add_block(producer_key=producer_priv, view=view, view_change_messages=vc)

# The competence domain a candidate earns merit in — deliberately NOT the
# consensus domain, so competence there never doubles as consensus authority.
COMPETENCE_DOMAIN = "general"


def genesis_validators(n: int):
    """``(keys, anchor)`` for ``n`` founding validators, including the authority.

    Key 0 is the reproducible genesis authority (it produces blocks); the rest are
    fresh keypairs. Every one holds CONSENSUS_DOMAIN weight, so they are the
    founding validator set — and nothing else, so none of them stands in for a
    promotion candidate. ``keys`` is a list of ``(private, public)`` pairs.
    """
    keys = [(AUTHORITY_KEY, AUTHORITY_PUBKEY)]
    for i in range(n - 1):
        keys.append(keypair_from_seed(bytes([200 + i]) * 32))
    anchor = {pub: {CONSENSUS_DOMAIN: 100} for _priv, pub in keys}
    return keys, anchor


def candidate_with_competence(anchor, weight):
    """Add a fresh candidate with ``weight`` competence (only) to ``anchor``.

    Returns ``(private, public)``. The candidate has competence in
    COMPETENCE_DOMAIN but NO consensus-domain weight, so it is not a validator —
    exactly the state a real earner would be in before any promotion.
    """
    priv, pub = generate_keypair()
    anchor[pub] = {COMPETENCE_DOMAIN: weight}
    return priv, pub


def promotion_tx(candidate_pub, approver_keys, domain=COMPETENCE_DOMAIN):
    """A promotion for ``candidate_pub`` signed by every key in ``approver_keys``."""
    approvals = dict(
        approve_promotion(priv, candidate_pub, domain) for priv, _pub in approver_keys
    )
    return make_promotion(candidate_pub, domain, approvals)


class PromotionValidationTests(unittest.TestCase):
    def test_valid_promotion_adds_a_validator(self):
        """A competent candidate approved by a quorum joins the validator set — and
        competence alone, before the promotion, did not."""
        keys, anchor = genesis_validators(4)  # quorum_size(4) = 3
        cand_priv, cand_pub = candidate_with_competence(anchor, PROMOTION_THRESHOLD)
        chain = Blockchain(genesis=anchor)

        # Before promotion: competent, but NOT a consensus authority.
        registry = derive_registry(chain, genesis=anchor)
        self.assertGreaterEqual(
            registry.weight(cand_pub, COMPETENCE_DOMAIN), PROMOTION_THRESHOLD
        )
        self.assertNotIn(cand_pub, chain.validator_set(1))

        chain.add_transaction(promotion_tx(cand_pub, keys[:3]))  # 3 approvers = quorum
        chain.add_block(producer_key=AUTHORITY_KEY)

        self.assertTrue(chain.is_valid_chain())
        # After promotion the candidate is a validator for the next block's set.
        self.assertIn(cand_pub, chain.validator_set(2))

    def test_candidate_below_threshold_cannot_be_promoted(self):
        """Merit is necessary: a candidate under PROMOTION_THRESHOLD is rejected
        even with a full quorum of approvals."""
        keys, anchor = genesis_validators(4)
        _priv, cand_pub = candidate_with_competence(anchor, PROMOTION_THRESHOLD - 1)
        chain = Blockchain(genesis=anchor)

        chain.add_transaction(promotion_tx(cand_pub, keys[:3]))  # quorum approves…
        chain.add_block(producer_key=AUTHORITY_KEY)

        self.assertFalse(chain.is_valid_chain())  # …but competence is short

    def test_promotion_without_quorum_is_invalid(self):
        """Peer approval is necessary: a competent candidate with fewer than a
        quorum of valid approvals is rejected."""
        keys, anchor = genesis_validators(4)  # quorum_size(4) = 3
        _priv, cand_pub = candidate_with_competence(anchor, PROMOTION_THRESHOLD)
        chain = Blockchain(genesis=anchor)

        chain.add_transaction(promotion_tx(cand_pub, keys[:2]))  # only 2 < quorum 3
        chain.add_block(producer_key=AUTHORITY_KEY)

        self.assertFalse(chain.is_valid_chain())

    def test_approvals_from_non_validators_do_not_count(self):
        """A quorum-sized pile of signatures from outsiders is not a quorum: only
        signatures by *current validators* count toward approval."""
        keys, anchor = genesis_validators(4)
        _priv, cand_pub = candidate_with_competence(anchor, PROMOTION_THRESHOLD)
        # Three strangers with real keys but no consensus authority.
        outsiders = [generate_keypair() for _ in range(3)]
        chain = Blockchain(genesis=anchor)

        chain.add_transaction(promotion_tx(cand_pub, outsiders))
        chain.add_block(producer_key=AUTHORITY_KEY)

        self.assertFalse(chain.is_valid_chain())

    def test_forged_approval_signature_does_not_count(self):
        """An approval entry whose signature is forged is dropped, so it cannot pad
        a promotion up to quorum."""
        keys, anchor = genesis_validators(4)  # quorum 3
        _priv, cand_pub = candidate_with_competence(anchor, PROMOTION_THRESHOLD)
        tx = promotion_tx(cand_pub, keys[:2])  # 2 genuine approvals
        # Add a third validator's pubkey with a garbage signature (not their sig).
        tx.payload["approvals"][keys[2][1]] = "00" * 64
        chain = Blockchain(genesis=anchor)
        chain.add_transaction(tx)
        chain.add_block(producer_key=AUTHORITY_KEY)

        self.assertFalse(chain.is_valid_chain())  # only 2 genuine < quorum 3


class PromotionCapTests(unittest.TestCase):
    def test_fraction_cap_blocks_mass_promotion(self):
        """The 1/3-per-window cap stops a fresh cohort from being minted large
        enough to seize a BFT share: with 2 founders, a second same-window
        promotion is refused even though it is competent and quorum-approved."""
        keys, anchor = genesis_validators(2)  # founders: authority + one more
        c1_priv, c1_pub = candidate_with_competence(anchor, PROMOTION_THRESHOLD)
        c2_priv, c2_pub = candidate_with_competence(anchor, PROMOTION_THRESHOLD)
        priv_by_pub = {pub: priv for priv, pub in keys}
        chain = Blockchain(genesis=anchor)

        # Block 1: promote c1. quorum_size(2) = 2 -> both founders approve.
        chain.add_transaction(promotion_tx(c1_pub, keys))
        propose_scheduled(chain, priv_by_pub)
        self.assertTrue(chain.is_valid_chain())
        self.assertIn(c1_pub, chain.validator_set(2))  # first promotion took effect

        # Block 2: try to promote c2 in the same window. Now 3 validators, so
        # quorum_size(3) = 3 -> the two founders PLUS c1 approve (quorum is met, so
        # the *fraction* cap, not quorum, is what must bite): promoting c2 would make
        # 2 of 4 fresh (> 1/3), so it is refused.
        c1_key = (c1_priv, c1_pub)
        priv_by_pub[c1_pub] = c1_priv  # c1 is now a validator, so it may be scheduled
        chain.add_transaction(promotion_tx(c2_pub, [*keys, c1_key]))
        propose_scheduled(chain, priv_by_pub)
        self.assertFalse(chain.is_valid_chain())

    def test_rate_cap_blocks_third_promotion_in_window(self):
        """Even when the fraction cap would allow it, no more than
        MAX_NEW_VALIDATORS_PER_WINDOW promotions may land within one window."""
        from blockchain.blockchain import MAX_NEW_VALIDATORS_PER_WINDOW

        # Six founders keep the fraction cap slack (3 fresh of 9 == 1/3 is allowed),
        # so the *rate* cap is the binding constraint on the (MAX+1)-th promotion.
        keys, anchor = genesis_validators(6)
        cands = [candidate_with_competence(anchor, PROMOTION_THRESHOLD) for _ in range(3)]
        priv_by_pub = {pub: priv for priv, pub in keys}
        chain = Blockchain(genesis=anchor)

        # Land MAX promotions, one per block, all inside the window.
        approvers = list(keys)
        for i in range(MAX_NEW_VALIDATORS_PER_WINDOW):
            cpriv, cpub = cands[i]
            quorum = approvers[: quorum_size(len(approvers))]
            chain.add_transaction(promotion_tx(cpub, quorum))
            propose_scheduled(chain, priv_by_pub)
            approvers.append((cpriv, cpub))  # newly promoted can now approve too
            priv_by_pub[cpub] = cpriv        # …and may now be scheduled to produce
        self.assertTrue(chain.is_valid_chain())

        # One more within the same window: quorum is satisfiable, fraction is slack,
        # but the rate cap refuses it.
        cpriv, cpub = cands[MAX_NEW_VALIDATORS_PER_WINDOW]
        quorum = approvers[: quorum_size(len(approvers))]
        chain.add_transaction(promotion_tx(cpub, quorum))
        propose_scheduled(chain, priv_by_pub)
        self.assertFalse(chain.is_valid_chain())


class PromotedValidatorTests(unittest.TestCase):
    def test_promoted_node_can_produce_and_commit_blocks(self):
        """The payoff: once promoted, the candidate holds consensus authority — its
        blocks validate and its commits count toward finality."""
        keys, anchor = genesis_validators(4)
        cand_priv, cand_pub = candidate_with_competence(anchor, PROMOTION_THRESHOLD)
        priv_by_pub = {pub: priv for priv, pub in [*keys, (cand_priv, cand_pub)]}
        chain = Blockchain(genesis=anchor)

        # Block 1: promote the candidate (quorum of 3 founders approve).
        chain.add_transaction(promotion_tx(cand_pub, keys[:3]))
        propose_scheduled(chain, priv_by_pub)
        self.assertTrue(chain.is_valid_chain())

        # Block 2: PRODUCED BY the newly-promoted candidate — accepted, because it
        # is a validator under the prefix (blocks 0..1) that granted its authority.
        # It produces in whichever view schedules it (with the quorum view-change
        # justification when that view is above 0).
        block2 = propose_as(chain, cand_priv, cand_pub, priv_by_pub)
        self.assertTrue(chain.is_valid_chain())
        self.assertEqual(block2.producer, cand_pub)

        # Its commit counts: attach a quorum of block 2's validator set including the
        # candidate, and the block finalizes with the candidate among the committers.
        validators = chain.validator_set(block2.index)
        self.assertIn(cand_pub, validators)
        signers = [cand_pub, *[p for p in validators if p != cand_pub]]
        for pub in signers[: quorum_size(len(validators))]:
            block2.add_commit_signature(priv_by_pub[pub])
        self.assertTrue(chain.is_final(block2))
        self.assertIn(cand_pub, block2.commit_signers() & validators)

    def test_competence_alone_confers_no_consensus_authority(self):
        """A highly competent, un-promoted participant is neither a validator nor an
        accepted block producer — the roles stay separate."""
        keys, anchor = genesis_validators(4)
        expert_priv, expert_pub = candidate_with_competence(anchor, 10_000)
        chain = Blockchain(genesis=anchor)

        # Enormous competence, zero consensus authority.
        self.assertNotIn(expert_pub, chain.validator_set(1))
        # A block it tries to produce is rejected under PoA.
        chain.add_block(producer_key=expert_priv)
        self.assertFalse(chain.is_valid_chain())


if __name__ == "__main__":
    unittest.main()
