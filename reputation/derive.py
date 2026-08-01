"""Derived reputation — the registry as a pure function of the chain.

Reputation is **not** an independently mutated object. It is *derived state*:
the current weight table is what you get by replaying the chain from genesis.
Start from :data:`~reputation.genesis.GENESIS_REPUTATION`, then apply each
chain event in order:

- a **certificate** issuance credits its subject in the certificate's domain by
  :data:`CERTIFICATE_REWARD` (honest work earns standing);
- a **slash** event debits the offender in its domain — but *only* when it is a
  valid, evidence-based, quorum-approved slash (:func:`reputation.slashing.validate_slash`):
  the offender's two conflicting attestations must exist in the prefix and a
  quorum of the prefix's validators must have signed it. The debit is capped at
  :data:`~reputation.slashing.MAX_SLASH` and floored at 0 (proven, bounded
  misconduct loses standing). An unproven slash simply has no effect here — and
  is rejected outright by consensus (see :mod:`blockchain.blockchain`).

Why derive it? The blockchain already solves *agreement on state* for the chain
itself. If reputation is a pure function of that agreed chain, then every node
computes the same weights for free — no extra consensus needed. An independent,
mutable registry would reintroduce the entire consensus problem for a *second*
piece of state, and two states can drift. So :meth:`ReputationRegistry.credit`
and :meth:`ReputationRegistry.debit` are used **only** inside this recomputation,
never called ad hoc from anywhere else.

The prefix rule
---------------
:func:`derive_registry` takes ``upto_index``: it applies events from blocks
``0 .. upto_index - 1`` only. This is what lets consensus break its own
circularity — a block N's producer is checked against reputation derived from
blocks ``0 .. N-1``, i.e. *before* block N, so a block can never authorise
itself (see :mod:`blockchain.blockchain`).

MVP note: this recomputes from scratch on every call. An incremental cache is a
valid future optimization, but it must always yield exactly what a full
recompute would — the full recompute here stays the source of truth.
"""

from __future__ import annotations

from types import SimpleNamespace

from attestation.attestation import is_abstain, is_attestation
from reputation.balances import BalanceLedger
from reputation.genesis import CONSENSUS_DOMAIN
from reputation.registry import ReputationRegistry
from reputation.slashing import MAX_SLASH, SLASH_TYPE, validate_slash

# Fixed weight a subject earns in a certificate's domain when a certificate for
# them is committed. A flat reward keeps derivation simple and auditable; a
# stake- or issuer-weighted reward is a possible future refinement.
CERTIFICATE_REWARD = 10

# Discriminator for a certificate payload. Kept as a literal (like SLASH_TYPE is
# imported) so this module recognises certificates without importing the
# aggregator, which would be circular (the aggregator imports the chain, which
# imports this module).
_CERTIFICATE_TYPE = "certificate"

# Flat token reward a reviewer earns when one of their attestations contributes
# to an issued certificate — the *motivation* half of the stake/reward pair (the
# bond is the *honesty* half). Kept flat and separate from CERTIFICATE_REWARD
# (which is reputation, credited to the subject): this reward is tokens, credited
# to the reviewer. Neither buys influence — certification is decided by
# reputation weight, never token balance.
#
#     Known tradeoff (documented for defence): paying for review invites *fast,
#     shallow* reviews chasing the reward. This is deliberately bounded — the
#     reward is flat (not proportional to stake, so bigger bonds earn no more),
#     the bond is at risk if the review is dishonest, and reputation weight (not
#     stake or reward) is what actually certifies. A production system would add
#     review-quality signals; that is out of scope here.
REVIEW_REWARD = 5


def derive_registry(
    chain,
    upto_index: int | None = None,
    genesis: dict[str, dict[str, int]] | None = None,
) -> ReputationRegistry:
    """Compute the reputation registry implied by the chain's prefix.

    Replays the chain from a fresh (genesis-seeded) :class:`ReputationRegistry`,
    applying the reputation events committed in blocks ``0 .. upto_index - 1``.

    Args:
        chain: The blockchain to replay.
        upto_index: Exclusive upper bound on block index. ``None`` means the
            whole chain. Passing ``block.index`` yields the reputation state
            *before* that block, which is what authority checks must use.
        genesis: The trust anchor to seed from. ``None`` (the default) uses the
            canonical :data:`~reputation.genesis.GENESIS_REPUTATION`, preserving
            behaviour for every ordinary caller. Injection exists so tests and
            demos can supply their *own* founding participant set without
            polluting the canonical anchor. **The anchor is part of the network's
            shared configuration**: honest nodes must all derive from the same one
            (see :mod:`blockchain.blockchain`).

    Returns:
        A registry whose weights reflect genesis plus every applied event. The
        returned registry is a fresh object; mutating it does not touch genesis.
    """
    registry = ReputationRegistry() if genesis is None else ReputationRegistry(genesis)
    limit = len(chain.blocks) if upto_index is None else upto_index

    for block in chain.blocks:
        if block.index >= limit:
            break
        # As we replay in index order, ``registry`` already reflects blocks
        # 0..block.index-1 — i.e. it *is* the prefix registry for this block. So a
        # slash in this block is judged against the reputation and validator set as
        # they stood *before* it (the prefix rule): its evidence must be in earlier
        # blocks, and its approvers must be validators derived from that prefix.
        prefix_chain = SimpleNamespace(blocks=chain.blocks[: block.index])
        validators = _consensus_validators(registry)
        for tx in block.transactions:
            _apply_transaction(registry, tx, prefix_chain, validators)

    return registry


def _consensus_validators(registry: ReputationRegistry) -> set[str]:
    """The validator set implied by ``registry``: its consensus-domain authorities.

    This is the same set consensus keys block production and finality on (the
    genesis consensus authorities; promotions are a separate concern not exercised
    by slashing). A slash's quorum is measured against exactly this set.
    """
    from blockchain.blockchain import AUTHORITY_THRESHOLD  # lazy: avoids a cycle

    return registry.authorities_in_domain(CONSENSUS_DOMAIN, AUTHORITY_THRESHOLD)


def _apply_transaction(registry: ReputationRegistry, tx, prefix_chain, validators) -> None:
    """Apply one transaction's reputation effect (if any) to ``registry``.

    Only certain payload types move reputation; everything else (raw
    attestations, ordinary transactions) is inert here. This is the one place
    ``credit``/``debit`` are invoked, keeping reputation strictly derived.
    """
    payload = tx.payload
    if not isinstance(payload, dict):
        return

    if payload.get("type") == "certificate":
        # A certificate credits its subject in the domain it was decided in.
        registry.credit(payload["subject"], payload["domain"], CERTIFICATE_REWARD)
    elif payload.get("type") == SLASH_TYPE:
        # A slash debits the offender ONLY if it is a valid evidence-based,
        # quorum-approved slash for this prefix. The debit is capped at MAX_SLASH
        # and ReputationRegistry floors the result at 0, so an over-slash can
        # neither exceed the cap nor drive weight negative. An unproven slash is
        # simply inert (and is rejected outright by is_valid_chain).
        if validate_slash(payload, prefix_chain, validators):
            debit = min(payload["amount"], MAX_SLASH)
            registry.debit(payload["offender"], payload["domain"], debit)


def derive_balances(
    chain,
    upto_index: int | None = None,
    endowments: dict[str, int] | None = None,
    genesis: dict[str, dict[str, int]] | None = None,
) -> BalanceLedger:
    """Compute the token :class:`~reputation.balances.BalanceLedger` implied by the chain.

    Balances are *derived state*, exactly like reputation: replay the chain from
    a fresh (endowment-seeded) ledger and apply each economic event in block
    order over blocks ``0 .. upto_index - 1``:

    - an **attestation** *locks* its ``stake`` from the reviewer's free balance
      (the bond posted to make the claim), recorded on-chain by the attestation
      itself — **except an abstain**, which bonds nothing (stake 0) and so locks
      and records nothing;
    - a **certificate** *releases* the locked stake of each credited reviewer's
      contributing attestation and pays them :data:`REVIEW_REWARD` (honest review
      that held up is returned its bond and earns a reward); and
    - a valid **slash** *burns* the locked stake of the offender's referenced
      evidence attestations (a dishonest bond is lost, not just reputation). The
      slash is re-validated from the prefix exactly as
      :func:`derive_registry` does, so only a genuine, quorum-approved slash burns
      anything.

    Args:
        chain: The blockchain to replay.
        upto_index: Exclusive upper bound on block index (the prefix rule); ``None``
            means the whole chain. Passing ``block.index`` yields balances *before*
            that block — what a consensus balance check must use.
        endowments: The initial-balance anchor to seed from (``pubkey -> tokens``).
            ``None`` uses the canonical :data:`~reputation.genesis.GENESIS_BALANCES`.
            Injection mirrors ``derive_registry``'s ``genesis`` so a demo/test can
            supply its own founding balances. **Shared network configuration**:
            honest nodes must all seed from the same anchor.
        genesis: The *reputation* anchor, used only to derive the validator set a
            slash's quorum is checked against (mirrors ``derive_registry``). ``None``
            uses the canonical reputation anchor.

    Returns:
        A fresh ledger reflecting the endowments plus every applied event.
    """
    ledger = BalanceLedger() if endowments is None else BalanceLedger(endowments)
    limit = len(chain.blocks) if upto_index is None else upto_index

    # tx_hash -> (reviewer, stake, subject, rubric_root, domain, verdict) for every
    # attestation whose bond is still locked. A certificate releases the matching
    # positive ones; a slash burns the referenced ones; anything left stays locked.
    locked: dict[str, tuple] = {}

    for block in chain.blocks:
        if block.index >= limit:
            break
        # Derived lazily and only if a slash actually appears in this block, so the
        # common (slash-free) block stays cheap. The prefix is blocks 0..index-1.
        prefix_chain = None
        validators: set[str] | None = None

        for tx in block.transactions:
            payload = tx.payload
            if not isinstance(payload, dict):
                continue

            if is_attestation(tx):
                # An abstain bonds nothing (stake is 0 by construction), so it
                # locks no balance and is never recorded as a resolvable bond —
                # nothing to release on a certificate, nothing to burn on a slash.
                if is_abstain(tx):
                    continue
                # Posting the bond: the stake leaves free balance and is recorded
                # so a later certificate or slash can resolve it.
                ledger.lock(tx.sender, payload["stake"])
                locked[tx.hash] = (
                    tx.sender,
                    payload["stake"],
                    payload["subject"],
                    payload["rubric_root"],
                    payload["domain"],
                    payload["verdict"],
                )
            elif payload.get("type") == _CERTIFICATE_TYPE:
                _release_for_certificate(ledger, locked, payload)
            elif payload.get("type") == SLASH_TYPE:
                if validators is None:
                    prefix_chain = SimpleNamespace(blocks=chain.blocks[: block.index])
                    prefix_registry = derive_registry(
                        chain, upto_index=block.index, genesis=genesis
                    )
                    validators = _consensus_validators(prefix_registry)
                if validate_slash(payload, prefix_chain, validators):
                    _burn_for_slash(ledger, locked, payload)

    return ledger


def _release_for_certificate(ledger: BalanceLedger, locked: dict, payload: dict) -> None:
    """Release bonds and pay rewards for the attesters a certificate credited.

    For each reviewer in the certificate's ``granted_by`` that still has a locked
    *positive* attestation matching the certificate's ``(subject, rubric_root,
    domain)``, return every such bond to free balance and pay them one
    :data:`REVIEW_REWARD`. The reward is tied to an actual live bond, so an
    attester named in ``granted_by`` without a matching locked attestation earns
    nothing here.
    """
    subject = payload.get("subject")
    rubric_root = payload.get("rubric_root")
    domain = payload.get("domain")
    granted_by = payload.get("granted_by")
    if not isinstance(granted_by, list):
        return

    for attester in granted_by:
        contributing = [
            tx_hash
            for tx_hash, (rev, _stake, subj, rub, dom, verdict) in locked.items()
            if rev == attester
            and verdict is True
            and subj == subject
            and rub == rubric_root
            and dom == domain
        ]
        if not contributing:
            continue
        ledger.reward(attester, REVIEW_REWARD)
        for tx_hash in contributing:
            reviewer, stake, *_rest = locked.pop(tx_hash)
            ledger.release(reviewer, stake)


def _burn_for_slash(ledger: BalanceLedger, locked: dict, payload: dict) -> None:
    """Burn the locked bonds of the offender's referenced evidence attestations.

    A valid slash proves the offender equivocated on the two attestations it
    references; each such bond that is still locked (and genuinely the offender's)
    is destroyed — the dishonest bond is a real, permanent cost on top of the
    reputation debit.
    """
    offender = payload["offender"]
    for tx_hash in payload.get("evidence", []):
        entry = locked.get(tx_hash)
        if entry is not None and entry[0] == offender:
            reviewer, stake, *_rest = locked.pop(tx_hash)
            ledger.burn(reviewer, stake)
