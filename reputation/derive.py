"""Derived reputation — the registry as a pure function of the chain.

Reputation is **not** an independently mutated object. It is *derived state*:
the current weight table is what you get by replaying the chain from genesis.
Start from :data:`~reputation.genesis.GENESIS_REPUTATION`, then apply each
chain event in order:

- a **certificate** issuance credits its subject in the certificate's domain by
  :data:`CERTIFICATE_REWARD` (honest work earns standing);
- a **slash** event debits the offender in its domain by the slash's amount,
  clamped at 0 (proven misconduct loses standing).

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

from reputation.registry import ReputationRegistry
from reputation.slashing import SLASH_TYPE, is_slash

# Fixed weight a subject earns in a certificate's domain when a certificate for
# them is committed. A flat reward keeps derivation simple and auditable; a
# stake- or issuer-weighted reward is a possible future refinement.
CERTIFICATE_REWARD = 10


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
        for tx in block.transactions:
            _apply_transaction(registry, tx)

    return registry


def _apply_transaction(registry: ReputationRegistry, tx) -> None:
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
    elif payload.get("type") == SLASH_TYPE and is_slash(tx):
        # A well-formed slash debits the offender in its domain; ReputationRegistry
        # clamps the result at 0, so an over-slash cannot drive weight negative.
        registry.debit(payload["offender"], payload["domain"], payload["amount"])
