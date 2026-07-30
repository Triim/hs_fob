"""The reputation registry — the live per-domain weight table.

A :class:`ReputationRegistry` starts from a genesis anchor (see
:mod:`reputation.genesis`) and thereafter answers "what is ``pubkey``'s weight
in ``domain``". Later steps mutate it through :meth:`credit` and :meth:`debit`
as the chain rewards honest attesters and slashes dishonest ones; this step only
provides those hooks.

There is one registry for the whole chain: ``domain`` is a key, not a separate
registry. Weight is looked up per ``(pubkey, domain)`` pair and defaults to 0
for anyone the anchor never mentioned.
"""

from __future__ import annotations

import copy

from reputation.genesis import GENESIS_REPUTATION


class ReputationRegistry:
    """Mutable per-domain weight table seeded from a genesis mapping."""

    def __init__(
        self, genesis: dict[str, dict[str, int]] = GENESIS_REPUTATION
    ) -> None:
        """Seed the registry from ``genesis``.

        The genesis mapping is **deep-copied**, so the shared module constant can
        never be mutated by :meth:`credit`/:meth:`debit` — a registry instance
        owns its own state entirely.
        """
        self._weights: dict[str, dict[str, int]] = copy.deepcopy(genesis)

    def weight(self, pubkey: str, domain: str) -> int:
        """Current weight of ``pubkey`` in ``domain`` (0 if unknown)."""
        return self._weights.get(pubkey, {}).get(domain, 0)

    def credit(self, pubkey: str, domain: str, amount: int) -> None:
        """Add ``amount`` to ``pubkey``'s weight in ``domain``.

        Creates the participant/domain entry if it does not yet exist, so weight
        can be granted to someone the genesis anchor never mentioned.
        """
        current = self._weights.setdefault(pubkey, {}).get(domain, 0)
        self._weights[pubkey][domain] = current + amount

    def debit(self, pubkey: str, domain: str, amount: int) -> None:
        """Subtract ``amount`` from ``pubkey``'s weight in ``domain``.

        Weight is **clamped at 0**: reputation is a non-negative quantity, and a
        negative weight has no meaning for authority or tallying, so an
        over-large debit (e.g. slashing more than a participant holds) simply
        floors the weight at zero rather than going negative.
        """
        current = self._weights.setdefault(pubkey, {}).get(domain, 0)
        self._weights[pubkey][domain] = max(0, current - amount)

    def is_authority(self, pubkey: str, threshold: int) -> bool:
        """Whether ``pubkey`` has weight ``>= threshold`` in *any* domain.

        Authority to *produce blocks* is infrastructural, not domain-specific: a
        producer merely records other participants' transactions, it does not
        pass judgement within a competence domain. So having enough standing in
        any single domain is sufficient to be a block producer — this is
        deliberately distinct from the per-domain weight that governs how much an
        attester's *vote* counts (see :mod:`reputation.tally`).
        """
        return any(w >= threshold for w in self._weights.get(pubkey, {}).values())

    def total_weight(self, pubkey: str) -> int:
        """Sum of ``pubkey``'s weight across all domains (0 if unknown)."""
        return sum(self._weights.get(pubkey, {}).values())

    def snapshot(self) -> dict[str, dict[str, int]]:
        """Read-only ``pubkey -> domain -> weight`` copy of the whole table.

        A deep copy, so callers (e.g. a monitoring/HTTP layer that renders the
        current reputation) can enumerate every participant without being able to
        mutate the registry's internal state.
        """
        return copy.deepcopy(self._weights)
