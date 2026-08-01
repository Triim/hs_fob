"""The balance ledger — the live per-participant token table.

A :class:`BalanceLedger` answers three questions about a participant's tokens:

* **total** — everything they own: their genesis endowment plus review rewards
  earned, minus any stake that has been *burned* (permanently lost to a slash);
* **locked** — how much of that is currently posted as attestation bonds and so
  cannot be spent or re-bonded; and
* **free** — ``total − locked``, the balance actually available to bond a new
  attestation.

This mirrors :class:`~reputation.registry.ReputationRegistry`: it is a plain
mutable table whose ``lock`` / ``release`` / ``reward`` / ``burn`` hooks are
called **only** during derivation from the chain (see
:func:`reputation.derive.derive_balances`), never mutated ad hoc from elsewhere.
Balances are therefore *derived state* — a pure function of the chain — exactly
like reputation, so every node computes the same table without extra consensus.

Why tokens as well as reputation? Reputation is *earned competence* and decides
certification. A token stake is a *bond for honesty*: a reviewer risks it when
they attest, gets it back (plus a reward) when their review holds up, and loses
it if they are slashed. Stake never buys influence — it is skin in the game, not
a vote. Keeping the two tables separate is the whole point.
"""

from __future__ import annotations

import copy

from reputation.genesis import DEFAULT_ENDOWMENT, GENESIS_BALANCES


class BalanceLedger:
    """Mutable token table: total balance + locked bonds, seeded from endowments."""

    def __init__(
        self,
        endowments: dict[str, int] = GENESIS_BALANCES,
        default: int = DEFAULT_ENDOWMENT,
    ) -> None:
        """Seed the ledger from ``endowments`` with a ``default`` baseline.

        ``endowments`` is **deep-copied**, so the shared module constant can never
        be mutated by the hooks below — a ledger instance owns its own state.
        ``default`` is the balance any participant *not* named in ``endowments``
        starts with (the faucet baseline; see
        :data:`~reputation.genesis.DEFAULT_ENDOWMENT`), so an unknown but valid
        keypair still has tokens to bond with.
        """
        self._total: dict[str, int] = copy.deepcopy(dict(endowments))
        self._locked: dict[str, int] = {}
        self._default = default

    def total(self, pubkey: str) -> int:
        """Everything ``pubkey`` owns (free + locked); the baseline if unknown."""
        return self._total.get(pubkey, self._default)

    def locked(self, pubkey: str) -> int:
        """How much of ``pubkey``'s balance is currently posted as bonds (0 if none)."""
        return self._locked.get(pubkey, 0)

    def free(self, pubkey: str) -> int:
        """Balance available to bond a new attestation: ``total − locked``.

        Can read negative on an *invalid* chain (one that locked more than it
        held); consensus (:meth:`blockchain.blockchain.Blockchain.is_valid_chain`)
        rejects exactly that, so on a valid chain free is always ``>= 0``.
        """
        return self.total(pubkey) - self.locked(pubkey)

    def reward(self, pubkey: str, amount: int) -> None:
        """Credit ``amount`` free tokens to ``pubkey`` (a review reward)."""
        self._total[pubkey] = self.total(pubkey) + amount

    def lock(self, pubkey: str, amount: int) -> None:
        """Post ``amount`` as a bond: it leaves free but stays part of total."""
        self._locked[pubkey] = self.locked(pubkey) + amount

    def release(self, pubkey: str, amount: int) -> None:
        """Return a bond of ``amount`` to free balance (clamped at 0 locked)."""
        self._locked[pubkey] = max(0, self.locked(pubkey) - amount)

    def burn(self, pubkey: str, amount: int) -> None:
        """Destroy a locked bond of ``amount`` permanently (a slash penalty).

        Both ``total`` and ``locked`` drop by ``amount``: the bond was already
        unavailable (locked), so **free is unchanged** — burning only makes the
        loss permanent, turning a returnable bond into a real cost. Both are
        floored at 0 so a burn can never drive a balance negative.
        """
        self._total[pubkey] = max(0, self.total(pubkey) - amount)
        self._locked[pubkey] = max(0, self.locked(pubkey) - amount)

    def snapshot(self) -> dict[str, dict[str, int]]:
        """Read-only ``pubkey -> {total, locked, free}`` for every touched account.

        Only participants the ledger has an entry for (endowed, rewarded, burned,
        or holding a lock) are listed; everyone else implicitly holds the baseline
        ``free`` balance. A fresh dict, so callers (e.g. the HTTP view) can render
        it without being able to mutate the ledger.
        """
        keys = set(self._total) | set(self._locked)
        return {
            pk: {
                "total": self.total(pk),
                "locked": self.locked(pk),
                "free": self.free(pk),
            }
            for pk in keys
        }
