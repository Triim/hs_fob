"""Slashing — the chain event that *removes* reputation.

Where a certificate credits reputation, a **slash** debits it. A slash is a plain
transaction with a structured payload, so — like attestations and certificates —
it rides the chain with no core changes and is applied during derivation (see
:func:`reputation.derive.derive_registry`), keeping reputation strictly derived
from the chain.

Design constraint (documented for the defence, **not** enforced in the MVP):
slashing is meant to fire only for *objectively provable* violations (e.g. an
attester signing two contradictory verdicts for the same claim). A slash is
submitted by an authority and carries a ``reason`` and a ``reference`` to the
offending record, but this module does **not** verify that the justification is
sound, nor that the issuer is actually an authority — that adjudication is out of
scope. The registry simply applies a well-formed slash event.
"""

from __future__ import annotations

from blockchain.transaction import Transaction

# Discriminator for the slash payload, mirroring ATTESTATION_TYPE / CERTIFICATE_TYPE.
SLASH_TYPE = "slash"

# Default penalty when a caller does not specify one. A flat, documented amount
# keeps derivation auditable; callers may pass a larger amount for graver faults.
DEFAULT_SLASH_PENALTY = 50

# Identity recorded as a slash transaction's sender when none is given. A slash is
# a governance act by an authority, distinct from the offender it names.
DEFAULT_SLASHER = "authority"


def make_slash(
    offender: str,
    domain: str,
    reason: str,
    reference: str,
    amount: int = DEFAULT_SLASH_PENALTY,
    issuer: str = DEFAULT_SLASHER,
) -> Transaction:
    """Build a slash event as a :class:`Transaction`.

    Args:
        offender: Hex public key whose weight is to be reduced.
        domain: Competence domain the penalty applies in (slashing, like
            crediting, is domain-scoped).
        reason: Human-readable justification (informational; not adjudicated).
        reference: Identifier of the offending record — e.g. the hash of the
            contradictory attestation — so the slash is auditable.
        amount: Weight to debit (clamped at 0 during derivation).
        issuer: Identity recorded as the transaction's sender.
    """
    payload = {
        "type": SLASH_TYPE,
        "offender": offender,
        "domain": domain,
        "amount": amount,
        "reason": reason,
        "reference": reference,
    }
    return Transaction(sender=issuer, payload=payload)


def is_slash(tx: Transaction) -> bool:
    """Whether ``tx`` is a well-formed slash event."""
    payload = tx.payload
    if not isinstance(payload, dict) or payload.get("type") != SLASH_TYPE:
        return False
    if not isinstance(payload.get("offender"), str) or not payload["offender"]:
        return False
    if not isinstance(payload.get("domain"), str) or not payload["domain"]:
        return False
    return isinstance(payload.get("amount"), int) and payload["amount"] >= 0
