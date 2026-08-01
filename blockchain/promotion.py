"""The promotion transaction — endogenous growth of the validator set.

The three roles this system keeps **distinct** are the whole point of this module:

- **competence reputation** — a subject's per-domain skill weight, earned through
  attestations/certificates (see :mod:`reputation.derive`);
- **attester credibility** — how much an attester's *vote* counts in weighted
  support (see :mod:`reputation.tally`);
- **consensus authority** — the right to *produce and commit* blocks, i.e.
  membership in the validator set (see :mod:`blockchain.blockchain`).

Genesis grants consensus authority axiomatically (the founding validators). A
**promotion** is the *only* on-chain event that grants it to anyone else, and it
does so as a deliberate conversion — never automatically from competence. A
candidate is promoted only when a promotion transaction proves all of:

1. the candidate already holds competence weight ``>= PROMOTION_THRESHOLD`` in
   some domain (merit is *necessary*), **and**
2. a BFT **quorum of the current validators** have signed off on the candidate
   (peer approval is *also necessary* — competence alone never suffices), **and**
3. **rate/fraction limits** hold, so a fresh cohort cannot be minted fast enough
   to seize a BFT majority (see :mod:`blockchain.blockchain`).

A promotion carries the candidate, the domain their competence is claimed in, and
a map of **approver signatures**. Each approver signs the canonical
``(candidate, domain)`` statement with their validator key; consensus re-verifies
every signature against the validator set derived from the chain prefix, so a
promotion cannot be forged or pad its approvals with outsiders.
"""

from __future__ import annotations

import json

from blockchain.transaction import Transaction
from crypto.keys import public_hex
from crypto.keys import sign as _sign

# Payload discriminator for a promotion transaction. Kept as a literal (like the
# participant/certificate type strings) so the core consensus layer needs no
# upward import to recognise it.
PROMOTION_TYPE = "promotion"


def promotion_signing_bytes(candidate: str, domain: str) -> bytes:
    """Canonical bytes an approver signs to endorse promoting ``candidate``.

    A sorted-key, whitespace-free JSON encoding of the ``(candidate, domain)``
    statement, so an approver and every verifier produce byte-for-byte identical
    input regardless of machine. The signature commits to *who* is being promoted
    and *in which competence domain*, so an endorsement for one candidate can
    never be replayed for another.
    """
    canonical = json.dumps(
        {"type": PROMOTION_TYPE, "candidate": candidate, "domain": domain},
        sort_keys=True,
        separators=(",", ":"),
    )
    return canonical.encode("utf-8")


def approve_promotion(validator_private_key, candidate: str, domain: str) -> tuple[str, str]:
    """One validator's endorsement of a candidate: ``(approver_pubkey, signature)``.

    The validator signs the canonical promotion statement with their consensus
    (validator) key. The returned pubkey is exactly what consensus checks against
    the prefix-derived validator set, so identity is the key, never an address.
    """
    return (
        public_hex(validator_private_key),
        _sign(validator_private_key, promotion_signing_bytes(candidate, domain)),
    )


def make_promotion(candidate: str, domain: str, approvals: dict[str, str]) -> Transaction:
    """Build a promotion transaction proposing ``candidate`` as a new validator.

    Args:
        candidate: Hex public key to be granted consensus authority.
        domain: Competence domain the candidate's merit is claimed in; consensus
            checks the candidate's weight there against ``PROMOTION_THRESHOLD``.
        approvals: Map ``approver_pubkey -> signature`` of endorsing validators,
            each produced by :func:`approve_promotion`.

    A promotion is a **protocol-validated** transaction, not a participant one:
    its integrity comes from the approver signatures it carries (re-verified by
    consensus), so it is exempt from the per-transaction author-signature rule —
    exactly like a certificate. ``sender`` is set to the candidate purely for
    readable provenance.
    """
    return Transaction(
        sender=candidate,
        payload={
            "type": PROMOTION_TYPE,
            "candidate": candidate,
            "domain": domain,
            "approvals": dict(approvals),
        },
    )


def is_promotion(tx_or_payload) -> bool:
    """Whether a transaction (or raw payload dict) is a well-formed promotion.

    Accepts either a :class:`~blockchain.transaction.Transaction` or a payload
    ``dict`` so both consensus (which holds payloads) and callers holding whole
    transactions can use one predicate. Checks the discriminator and that the
    structural fields have the right shape; the *cryptographic* checks (competence,
    quorum, caps) live in consensus (:mod:`blockchain.blockchain`).
    """
    payload = getattr(tx_or_payload, "payload", tx_or_payload)
    if not isinstance(payload, dict) or payload.get("type") != PROMOTION_TYPE:
        return False
    return (
        isinstance(payload.get("candidate"), str)
        and isinstance(payload.get("domain"), str)
        and isinstance(payload.get("approvals"), dict)
    )
