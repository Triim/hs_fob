"""Slashing — evidence-based, quorum-approved removal of reputation.

Where a certificate credits reputation, a **slash** debits it. A slash is a plain
transaction with a structured payload, so — like attestations and certificates —
it rides the chain with no core changes and its effect is applied during
derivation (see :func:`reputation.derive.derive_registry`), keeping reputation
strictly derived from the chain.

From governance slashing to evidence + quorum
---------------------------------------------
Earlier this module modelled *governance* slashing: a single authority signed a
slash carrying an unchecked free-text ``reason``, and nothing verified that the
justification was sound or that the issuer had the right to slash. That is a
trust hole — one authority could debit anyone for any stated reason.

This module now implements **evidence-based, quorum-approved** slashing. A slash
is valid only when all of the following hold, and consensus re-checks every one
of them deterministically from the chain prefix (see
:meth:`blockchain.blockchain.Blockchain.is_valid_chain` and
:func:`validate_slash`):

  (a) **Evidence** — the slash references *two* signed transactions by the
      offender that genuinely conflict: two contradictory attestation verdicts
      (opposite ``verdict``) on the *same* claim — same ``(subject, rubric_root,
      domain, item_index)``. Equivocation is the objectively provable fault.
  (b) **Deterministic re-verification** — both referenced transactions must
      actually exist in the chain **prefix** before the slash, must both be
      signed by the offender (``sender`` == offender and the signature verifies),
      and must genuinely conflict as above. None of this is taken on faith.
  (c) **Quorum approval** — at least a BFT quorum
      (:func:`blockchain.blockchain.quorum_size`) of the *current* validators
      (the consensus-domain authorities derived from the prefix) have signed the
      slash statement with their validator keys. A single authority can no longer
      slash alone.

Only when (a)–(c) all hold does :func:`reputation.derive.derive_registry` debit
the offender, and the debit is **capped at** :data:`MAX_SLASH` and floored at 0
by the registry. So a slash can neither be fabricated nor exceed a bounded
penalty.

Like a promotion (:mod:`blockchain.promotion`), a slash is therefore a
*protocol-validated* transaction, **not** a participant-signed one: its integrity
comes from the approver signatures and the on-chain evidence it references, not
from a single author signature. It is exempt from the per-transaction
author-signature rule (see :mod:`blockchain.tx_signing`).
"""

from __future__ import annotations

import json

from attestation.attestation import is_attestation
from blockchain.transaction import Transaction
from crypto.keys import public_hex
from crypto.keys import sign as _sign
from crypto.keys import verify as _verify

# Discriminator for the slash payload, mirroring ATTESTATION_TYPE / CERTIFICATE_TYPE.
SLASH_TYPE = "slash"

# Default penalty when a caller does not specify one. A flat, documented amount
# keeps derivation auditable; callers may pass a larger amount for graver faults,
# but no slash ever debits more than MAX_SLASH.
DEFAULT_SLASH_PENALTY = 50

# **Penalty cap.** No single slash may debit more than this, regardless of the
# ``amount`` its approvers signed: the debit applied during derivation is
# ``min(amount, MAX_SLASH)`` (and the registry then floors the result at 0). A
# bounded penalty keeps one slash — even a quorum-approved one — from wiping out
# an offender's entire standing in a domain, and is shared network configuration
# every honest node agrees on, exactly like the certificate threshold.
MAX_SLASH = 100


def slash_signing_bytes(offender: str, domain: str, amount: int, evidence: list[str]) -> bytes:
    """Canonical bytes a validator signs to approve a slash.

    A sorted-key, whitespace-free JSON encoding of the ``(offender, domain,
    amount, evidence)`` statement, so an approver and every verifier produce
    byte-for-byte identical input regardless of machine. ``evidence`` is sorted so
    the statement is independent of the order the two references are listed in.
    The signature commits to *who* is slashed, *in which domain*, *by how much*,
    and *on what evidence*, so an approval can never be replayed against a
    different offender, amount, or evidence set.
    """
    canonical = json.dumps(
        {
            "type": SLASH_TYPE,
            "offender": offender,
            "domain": domain,
            "amount": amount,
            "evidence": sorted(evidence),
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return canonical.encode("utf-8")


def approve_slash(
    validator_private_key, offender: str, domain: str, amount: int, evidence: list[str]
) -> tuple[str, str]:
    """One validator's endorsement of a slash: ``(approver_pubkey, signature)``.

    The validator signs the canonical slash statement with their consensus
    (validator) key. The returned pubkey is exactly what consensus checks against
    the prefix-derived validator set, so identity is the key, never an address.
    """
    return (
        public_hex(validator_private_key),
        _sign(validator_private_key, slash_signing_bytes(offender, domain, amount, evidence)),
    )


def make_slash(
    offender: str,
    domain: str,
    evidence: list[str],
    approvals: dict[str, str],
    amount: int = DEFAULT_SLASH_PENALTY,
    issuer: str | None = None,
) -> Transaction:
    """Build an evidence-based, quorum-approved slash as a :class:`Transaction`.

    Args:
        offender: Hex public key whose weight is to be reduced.
        domain: Competence domain the penalty applies in (slashing, like
            crediting, is domain-scoped). Must match the domain of the two
            conflicting attestations named in ``evidence``.
        evidence: The two transaction **hashes** of the offender's conflicting
            attestations. Consensus re-checks that both exist in the prefix, are
            the offender's, and genuinely contradict each other.
        approvals: Map ``approver_pubkey -> signature`` of endorsing validators,
            each produced by :func:`approve_slash`. Consensus requires a quorum of
            the current validators here.
        amount: Weight to debit; the applied debit is ``min(amount, MAX_SLASH)``
            and the registry floors the result at 0.
        issuer: Identity recorded as the transaction's ``sender``. Defaults to the
            offender for readable provenance (mirroring how a promotion's sender is
            the candidate); the slash's integrity is its evidence + approvals, not
            this field.
    """
    payload = {
        "type": SLASH_TYPE,
        "offender": offender,
        "domain": domain,
        "amount": amount,
        "evidence": sorted(evidence),
        "approvals": dict(approvals),
    }
    return Transaction(sender=offender if issuer is None else issuer, payload=payload)


def is_slash(tx_or_payload) -> bool:
    """Whether a transaction (or raw payload dict) is a *structurally* well-formed slash.

    Accepts either a :class:`~blockchain.transaction.Transaction` or a payload
    ``dict`` (like :func:`blockchain.promotion.is_promotion`), so both consensus
    (which holds payloads) and callers holding whole transactions can use one
    predicate. Checks the discriminator and field shapes only; the *substantive*
    checks — that the evidence is real and conflicting and that a quorum approved —
    live in :func:`validate_slash`.
    """
    payload = getattr(tx_or_payload, "payload", tx_or_payload)
    if not isinstance(payload, dict) or payload.get("type") != SLASH_TYPE:
        return False
    if not isinstance(payload.get("offender"), str) or not payload["offender"]:
        return False
    if not isinstance(payload.get("domain"), str) or not payload["domain"]:
        return False
    amount = payload.get("amount")
    if isinstance(amount, bool) or not isinstance(amount, int) or amount < 0:
        return False
    evidence = payload.get("evidence")
    if not isinstance(evidence, list) or len(evidence) != 2:
        return False
    if not all(isinstance(h, str) and h for h in evidence):
        return False
    if evidence[0] == evidence[1]:  # two *distinct* conflicting transactions
        return False
    return isinstance(payload.get("approvals"), dict)


def validate_slash(payload: dict, prefix_chain, validators: set[str]) -> bool:
    """Whether ``payload`` is a slash the protocol would actually apply.

    Re-derives the slash's justification deterministically from the chain
    **prefix** — the blocks committed before the one carrying it — exactly as
    :func:`reputation.derive.derive_registry` and
    :meth:`blockchain.blockchain.Blockchain.is_valid_chain` require. Returns
    ``True`` only if:

      (a) it is structurally well-formed (:func:`is_slash`);
      (b) both referenced transactions exist in ``prefix_chain``, are attestations
          **signed by the offender**, and genuinely conflict — opposite verdicts
          on the same ``(subject, rubric_root, domain, item_index)``, with that
          domain equal to the slash's domain; and
      (c) at least :func:`blockchain.blockchain.quorum_size` of the ``validators``
          have a valid approver signature over :func:`slash_signing_bytes`.

    ``prefix_chain`` is any object exposing ``blocks`` (the prefix view) and
    ``validators`` is the current validator set derived from that same prefix (the
    consensus-domain authorities). A fabricated slash (evidence missing, not the
    offender's, or non-conflicting) or one lacking quorum fails, so no authority
    can debit anyone by fiat.
    """
    if not is_slash(payload):
        return False
    offender = payload["offender"]
    domain = payload["domain"]
    amount = payload["amount"]
    evidence = payload["evidence"]

    # (b) Evidence: the two referenced transactions must be on-chain (in the
    # prefix), the offender's, and genuinely conflicting. Re-verified here, never
    # trusted from the slash's own assertion.
    tx_a = _find_tx(prefix_chain, evidence[0])
    tx_b = _find_tx(prefix_chain, evidence[1])
    if tx_a is None or tx_b is None:
        return False
    if not _conflicting_attestations(tx_a, tx_b, offender, domain):
        return False

    # (c) Quorum approval by *current* validators, with genuine signatures. An
    # empty validator set is never a quorum, so such a slash is never valid.
    from blockchain.blockchain import quorum_size  # lazy: avoids an import cycle

    if not validators:
        return False
    message = slash_signing_bytes(offender, domain, amount, evidence)
    approvers = {
        approver
        for approver, signature in payload["approvals"].items()
        if approver in validators
        and isinstance(signature, str)
        and _verify(approver, message, signature)
    }
    return len(approvers) >= quorum_size(len(validators))


def _find_tx(prefix_chain, tx_hash: str):
    """The transaction in ``prefix_chain`` whose hash is ``tx_hash`` (or ``None``)."""
    for block in prefix_chain.blocks:
        for tx in block.transactions:
            if tx.hash == tx_hash:
                return tx
    return None


def _conflicting_attestations(tx_a, tx_b, offender: str, domain: str) -> bool:
    """Whether ``tx_a`` and ``tx_b`` are the offender's two contradictory verdicts.

    Both must be well-formed attestations authored (and validly signed) by the
    offender, in the slash's ``domain``, and must disagree on the *same* claim:
    identical ``(subject, rubric_root, item_index)`` but opposite ``verdict``.
    Signing two opposite verdicts for one claim is the objectively provable fault
    a slash punishes.
    """
    if not (is_attestation(tx_a) and is_attestation(tx_b)):
        return False
    # Authored by the offender, and the signatures genuinely verify against them.
    if tx_a.sender != offender or tx_b.sender != offender:
        return False
    if not (tx_a.verify_signature() and tx_b.verify_signature()):
        return False
    a, b = tx_a.payload, tx_b.payload
    if a["domain"] != domain or b["domain"] != domain:
        return False
    # An abstain (``verdict is None``) is honest, not an offence: it can never be
    # half of a conflict. Require BOTH verdicts to be real bools so that only two
    # opposite True/False claims — genuine equivocation — count. Without this,
    # None != True would wrongly read an abstain as contradicting a verdict.
    if not (isinstance(a["verdict"], bool) and isinstance(b["verdict"], bool)):
        return False
    same_claim = (
        a["subject"] == b["subject"]
        and a["rubric_root"] == b["rubric_root"]
        and a["item_index"] == b["item_index"]
    )
    return same_claim and a["verdict"] != b["verdict"]
