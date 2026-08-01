"""Attestations as transactions.

An **attestation** is one attester's signed-off claim about whether a
``subject`` meets a single rubric item — e.g. "this student demonstrated
competence on item 3 of rubric X". Rather than invent a new on-chain object, an
attestation is modelled as a :class:`~blockchain.transaction.Transaction` whose
generic ``payload`` holds the attestation fields. It therefore inherits the
core's canonical serialization and stable content-addressed hash for free, and
the blockchain core needs no changes to carry it.

Payload schema (all under ``Transaction.payload``)::

    {
        "type": "attestation",       # discriminator for this payload kind
        "subject": <hex pubkey str>, # who the attestation is about
        "rubric_root": <hex str>,    # Merkle root identifying the rubric
        "domain": <str>,             # competence domain the claim is scoped to
        "submission_tx_hash": <hex str>, # the exact submission this review covers
        "item_index": <int>,         # which rubric item this verdict covers
        "verdict": <bool | None>,    # pass/fail, or None to *abstain*
        "stake": <int>,              # real token bond locked to make this claim
    }

``submission_tx_hash`` binds the review to **one specific submission** — the hash
of the :func:`~attestation.submission.make_submission` transaction the attester
actually reviewed. Two submissions of the same ``subject`` against the same
``rubric_root`` in the same ``domain`` are distinct pieces of work, so votes are
pooled per ``(subject, rubric_root, domain, submission_tx_hash)`` (see
:mod:`reputation.tally`): an attestation for one submission never counts toward a
certificate for a *different* submission, and the certificate carries the hash it
was decided on. It is a required, non-empty hex field so "which submission was
reviewed" is always provable, never implicit.

An **abstain** (``verdict is None``) is a first-class third state, distinct from
both ``True`` and ``False``: a reviewer who lacks competence in the submission's
domain says so explicitly rather than guessing. An abstain counts toward neither
support nor opposition (only ``verdict is True`` adds weight — see
:mod:`reputation.tally`), locks **no** stake, and can never be part of the
conflicting evidence a slash needs (abstaining is honest, not an offence — see
:func:`reputation.slashing._conflicting_attestations`). Because it risks nothing,
an abstain must carry ``stake == 0``; :func:`is_attestation` enforces that so
"stake-free" is a structural property, not merely applied at derivation.

The ``stake`` is a **real economic bond**, not a decorative number: consensus
locks it from the reviewer's free token balance when the attestation is committed
(and rejects the attestation outright if the reviewer cannot cover it). The bond
is returned — plus a :data:`~reputation.derive.REVIEW_REWARD` — when the review
contributes to an issued certificate, and **burned** if the reviewer is slashed
for it. All of this is chain-derived (see :mod:`reputation.balances` and
:func:`reputation.derive.derive_balances`); the field here simply records how much
was bonded. Stake buys no influence — certification is decided by reputation
weight, never bond size.

``domain`` scopes the claim to a competence area (e.g. ``"bioinformatics"``):
reputation is per-domain, so an attester's weight is only meaningful once we
know *which* domain the attestation is about. ``make_attestation`` gives it a
default and appends it as the last parameter, so the field is added without
disturbing the existing positional call sites elsewhere in the system.
"""

from __future__ import annotations

import string

from blockchain.transaction import Transaction

# Discriminator stored in the payload so a mixed mempool can tell attestation
# transactions apart from any other future payload type.
ATTESTATION_TYPE = "attestation"

# The exact payload keys an attestation must carry. Kept as a module constant so
# the factory and the validator agree on the schema by construction.
_REQUIRED_KEYS = {
    "type",
    "subject",
    "rubric_root",
    "domain",
    "submission_tx_hash",
    "item_index",
    "verdict",
    "stake",
}

# Default competence domain, used when a caller does not name one. Non-empty so
# the value always satisfies ``is_attestation``'s domain requirement.
DEFAULT_DOMAIN = "general"

# The sentinel verdict for an *abstain*: a reviewer declining to take a side on a
# claim they are not competent to judge. Kept as a named constant so callers and
# the validator agree on the third state by construction.
ABSTAIN = None


def make_attestation(
    attester: str,
    subject: str,
    rubric_root: str,
    item_index: int,
    verdict: bool | None,
    stake: int,
    submission_tx_hash: str,
    domain: str = DEFAULT_DOMAIN,
) -> Transaction:
    """Build an attestation as a :class:`Transaction`.

    Args:
        attester: Identity of the node making the claim; becomes the
            transaction's ``sender``. The *subject* (below) is who the claim is
            about, which is a distinct role, so the two are separate fields.
        subject: Hex public key of the entity being attested about.
        rubric_root: Hex Merkle root identifying the rubric the item belongs to.
        submission_tx_hash: Hex hash of the submission transaction this review
            covers — the exact piece of work the attester judged. Required and
            non-empty: an attestation always names the submission it reviewed, so
            votes for different submissions of the same subject/rubric/domain are
            never pooled together. Inserted before ``domain`` (which keeps its
            default) so the required binding is positionally explicit.
        item_index: Zero-based index of the rubric item this verdict covers.
        verdict: Whether the subject passed (``True``) or failed (``False``) the
            item, or :data:`ABSTAIN` (``None``) to decline judging it. An abstain
            risks nothing, so any ``stake`` passed with it is forced to 0.
        stake: Non-negative token amount the attester risks on this claim. Ignored
            (coerced to 0) for an abstain, which bonds nothing.
        domain: Competence domain the claim is scoped to. Appended last with a
            default so this new field does not disturb the existing positional
            call sites; reputation is looked up per-domain, so every attestation
            carries the domain it speaks to.

    Returns:
        A plain ``Transaction`` whose ``payload`` follows the attestation
        schema. It is returned unmined and unpooled; the caller decides when to
        submit it to a chain.
    """
    payload = {
        "type": ATTESTATION_TYPE,
        "subject": subject,
        "rubric_root": rubric_root,
        "domain": domain,
        "submission_tx_hash": submission_tx_hash,
        "item_index": item_index,
        "verdict": verdict,
        # An abstain bonds nothing; force its stake to 0 so it always satisfies the
        # stake-free rule ``is_attestation`` enforces.
        "stake": 0 if verdict is ABSTAIN else stake,
    }
    return Transaction(sender=attester, payload=payload)


def is_attestation(tx: Transaction) -> bool:
    """Return ``True`` iff ``tx`` carries a well-formed attestation payload.

    This is a defensive check on untrusted input (transactions may arrive from
    the network), so it verifies not just the discriminator but the presence and
    Python type of every field. ``bool`` is checked before ``int`` because
    ``bool`` is a subclass of ``int`` — otherwise a ``verdict`` of ``True`` would
    wrongly pass as an ``int`` field and vice versa.
    """
    payload = tx.payload
    if not isinstance(payload, dict):
        return False
    if set(payload) != _REQUIRED_KEYS:
        return False
    if payload["type"] != ATTESTATION_TYPE:
        return False
    if not isinstance(payload["subject"], str):
        return False
    if not isinstance(payload["rubric_root"], str):
        return False
    # Domain must be present and meaningful: an empty string names no domain, so
    # reputation could not be scoped, and we reject it.
    if not isinstance(payload["domain"], str) or not payload["domain"]:
        return False
    # submission_tx_hash binds the review to a specific submission. It must be a
    # non-empty *hex* string (it is a transaction hash), so the binding is always
    # provable and can never be an empty/placeholder value that would silently
    # merge votes across submissions.
    submission_tx_hash = payload["submission_tx_hash"]
    if not isinstance(submission_tx_hash, str) or not submission_tx_hash:
        return False
    if any(c not in string.hexdigits for c in submission_tx_hash):
        return False
    # Reject bools explicitly: bool is a subclass of int, so an accidental
    # True/False in a numeric field would otherwise slip through.
    if isinstance(payload["item_index"], bool) or not isinstance(
        payload["item_index"], int
    ):
        return False
    # A verdict is True/False, or None to *abstain*. None is the only non-bool
    # value accepted — anything else (a string, an int) is malformed.
    verdict = payload["verdict"]
    if verdict is not None and not isinstance(verdict, bool):
        return False
    # Stake is now a real bond locked from the reviewer's balance, so a negative
    # amount is meaningless (it would "lock" a credit) and is rejected. Bools are
    # excluded first since bool is a subclass of int.
    if isinstance(payload["stake"], bool) or not isinstance(payload["stake"], int):
        return False
    if payload["stake"] < 0:
        return False
    # An abstain risks nothing, so it must carry no bond. Enforcing stake == 0 here
    # makes "abstain is stake-free" a structural guarantee of the type, not just a
    # convention applied during balance derivation.
    if verdict is None and payload["stake"] != 0:
        return False
    return True


def is_abstain(tx_or_payload) -> bool:
    """Whether ``tx_or_payload`` is an attestation that *abstains* (``verdict is None``).

    Accepts either a :class:`Transaction` or a raw payload ``dict`` so both
    callers holding whole transactions and consensus code holding payloads can ask
    the question. Assumes the input is already a well-formed attestation
    (:func:`is_attestation`); it only distinguishes the abstain state from a
    True/False verdict.
    """
    payload = getattr(tx_or_payload, "payload", tx_or_payload)
    return isinstance(payload, dict) and payload.get("verdict") is None
