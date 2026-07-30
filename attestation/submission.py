"""Submissions as transactions.

A **submission** is a specialist's signed declaration that they have submitted a
piece of work for review — "here is my artifact for rubric X in domain Y". Like
an attestation, it is not a new on-chain object: it is an ordinary
:class:`~blockchain.transaction.Transaction` whose generic ``payload`` holds the
submission fields, so it inherits the core's canonical serialization and stable
content-addressed hash for free and needs no changes to the blockchain core.

**The artifact file itself is never stored on-chain.** Only its SHA-256 hash
(``artifact_hash``) and lightweight metadata go in the payload; the bytes live
wherever the application keeps them. The chain thus commits to *which* file was
submitted (any later copy can be re-hashed and compared) without bloating blocks
or leaking file contents. :func:`hash_artifact` is the one canonical way to
compute that hash, so the UI layer and the chain agree byte-for-byte.

Payload schema (all under ``Transaction.payload``)::

    {
        "type": "submission",         # discriminator for this payload kind
        "subject": <hex pubkey str>,  # who the work is by / being reviewed
        "domain": <str>,              # competence domain the work is in
        "rubric_root": <hex str>,     # Merkle root identifying the rubric
        "title": <str>,               # human-readable title of the work
        "artifact_hash": <hex str>,   # SHA-256 of the artifact bytes (never the bytes)
        "artifact_name": <str>,       # original filename; may be empty
    }

A submission is a **standalone declaration**: it grants no reputation and is
independent of attestations. Attestations still key on
``(subject, rubric_root, domain)`` exactly as they do today, and are *not* linked
to a specific submission. Binding an attestation to the precise submission it
reviewed (by ``artifact_hash``) is a possible future refinement, deliberately
deferred so this step stays isolated.
"""

from __future__ import annotations

import hashlib

from blockchain.transaction import Transaction

# Discriminator stored in the payload so a mixed mempool can tell submission
# transactions apart from attestations and any other payload type.
SUBMISSION_TYPE = "submission"

# The exact payload keys a submission must carry. Kept as a module constant so
# the factory and the validator agree on the schema by construction.
_REQUIRED_KEYS = {
    "type",
    "subject",
    "domain",
    "rubric_root",
    "title",
    "artifact_hash",
    "artifact_name",
}


def make_submission(
    subject: str,
    domain: str,
    rubric_root: str,
    title: str,
    artifact_hash: str,
    artifact_name: str = "",
) -> Transaction:
    """Build a submission as a :class:`Transaction`.

    The transaction is returned **unsigned**; the caller signs it exactly as an
    attestation is signed (the sender is the ``subject`` submitting the work).

    Args:
        subject: Hex public key of the specialist submitting; becomes the
            transaction's ``sender`` as well as the payload ``subject``.
        domain: Competence domain the work belongs to (e.g. ``"bioinformatics"``).
        rubric_root: Hex Merkle root identifying the rubric the work targets.
        title: Human-readable title of the submitted work.
        artifact_hash: Hex SHA-256 of the artifact bytes, as produced by
            :func:`hash_artifact`. The bytes themselves are never stored.
        artifact_name: Original filename of the artifact. Optional metadata, so
            it defaults to and may be the empty string.

    Returns:
        A plain ``Transaction`` whose ``payload`` follows the submission schema.
        It is returned unmined and unpooled; the caller decides when to sign and
        submit it to a chain.
    """
    payload = {
        "type": SUBMISSION_TYPE,
        "subject": subject,
        "domain": domain,
        "rubric_root": rubric_root,
        "title": title,
        "artifact_hash": artifact_hash,
        "artifact_name": artifact_name,
    }
    return Transaction(sender=subject, payload=payload)


def is_submission(tx: Transaction) -> bool:
    """Return ``True`` iff ``tx`` carries a well-formed submission payload.

    This is a defensive check on untrusted input (transactions may arrive from
    the network), so it verifies the discriminator and the presence and Python
    type of every field. Every field is a string; the required ones must be
    non-empty (an empty ``subject``/``domain``/``rubric_root``/``title``/
    ``artifact_hash`` carries no meaning), while ``artifact_name`` is optional
    metadata and may be empty.
    """
    payload = tx.payload
    if not isinstance(payload, dict):
        return False
    if set(payload) != _REQUIRED_KEYS:
        return False
    if payload["type"] != SUBMISSION_TYPE:
        return False
    # Required fields must be present, string, and meaningful (non-empty).
    for key in ("subject", "domain", "rubric_root", "title", "artifact_hash"):
        if not isinstance(payload[key], str) or not payload[key]:
            return False
    # artifact_name is optional metadata: it must be a string but may be empty.
    if not isinstance(payload["artifact_name"], str):
        return False
    return True


def hash_artifact(data: bytes) -> str:
    """Return the hex SHA-256 of ``data`` — the canonical ``artifact_hash``.

    This is the single source of truth for how artifact bytes are hashed, so the
    UI that computes a submission's ``artifact_hash`` and any later verifier
    produce the same digest. Only this hash is ever stored on-chain; the bytes
    are not.
    """
    return hashlib.sha256(data).hexdigest()
