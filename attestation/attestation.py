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
        "item_index": <int>,         # which rubric item this verdict covers
        "verdict": <bool>,           # pass/fail for that item
        "stake": <int>,              # tokens the attester puts at risk
    }
"""

from __future__ import annotations

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
    "item_index",
    "verdict",
    "stake",
}


def make_attestation(
    attester: str,
    subject: str,
    rubric_root: str,
    item_index: int,
    verdict: bool,
    stake: int,
) -> Transaction:
    """Build an attestation as a :class:`Transaction`.

    Args:
        attester: Identity of the node making the claim; becomes the
            transaction's ``sender``. The *subject* (below) is who the claim is
            about, which is a distinct role, so the two are separate fields.
        subject: Hex public key of the entity being attested about.
        rubric_root: Hex Merkle root identifying the rubric the item belongs to.
        item_index: Zero-based index of the rubric item this verdict covers.
        verdict: Whether the subject passed (``True``) or failed the item.
        stake: Non-negative token amount the attester risks on this claim.

    Returns:
        A plain ``Transaction`` whose ``payload`` follows the attestation
        schema. It is returned unmined and unpooled; the caller decides when to
        submit it to a chain.
    """
    payload = {
        "type": ATTESTATION_TYPE,
        "subject": subject,
        "rubric_root": rubric_root,
        "item_index": item_index,
        "verdict": verdict,
        "stake": stake,
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
    # Reject bools explicitly: bool is a subclass of int, so an accidental
    # True/False in a numeric field would otherwise slip through.
    if isinstance(payload["item_index"], bool) or not isinstance(
        payload["item_index"], int
    ):
        return False
    if not isinstance(payload["verdict"], bool):
        return False
    if isinstance(payload["stake"], bool) or not isinstance(payload["stake"], int):
        return False
    return True
