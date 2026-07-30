"""Which transactions must carry an author signature — a consensus policy.

Transactions on this chain fall into two classes, and the class decides whether a
per-transaction author signature is *required* for the chain to be valid:

**Participant-submitted** — ``attestation``, ``submission``, ``slash``. A human
(or their node) authored these, so each MUST be signed by its author: the
transaction's ``sender`` is the author's hex public key, and
``verify_signature()`` must pass against it. An unsigned or wrongly-signed
participant transaction makes the whole chain invalid.

**Protocol-generated** — ``certificate`` (minted by :func:`attestation.aggregator.certify`),
anything in the **genesis block**, and any other/unknown payload. These are not
authored by an individual signer; their integrity comes from the block
producer's signature (checked by Proof-of-Authority) and from being
deterministically re-derivable from chain state. They are **exempt** from the
per-transaction signature requirement.

:func:`requires_signature` makes this rule explicit and independently testable,
so :func:`blockchain.blockchain.Blockchain.is_valid_chain` does not hard-code
type checks. The type strings below intentionally mirror the discriminators
defined in the application layer (``ATTESTATION_TYPE`` / ``SUBMISSION_TYPE`` /
``SLASH_TYPE``); they are kept as literals here so this core consensus policy has
no upward dependency on — and no import cycle with — the attestation package.
"""

from __future__ import annotations

# Payload ``type`` values authored by a participant, who must sign the
# transaction. Mirrors ATTESTATION_TYPE, SUBMISSION_TYPE, SLASH_TYPE.
PARTICIPANT_SIGNED_TYPES = frozenset({"attestation", "submission", "slash"})


def requires_signature(tx) -> bool:
    """Whether ``tx`` must carry a valid author signature to be chain-valid.

    ``True`` for participant-submitted transactions (attestation / submission /
    slash); ``False`` for protocol-generated ones (certificate) and anything
    else, which are exempt. Reads only the payload ``type`` discriminator, so it
    is total and never raises on odd input.
    """
    payload = tx.payload
    if not isinstance(payload, dict):
        return False
    return payload.get("type") in PARTICIPANT_SIGNED_TYPES
