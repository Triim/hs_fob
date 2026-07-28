"""Aggregation and threshold — turning attestations into a certificate.

Individual attestations are cheap opinions; a **certificate** is the protocol's
collective decision that a subject has met a rubric. This module scans a
:class:`~blockchain.blockchain.Blockchain`, gathers the attestations that bear on
one ``(subject, rubric_root)`` pair, and — if enough *distinct* attesters voted
in favour — mints a certificate transaction.

Design decisions, documented for the coursework:

- **Scope is ``(subject, rubric_root)``.** A certificate names a single rubric,
  so votes are only pooled among attestations against that same rubric; an
  attestation for a different rubric is irrelevant to this decision.
- **Only positive verdicts count.** ``verdict=False`` is an explicit "did not
  meet it" and must not push the subject toward acceptance.
- **One attester, one vote.** Votes are deduplicated by attester identity
  (the transaction ``sender``), so the same attester spamming attestations
  cannot inflate the count. This is what makes the threshold meaningful.
- **Equal weight, for now.** Every distinct attester counts exactly 1.
"""

from __future__ import annotations

from attestation.attestation import is_attestation
from blockchain.blockchain import Blockchain
from blockchain.transaction import Transaction

# Discriminator for the certificate payload, mirroring ATTESTATION_TYPE.
CERTIFICATE_TYPE = "certificate"

# Default issuer recorded as the certificate transaction's sender. A certificate
# is minted by the aggregating protocol rather than by any single attester, so it
# gets its own identity distinct from the attesters listed in ``granted_by``.
DEFAULT_ISSUER = "certifier"


def _positive_attesters(
    chain: Blockchain, subject: str, rubric_root: str
) -> set[str]:
    """Return the distinct attesters who positively attested ``subject``.

    Scans every mined block, keeping attestation transactions that match the
    requested ``subject`` and ``rubric_root`` with a ``True`` verdict, and
    returns the set of their attester identities (``sender``). Returning a set
    is what enforces one-attester-one-vote.

    # TODO(reputation): votes are currently equal-weight (each attester counts 1).
    # A later step will weight each attester by domain-scoped reputation/stake so
    # this returns a weighted tally rather than a plain set of identities.
    """
    attesters: set[str] = set()
    for block in chain.blocks:
        for tx in block.transactions:
            if not is_attestation(tx):
                continue
            payload = tx.payload
            if payload["subject"] != subject:
                continue
            if payload["rubric_root"] != rubric_root:
                continue
            if payload["verdict"] is not True:
                continue
            attesters.add(tx.sender)
    return attesters


def make_certificate(
    subject: str,
    rubric_root: str,
    granted_by: list[str],
    issuer: str = DEFAULT_ISSUER,
) -> Transaction:
    """Build a certificate as a :class:`Transaction`.

    Like an attestation, a certificate is a plain transaction with a structured
    payload, so it rides the chain with no core changes. ``granted_by`` is stored
    sorted so the payload — and therefore the transaction hash — is deterministic
    regardless of the order attesters were discovered in.
    """
    payload = {
        "type": CERTIFICATE_TYPE,
        "subject": subject,
        "rubric_root": rubric_root,
        "granted_by": sorted(granted_by),
    }
    return Transaction(sender=issuer, payload=payload)


def certify(
    chain: Blockchain,
    subject: str,
    rubric_root: str,
    threshold: int,
    issuer: str = DEFAULT_ISSUER,
) -> Transaction | None:
    """Decide whether ``subject`` earns a certificate for ``rubric_root``.

    Counts the distinct attesters who positively attested the subject against
    the rubric. If that count is at least ``threshold``, returns a certificate
    transaction naming exactly those attesters; otherwise returns ``None``.

    Args:
        chain: The blockchain to scan (only mined blocks are considered).
        subject: Hex public key of the entity being certified.
        rubric_root: Merkle root of the rubric the certificate attests to.
        threshold: Minimum number of distinct positive attesters required.
        issuer: Identity recorded as the certificate's sender.
    """
    attesters = _positive_attesters(chain, subject, rubric_root)
    if len(attesters) < threshold:
        return None
    return make_certificate(subject, rubric_root, list(attesters), issuer=issuer)
