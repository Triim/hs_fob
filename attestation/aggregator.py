"""Aggregation and threshold — turning attestations into a certificate.

Individual attestations are cheap opinions; a **certificate** is the protocol's
collective decision that a subject has met a rubric in a domain. This module
scans a :class:`~blockchain.blockchain.Blockchain`, gathers the attestations that
bear on one ``(subject, rubric_root, domain)`` triple, and — if their backers
carry enough *reputation weight* — mints a certificate transaction.

Design decisions, documented for the coursework:

- **Scope is ``(subject, rubric_root, domain)``.** A certificate names a single
  rubric in a single competence domain, so votes are only pooled among
  attestations matching all three; anything else is irrelevant to this decision.
- **Only positive verdicts count.** ``verdict=False`` is an explicit "did not
  meet it" and must not push the subject toward acceptance.
- **One attester, one vote.** Votes are deduplicated by attester identity
  (the transaction ``sender``), so the same attester spamming attestations
  cannot inflate support.
- **Weighted by reputation.** Acceptance is decided by the *sum of the
  attesters' domain-scoped weights* (via :func:`reputation.tally.weighted_support`),
  not a head count: ``threshold`` is now a weight sum. This closes the former
  equal-weight simplification.
"""

from __future__ import annotations

from blockchain.blockchain import Blockchain
from blockchain.transaction import Transaction
from reputation.registry import ReputationRegistry
from reputation.tally import positive_attesters

# Discriminator for the certificate payload, mirroring ATTESTATION_TYPE.
CERTIFICATE_TYPE = "certificate"

# Default issuer recorded as the certificate transaction's sender. A certificate
# is minted by the aggregating protocol rather than by any single attester, so it
# gets its own identity distinct from the attesters listed in ``granted_by``.
DEFAULT_ISSUER = "certifier"


def make_certificate(
    subject: str,
    rubric_root: str,
    domain: str,
    granted_by: list[str],
    issuer: str = DEFAULT_ISSUER,
) -> Transaction:
    """Build a certificate as a :class:`Transaction`.

    Like an attestation, a certificate is a plain transaction with a structured
    payload, so it rides the chain with no core changes. It records the
    ``domain`` it was decided in (a certificate is per
    ``(subject, rubric_root, domain)``). ``granted_by`` is stored sorted so the
    payload — and therefore the transaction hash — is deterministic regardless of
    the order attesters were discovered in.
    """
    payload = {
        "type": CERTIFICATE_TYPE,
        "subject": subject,
        "rubric_root": rubric_root,
        "domain": domain,
        "granted_by": sorted(granted_by),
    }
    return Transaction(sender=issuer, payload=payload)


def certify(
    chain: Blockchain,
    registry: ReputationRegistry,
    subject: str,
    rubric_root: str,
    domain: str,
    threshold: int,
    issuer: str = DEFAULT_ISSUER,
) -> Transaction | None:
    """Decide whether ``subject`` earns a certificate for ``(rubric_root, domain)``.

    Sums the domain-scoped reputation weight of the distinct attesters who
    positively attested the subject against the rubric in the domain. If that
    weighted support meets ``threshold`` (now a *weight sum*, not a head count),
    returns a certificate naming the attesters who carried weight; otherwise
    returns ``None``.

    The attester set is obtained from a single chain scan
    (:func:`reputation.tally.positive_attesters`), which is the same scan
    :func:`weighted_support` is built on; the weighted sum and the credited set
    are then both derived from it, so the chain is never scanned twice.

    Args:
        chain: The blockchain to scan (only mined blocks are considered).
        registry: Reputation registry supplying per-domain attester weights.
        subject: Hex public key of the entity being certified.
        rubric_root: Merkle root of the rubric the certificate attests to.
        domain: Competence domain the certificate is scoped to.
        threshold: Minimum weighted support (sum of attester weights) required.
        issuer: Identity recorded as the certificate's sender.
    """
    attesters = positive_attesters(chain, subject, rubric_root, domain)
    weights = {attester: registry.weight(attester, domain) for attester in attesters}
    if sum(weights.values()) < threshold:
        return None
    # Exclude zero-weight attesters from granted_by: the certificate credits only
    # those whose reputation actually carried it, so it is an honest audit trail.
    credited = [attester for attester, w in weights.items() if w > 0]
    return make_certificate(subject, rubric_root, domain, credited, issuer=issuer)
