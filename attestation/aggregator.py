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

import hashlib
import json

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

# The **protocol-wide** weighted-support threshold a certificate must clear to be
# valid. Unlike the ``threshold`` argument to :func:`certify` (a caller knob for
# deciding *when* to issue / for what-if analysis), this is the floor that
# consensus itself enforces: :meth:`blockchain.blockchain.Blockchain.is_valid_chain`
# re-derives every on-chain certificate from the prefix and rejects the block
# unless the real weighted support of its genuine positive attesters meets this
# value. It is therefore shared network configuration — every honest node must
# agree on it, exactly like the genesis anchor — so an authority cannot mint an
# unearned certificate by simply asserting a lower bar.
CERTIFICATE_THRESHOLD = 250


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


def certificate_id(payload: dict) -> str:
    """Stable identity of a certificate, independent of who issued or how it hashes.

    A certificate is *what was certified*, not *which transaction carried it*: its
    identity is the ``(subject, rubric_root, domain, submission_tx_hash)`` it
    decides. Two transactions with those four fields equal are the **same**
    certificate and must not both credit reputation, so consensus forbids
    re-issuing an id already committed in the prefix (see
    :meth:`blockchain.blockchain.Blockchain.is_valid_chain`).

    ``submission_tx_hash`` binds the certificate to the exact submission its
    attestations reviewed; it is absent (``None``) until that binding is added,
    and is read defensively so this stays total on any certificate payload.
    """
    identity = [
        payload.get("subject"),
        payload.get("rubric_root"),
        payload.get("domain"),
        payload.get("submission_tx_hash"),
    ]
    canonical = json.dumps(identity, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def validate_certificate(payload: dict, prefix_chain, prefix_registry) -> bool:
    """Whether ``payload`` is a certificate the protocol would actually issue.

    Re-derives the certificate deterministically from the chain **prefix** — the
    blocks committed before the one carrying it — exactly as :func:`certify`
    would: it recomputes the weighted support of the genuine positive attesters
    for ``(subject, rubric_root, domain)`` and requires that (a) the support meets
    the protocol-wide :data:`CERTIFICATE_THRESHOLD` and (b) ``granted_by`` names
    precisely the attesters who actually carried weight. A forged certificate
    (threshold unmet) or one crediting the wrong attesters fails, so an authority
    cannot mint an unearned certificate by putting it in a block it signs.

    ``prefix_chain`` is any object exposing ``blocks`` (the prefix view) and
    ``prefix_registry`` is the reputation derived from that same prefix.
    """
    subject = payload.get("subject")
    rubric_root = payload.get("rubric_root")
    domain = payload.get("domain")
    attesters = positive_attesters(prefix_chain, subject, rubric_root, domain)
    weights = {a: prefix_registry.weight(a, domain) for a in attesters}
    if sum(weights.values()) < CERTIFICATE_THRESHOLD:
        return False
    credited = sorted(a for a, w in weights.items() if w > 0)
    granted_by = payload.get("granted_by")
    if not isinstance(granted_by, list):
        return False
    return sorted(granted_by) == credited
