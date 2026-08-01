"""Aggregation and threshold — turning attestations into a certificate.

Individual attestations are cheap opinions; a **certificate** is the protocol's
collective decision that a subject has met a rubric in a domain. This module
scans a :class:`~blockchain.blockchain.Blockchain`, gathers the attestations that
bear on one ``(subject, rubric_root, domain)`` triple, and — if their backers
carry enough *reputation weight* — mints a certificate transaction.

Design decisions, documented for the coursework:

- **Scope is ``(subject, rubric_root, domain, submission_tx_hash)``.** A certificate
  names a single submission of a single rubric in a single competence domain, so
  votes are only pooled among attestations matching all four; a review of a
  *different* submission of the same subject/rubric/domain is irrelevant to this
  decision and never co-counts.
- **Only positive verdicts count.** ``verdict=False`` is an explicit "did not
  meet it" and must not push the subject toward acceptance.
- **One attester, one vote.** Votes are deduplicated by attester identity
  (the transaction ``sender``), so the same attester spamming attestations
  cannot inflate support.
- **Weighted by reputation.** Acceptance is decided by the *sum of the
  attesters' domain-scoped weights* (via :func:`reputation.tally.weighted_support`),
  not a head count: ``threshold`` is now a weight sum. This closes the former
  equal-weight simplification.
- **Collusion-capped.** Acceptance counts support through
  :func:`reputation.tally.capped_support`: no single cross-attesting *cluster* may
  contribute more than a fraction ``ALPHA`` of the counted total, so a cartel that
  cross-attests to farm reputation cannot pool it to force a certificate. The
  cluster is a simplified, chain-derivable proxy (mutual cross-attestation) for
  graph community detection; see :mod:`reputation.tally`. The identical cap is
  enforced in consensus by :func:`validate_certificate`.
"""

from __future__ import annotations

import hashlib
import json
from types import SimpleNamespace

from attestation.attestation import is_attestation
from blockchain.blockchain import AUTHORITY_THRESHOLD, Blockchain
from blockchain.transaction import Transaction
from reputation.derive import derive_registry
from reputation.genesis import CONSENSUS_DOMAIN
from reputation.registry import ReputationRegistry
from reputation.slashing import SLASH_TYPE, validate_slash
from reputation.tally import capped_support, positive_attesters

# Discriminator for the certificate payload, mirroring ATTESTATION_TYPE.
CERTIFICATE_TYPE = "certificate"

# The two chain-derived statuses a committed certificate can hold. A certificate
# is an **immutable historical fact** — once on-chain it is never deleted or
# rewritten — so its status is not a stored field but a *pure function of the
# chain* (see :func:`certificate_statuses`): "valid" until a contributing attester
# is later slashed for the very submission it certifies, then "contested".
CERTIFICATE_VALID = "valid"
CERTIFICATE_CONTESTED = "contested"

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
    submission_tx_hash: str,
    granted_by: list[str],
    issuer: str = DEFAULT_ISSUER,
) -> Transaction:
    """Build a certificate as a :class:`Transaction`.

    Like an attestation, a certificate is a plain transaction with a structured
    payload, so it rides the chain with no core changes. It records the ``domain``
    it was decided in and the ``submission_tx_hash`` it certifies — a certificate
    is per ``(subject, rubric_root, domain, submission_tx_hash)``, and it **carries**
    that submission hash so an auditor (and :func:`certificate_id`) can prove which
    exact submission its attesters reviewed. ``granted_by`` is stored sorted so the
    payload — and therefore the transaction hash — is deterministic regardless of
    the order attesters were discovered in.
    """
    payload = {
        "type": CERTIFICATE_TYPE,
        "subject": subject,
        "rubric_root": rubric_root,
        "domain": domain,
        "submission_tx_hash": submission_tx_hash,
        "granted_by": sorted(granted_by),
    }
    return Transaction(sender=issuer, payload=payload)


def certify(
    chain: Blockchain,
    registry: ReputationRegistry,
    subject: str,
    rubric_root: str,
    domain: str,
    submission_tx_hash: str,
    threshold: int,
    issuer: str = DEFAULT_ISSUER,
) -> Transaction | None:
    """Decide whether ``subject`` earns a certificate for one submission of ``(rubric_root, domain)``.

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
        submission_tx_hash: Hex hash of the submission being certified. Only
            attestations that reviewed *this* submission are counted, so a
            certificate is bound to one specific piece of work.
        threshold: Minimum weighted support (sum of attester weights) required.
        issuer: Identity recorded as the certificate's sender.
    """
    attesters = positive_attesters(chain, subject, rubric_root, domain, submission_tx_hash)
    weights = {attester: registry.weight(attester, domain) for attester in attesters}
    # Support is counted through the collusion cap (:func:`reputation.tally.capped_support`),
    # so no single cross-attesting cluster can contribute more than ALPHA of the
    # total. A cartel that would meet ``threshold`` only via over-concentration is
    # clamped below it and does not certify. The cap is applied identically in
    # consensus (:func:`validate_certificate`), so certify() and chain validation
    # agree by construction.
    if capped_support(chain, attesters, weights) < threshold:
        return None
    # Exclude zero-weight attesters from granted_by: the certificate credits only
    # those whose reputation actually carried it, so it is an honest audit trail.
    # The cap governs *how much support counts*, not *who is credited* — a capped
    # cluster's members still genuinely attested, so they remain credited (and the
    # balance layer still releases/rewards their bonds unchanged).
    credited = [attester for attester, w in weights.items() if w > 0]
    return make_certificate(
        subject, rubric_root, domain, submission_tx_hash, credited, issuer=issuer
    )


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
    for ``(subject, rubric_root, domain, submission_tx_hash)`` and requires that (a) the support meets
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
    # The certificate is bound to one submission; re-derivation must key on the
    # same submission its payload carries, so it credits only the attesters who
    # actually reviewed that piece of work. A None (missing) hash keys a scope no
    # real attestation matches, so a certificate lacking the binding re-derives as
    # unsupported and is rejected.
    submission_tx_hash = payload.get("submission_tx_hash")
    attesters = positive_attesters(
        prefix_chain, subject, rubric_root, domain, submission_tx_hash
    )
    weights = {a: prefix_registry.weight(a, domain) for a in attesters}
    # Apply the SAME collusion cap consensus's peer, ``certify``, applies: support
    # is counted through :func:`reputation.tally.capped_support`, so a certificate
    # that only clears the threshold via an over-concentrated (>ALPHA) cross-
    # attesting cluster is re-derived here as under-supported and rejected. The
    # clusters and cap are chain-derived from the same prefix on every node, so this
    # is deterministic.
    if capped_support(prefix_chain, attesters, weights) < CERTIFICATE_THRESHOLD:
        return False
    credited = sorted(a for a, w in weights.items() if w > 0)
    granted_by = payload.get("granted_by")
    if not isinstance(granted_by, list):
        return False
    return sorted(granted_by) == credited


# --- Certificate revocation / contest policy --------------------------------
#
# A certificate is an **immutable historical fact**: once committed it is never
# deleted or rewritten, and the reputation reward it credited its subject is
# *never* clawed back (history is immutable — see
# :func:`reputation.derive.derive_registry`). But issuance is not the last word on
# a certificate's *standing*. Slashing already prevents a certificate *before*
# issuance (a slashed attester's weight drops, so their support no longer counts
# toward the threshold). This policy closes the remaining gap: an attester whose
# attestation **contributed to an already-issued certificate** may be
# successfully slashed *afterwards* (evidence + quorum). When that happens the
# certificate does not vanish and its reward is not reversed — instead it
# deterministically transitions to a **"contested"** status, derived from the
# chain so every node computes it identically and consumers can judge it.
#
# A certificate is "contested" iff at least one of its ``granted_by`` attesters
# was **validly slashed** (:func:`reputation.slashing.validate_slash`) for an
# attestation **bound to the certificate's own** ``submission_tx_hash``, in a
# block committed **after** the certificate's block. Both conditions are
# required: a slash of an unrelated attester, or a slash of a contributing
# attester for a *different* submission, leaves the certificate "valid". The
# status is a pure function of the chain — no mutation of any certificate or of
# reputation — so it is identical on every honest node.


def _find_tx(chain, tx_hash: str):
    """The transaction on ``chain`` whose hash is ``tx_hash`` (or ``None``)."""
    for block in chain.blocks:
        for tx in block.transactions:
            if tx.hash == tx_hash:
                return tx
    return None


def _evidence_submissions(chain, slash_payload: dict) -> set[str]:
    """The ``submission_tx_hash`` set of a slash's evidence attestations.

    A slash references the offender's two conflicting attestations by hash. Each
    such attestation is bound (via its ``submission_tx_hash``) to the exact
    submission it reviewed; this returns the set of those submissions, so a
    certificate for one of them can recognise that its contributing attester was
    slashed for *this same* piece of work.
    """
    submissions: set[str] = set()
    for tx_hash in slash_payload.get("evidence", []):
        tx = _find_tx(chain, tx_hash)
        if tx is not None and is_attestation(tx):
            submissions.add(tx.payload["submission_tx_hash"])
    return submissions


def certificate_statuses(chain) -> dict[str, str]:
    """Map every committed certificate's transaction hash to its chain-derived status.

    The status is :data:`CERTIFICATE_CONTESTED` if at least one of the
    certificate's ``granted_by`` attesters was **validly slashed** for an
    attestation bound to the certificate's ``submission_tx_hash`` in a block
    committed *after* the certificate, and :data:`CERTIFICATE_VALID` otherwise.

    This is a **pure function of the chain** — it neither mutates the certificate
    nor revokes the subject's reputation reward (history is immutable). Slashes
    are re-validated from their prefix exactly as
    :func:`reputation.derive.derive_registry` applies them (evidence present + a
    quorum of the prefix's consensus authorities), so only a genuine slash can
    contest a certificate and the result is deterministic and identical on every
    node.

    ``chain`` is any object exposing ``blocks`` (and optionally ``genesis``, the
    reputation anchor used to derive the validator set a slash's quorum is checked
    against; ``None`` uses the canonical anchor).
    """
    genesis = getattr(chain, "genesis", None)

    # Pass 1: collect the genuine slashes as (block_index, offender, submissions),
    # where ``submissions`` is the set of submission hashes the offender was proven
    # to have equivocated on. Each slash is re-validated against its own prefix and
    # the consensus authorities derived from that prefix, mirroring how the debit
    # is applied during reputation derivation — so a fabricated or unapproved slash
    # never contests anything.
    slashes: list[tuple[int, str, set[str]]] = []
    for block in chain.blocks:
        prefix_chain = None
        validators: set[str] | None = None
        for tx in block.transactions:
            payload = tx.payload
            if not isinstance(payload, dict) or payload.get("type") != SLASH_TYPE:
                continue
            if validators is None:
                prefix_chain = SimpleNamespace(blocks=chain.blocks[: block.index])
                prefix_registry = derive_registry(
                    chain, upto_index=block.index, genesis=genesis
                )
                validators = prefix_registry.authorities_in_domain(
                    CONSENSUS_DOMAIN, AUTHORITY_THRESHOLD
                )
            if not validate_slash(payload, prefix_chain, validators):
                continue
            slashes.append(
                (block.index, payload["offender"], _evidence_submissions(chain, payload))
            )

    # Pass 2: derive each certificate's status. A certificate is contested by a
    # later slash whose offender it credited (``granted_by``) and whose proven
    # equivocation is on the certificate's own submission.
    statuses: dict[str, str] = {}
    for block in chain.blocks:
        for tx in block.transactions:
            payload = tx.payload
            if not isinstance(payload, dict) or payload.get("type") != CERTIFICATE_TYPE:
                continue
            granted_by = payload.get("granted_by")
            granted = set(granted_by) if isinstance(granted_by, list) else set()
            submission_tx_hash = payload.get("submission_tx_hash")
            contested = any(
                slash_index > block.index
                and offender in granted
                and submission_tx_hash in submissions
                for slash_index, offender, submissions in slashes
            )
            statuses[tx.hash] = (
                CERTIFICATE_CONTESTED if contested else CERTIFICATE_VALID
            )
    return statuses
