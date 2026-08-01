"""Weighted tally — support for a claim, measured in reputation not headcount.

:func:`positive_attesters` finds the distinct attesters backing a claim, and
:func:`weighted_support` sums each one's **domain-scoped weight** from a
:class:`~reputation.registry.ReputationRegistry`. A claim therefore gains support
in proportion to how much standing its backers hold in the relevant domain, not
merely how many backers it has.

Scope is the four-tuple ``(subject, rubric_root, domain, submission_tx_hash)``: an
attestation counts only if it is a positive verdict about that subject, against
that rubric, in that domain, **for that exact submission**. Two submissions of the
same subject/rubric/domain are distinct pieces of work, so their reviews are pooled
separately and never co-count. Votes are deduplicated by attester identity
(``sender``) so repeat attestations cannot inflate support.

These are the shared primitives the aggregator's :func:`attestation.aggregator.certify`
now decides on: it obtains the attester set here (one chain scan) and derives
both the weighted sum and the credited attester list from it.

Collusion cap
-------------
A raw weighted sum has a paid-review / cartel weakness: a group that cross-attests
one another can farm reputation among themselves and then pool it to push *any*
subject over the certification threshold. To blunt that, certification counts
support through :func:`capped_support`, which caps how much a single **collusion
cluster** may contribute to at most a fraction :data:`ALPHA` of the total.

The cluster is a deliberately *simplified* proxy for graph-based community
detection (the fuller solution): rather than run community detection over the
whole attestation graph, we define an edge only between two attesters who have
**mutually positively cross-attested** each other anywhere in the chain — A
positively attested a submission by B *and* B positively attested a submission by
A (:func:`attester_clusters`). Clusters are the connected components of that
mutual-edge graph. This is fully chain-derivable and deterministic, so every node
computes the same clusters and the same cap. Its known limitation — asymmetric or
sparser collusion (e.g. a star where one node is boosted but never reciprocates)
is not detected — is exactly what real community detection would close; that is
out of scope for this MVP.

A *singleton* cluster (an attester tied to no one by mutual cross-attestation) is
an independent reviewer, not a cartel, so it is **never** capped: a single strong,
honest attester may legitimately carry a certificate on their own standing. Only a
group of size ≥ 2 linked by mutual cross-attestation has its joint contribution
clamped.
"""

from __future__ import annotations

from attestation.attestation import is_attestation
from blockchain.blockchain import Blockchain
from reputation.registry import ReputationRegistry

# Maximum fraction of the *total* counted weighted support that any one collusion
# cluster may contribute, expressed as an exact integer ratio so the cap is
# computed with integer arithmetic and is therefore bit-identical on every node
# (a float ``0.34`` could round differently across platforms and fork the chain).
# ALPHA = ALPHA_NUM / ALPHA_DEN = 0.34. This is **shared network configuration**:
# honest nodes must all agree on it, exactly like ``CERTIFICATE_THRESHOLD`` and the
# genesis anchor, since it is enforced in consensus (see
# :func:`attestation.aggregator.validate_certificate` and
# :meth:`blockchain.blockchain.Blockchain.is_valid_chain`).
ALPHA_NUM = 34
ALPHA_DEN = 100
ALPHA = ALPHA_NUM / ALPHA_DEN


def positive_attesters(
    chain: Blockchain,
    subject: str,
    rubric_root: str,
    domain: str,
    submission_tx_hash: str,
) -> set[str]:
    """Distinct attesters who positively attested the ``(subject, rubric_root, domain, submission_tx_hash)`` key.

    Scans every mined block for attestations matching **all four** fields with a
    ``True`` verdict and returns the set of their ``sender`` identities. The scope
    is per *submission*: an attestation about a different submission of the same
    subject/rubric/domain has a different ``submission_tx_hash`` and does **not**
    count here, so votes for one piece of work never leak into another's
    certification. Returning a set is what enforces one-attester-one-vote. This is
    the single scan that both :func:`weighted_support` and the aggregator build on,
    so the chain is never scanned twice for the same decision.
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
            if payload["domain"] != domain:
                continue
            # Per-submission scope: a review of a *different* submission of the
            # same subject/rubric/domain is a different claim and must not count.
            if payload["submission_tx_hash"] != submission_tx_hash:
                continue
            # Only an explicit positive verdict backs the claim: ``False``
            # (opposition) and ``None`` (an *abstain*) both fall here and add zero
            # weight, so an abstain is weight-neutral by construction.
            if payload["verdict"] is not True:
                continue
            attesters.add(tx.sender)
    return attesters


def weighted_support(
    chain: Blockchain,
    registry: ReputationRegistry,
    subject: str,
    rubric_root: str,
    domain: str,
    submission_tx_hash: str,
) -> int:
    """Sum the domain-scoped weight of the distinct positive attesters of one submission.

    The reputation-weighted counterpart of a head count: it sums each distinct
    positive attester's weight in ``domain`` per ``registry``. An attester with
    0 weight in the domain contributes nothing. Built on
    :func:`positive_attesters`, so its per-submission scoping and dedup rules are
    shared by construction — only reviews of *this* ``submission_tx_hash`` count.
    """
    attesters = positive_attesters(chain, subject, rubric_root, domain, submission_tx_hash)
    return sum(registry.weight(attester, domain) for attester in attesters)


def _positive_pairs(chain: Blockchain) -> set[tuple[str, str]]:
    """All ``(attester, subject)`` pairs that carry a positive attestation on chain.

    One scan over every mined block, collecting the directed relation "this
    attester positively attested this subject". Domain and rubric are intentionally
    ignored: a collusion tie is a *social* signal about two identities vouching for
    each other, so a cartel that cross-attests in one area to farm reputation used
    in another is still caught. Used by :func:`attester_clusters` to find mutual
    (bidirectional) ties.
    """
    pairs: set[tuple[str, str]] = set()
    for block in chain.blocks:
        for tx in block.transactions:
            if not is_attestation(tx):
                continue
            payload = tx.payload
            if payload["verdict"] is not True:
                continue
            pairs.add((tx.sender, payload["subject"]))
    return pairs


def attester_clusters(chain: Blockchain, attesters: set[str]) -> list[set[str]]:
    """Partition ``attesters`` into collusion clusters, deterministically.

    Two attesters share an (undirected) edge iff they have **mutually positively
    cross-attested**: each has, somewhere on ``chain``, a positive attestation
    about the *other* as subject. Clusters are the connected components of that
    graph over ``attesters``; an attester tied to no one is its own singleton.

    This is the simplified, chain-derivable proxy for graph community detection
    documented in the module header. The result is deterministic regardless of the
    order attesters are discovered in — components depend only on the edge set —
    so every node derives the same partition and therefore the same cap.
    """
    pairs = _positive_pairs(chain)
    # Union-find over the attester set. ``find`` path-compresses; ``union`` always
    # attaches the lexicographically larger root under the smaller, so the chosen
    # representative — and thus the grouping — is order-independent.
    parent: dict[str, str] = {a: a for a in attesters}

    def find(x: str) -> str:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a: str, b: str) -> None:
        ra, rb = find(a), find(b)
        if ra == rb:
            return
        hi, lo = (ra, rb) if ra > rb else (rb, ra)
        parent[hi] = lo

    ordered = sorted(attesters)
    for i, a in enumerate(ordered):
        for b in ordered[i + 1 :]:
            if (a, b) in pairs and (b, a) in pairs:
                union(a, b)

    clusters: dict[str, set[str]] = {}
    for a in attesters:
        clusters.setdefault(find(a), set()).add(a)
    return list(clusters.values())


def capped_support(
    chain: Blockchain, attesters: set[str], weights: dict[str, int]
) -> int:
    """Weighted support with each collusion cluster clamped to a fraction of the total.

    ``weights`` maps each attester in ``attesters`` to its domain-scoped weight.
    Let ``total`` be their raw sum. No single collusion cluster (see
    :func:`attester_clusters`) may contribute more than ``ALPHA * total`` toward
    the counted support: a cluster's joint weight is clamped to
    ``floor(ALPHA_NUM * total / ALPHA_DEN)``. **Singletons are exempt** — an
    attester in no mutual-cross-attestation tie is an independent reviewer, not a
    cartel, and carries full weight.

    The cap is measured against the *raw* ``total`` (not a post-clamp total), which
    keeps it a single, non-circular pass: the ceiling is fixed up front, then every
    multi-member cluster is clamped against it. Integer arithmetic throughout, so
    the value is identical on every node — this is what consensus re-derives in
    :func:`attestation.aggregator.validate_certificate`.
    """
    total = sum(weights.values())
    cap = (ALPHA_NUM * total) // ALPHA_DEN
    counted = 0
    for cluster in attester_clusters(chain, attesters):
        cluster_weight = sum(weights[a] for a in cluster)
        # A lone attester is not a colluding group, so it is never capped; a group
        # of two or more linked by mutual cross-attestation is clamped to the cap.
        if len(cluster) >= 2:
            cluster_weight = min(cluster_weight, cap)
        counted += cluster_weight
    return counted
