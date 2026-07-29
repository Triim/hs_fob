"""Weighted tally — support for a claim, measured in reputation not headcount.

:func:`weighted_support` is the reputation-aware counterpart of the aggregator's
``_positive_attesters``. Where the aggregator counts *distinct positive
attesters* (each worth 1), this sums each distinct attester's **domain-scoped
weight** from a :class:`~reputation.registry.ReputationRegistry`. A claim
therefore gains support in proportion to how much standing its backers hold in
the relevant domain, not merely how many backers it has.

Scope is the triple ``(subject, rubric_root, domain)``: an attestation counts
only if it is a positive verdict about that subject, against that rubric, in
that domain. Like the aggregator, votes are deduplicated by attester identity
(``sender``) so repeat attestations cannot inflate support.

This lives alongside ``aggregator.py`` rather than modifying it; rewiring
``certify()`` to use weights is a later step.
"""

from __future__ import annotations

from attestation.attestation import is_attestation
from blockchain.blockchain import Blockchain
from reputation.registry import ReputationRegistry


def weighted_support(
    chain: Blockchain,
    registry: ReputationRegistry,
    subject: str,
    rubric_root: str,
    domain: str,
) -> int:
    """Sum the domain-scoped weight of ``subject``'s distinct positive attesters.

    Scans every mined block for attestations matching the
    ``(subject, rubric_root, domain)`` triple with a ``True`` verdict,
    deduplicates the attesters by ``sender`` (one attester, one vote), and
    returns the sum of each distinct attester's weight in ``domain`` per
    ``registry``. An attester with 0 weight in the domain contributes nothing.
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
            if payload["verdict"] is not True:
                continue
            attesters.add(tx.sender)
    return sum(registry.weight(attester, domain) for attester in attesters)
