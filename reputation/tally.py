"""Weighted tally — support for a claim, measured in reputation not headcount.

:func:`positive_attesters` finds the distinct attesters backing a claim, and
:func:`weighted_support` sums each one's **domain-scoped weight** from a
:class:`~reputation.registry.ReputationRegistry`. A claim therefore gains support
in proportion to how much standing its backers hold in the relevant domain, not
merely how many backers it has.

Scope is the triple ``(subject, rubric_root, domain)``: an attestation counts
only if it is a positive verdict about that subject, against that rubric, in
that domain. Votes are deduplicated by attester identity (``sender``) so repeat
attestations cannot inflate support.

These are the shared primitives the aggregator's :func:`attestation.aggregator.certify`
now decides on: it obtains the attester set here (one chain scan) and derives
both the weighted sum and the credited attester list from it.
"""

from __future__ import annotations

from attestation.attestation import is_attestation
from blockchain.blockchain import Blockchain
from reputation.registry import ReputationRegistry


def positive_attesters(
    chain: Blockchain,
    subject: str,
    rubric_root: str,
    domain: str,
) -> set[str]:
    """Distinct attesters who positively attested the ``(subject, rubric_root, domain)`` triple.

    Scans every mined block for attestations matching the triple with a ``True``
    verdict and returns the set of their ``sender`` identities. Returning a set
    is what enforces one-attester-one-vote. This is the single scan that both
    :func:`weighted_support` and the aggregator build on, so the chain is never
    scanned twice for the same decision.
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
    return attesters


def weighted_support(
    chain: Blockchain,
    registry: ReputationRegistry,
    subject: str,
    rubric_root: str,
    domain: str,
) -> int:
    """Sum the domain-scoped weight of ``subject``'s distinct positive attesters.

    The reputation-weighted counterpart of a head count: it sums each distinct
    positive attester's weight in ``domain`` per ``registry``. An attester with
    0 weight in the domain contributes nothing. Built on
    :func:`positive_attesters`, so its scoping and dedup rules are shared by
    construction.
    """
    attesters = positive_attesters(chain, subject, rubric_root, domain)
    return sum(registry.weight(attester, domain) for attester in attesters)
