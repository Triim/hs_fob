"""Rubrics — an ordered set of competence claims committed under a Merkle root.

A **rubric** is the checklist an attestation is made against: an ordered list of
plain-text claims such as ``"Can derive the Merkle root by hand"``. Committing
the list to a single Merkle root gives every claim a compact, verifiable
identity: an attestation references a claim by ``(rubric_root, item_index)``, and
anyone holding the rubric can prove that item ``i`` really is the claim the
attester meant — without shipping the whole rubric.

Reuse, not reinvention
----------------------
The commitment is built with the *existing* :class:`~blockchain.merkle.MerkleTree`
and checked with the existing :func:`~blockchain.merkle.verify`. That tree hashes
any object exposing a ``.hash`` property, so each claim string is wrapped in a
small :class:`_ClaimLeaf` whose ``hash`` is the SHA-256 of the claim. No core
code changes; the rubric is a pure application-layer client of the core.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from blockchain.merkle import MerkleProof, MerkleTree, verify


@dataclass(frozen=True)
class _ClaimLeaf:
    """Adapter making a claim string usable as a Merkle leaf.

    :class:`MerkleTree` builds its leaves from ``object.hash``. A claim is just a
    string, so this wrapper exposes the SHA-256 hex digest of the claim's UTF-8
    bytes as ``hash`` — the same digest kind (64-char hex) the tree already
    pairs, keeping the leaf format uniform with the rest of the project.
    """

    claim: str

    @property
    def hash(self) -> str:
        return hashlib.sha256(self.claim.encode("utf-8")).hexdigest()


class Rubric:
    """An ordered list of claims committed under one Merkle root."""

    def __init__(self, claims: list[str]) -> None:
        """Build a rubric over ``claims`` in the given order.

        Order is significant: an attestation points at a claim by numeric
        ``item_index``, so reordering the claims changes what every index means
        (and changes the root). The claims are snapshotted so later external
        mutation of the caller's list cannot silently change this rubric.
        """
        self._claims = list(claims)
        self._leaves = [_ClaimLeaf(claim) for claim in self._claims]
        self._tree = MerkleTree(self._leaves)

    @property
    def claims(self) -> list[str]:
        """A copy of the ordered claims (copy so callers can't mutate state)."""
        return list(self._claims)

    def root(self) -> str:
        """The rubric's Merkle root — its stable, content-addressed identity."""
        return self._tree.root

    def proof(self, item_index: int) -> MerkleProof:
        """Return an inclusion proof for the claim at ``item_index``.

        Raises:
            IndexError: if ``item_index`` is out of range for this rubric.
        """
        if not 0 <= item_index < len(self._leaves):
            raise IndexError("item_index out of range for this rubric")
        return self._tree.proof(self._leaves[item_index])

    def verify_item(self, item_index: int, claim: str, root: str) -> bool:
        """Check that ``claim`` sits at ``item_index`` under ``root``.

        Convenience wrapper over the core :func:`verify`: it rebuilds the leaf
        from the *claimed* text and item index and confirms the resulting
        inclusion proof reconstructs ``root``. Returns ``False`` (rather than
        raising) for an out-of-range index so it can validate untrusted input.
        """
        if not 0 <= item_index < len(self._leaves):
            return False
        # Prove membership of the leaf actually at that index, then require the
        # claimed text to match it — so a right proof for the wrong claim fails.
        proof = self._tree.proof(self._leaves[item_index])
        if _ClaimLeaf(claim).hash != proof.leaf_hash:
            return False
        return verify(proof, root)
