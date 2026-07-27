"""Merkle tree over transaction hashes.

A Merkle tree condenses many transaction hashes into a single ``root`` hash by
repeatedly hashing pairs of nodes until one value remains. Two properties make
it the interesting data structure of this project:

1. **Tamper-evidence** — changing any transaction changes its leaf hash and
   therefore the root, so a block header that commits to the root commits to
   every transaction it contains.
2. **Compact inclusion proofs** — a peer can prove a transaction is in a block
   by revealing only ``log2(n)`` sibling hashes (the "authentication path"),
   not the whole block.

Design choices, documented for the coursework:

- **Leaves are transaction hashes** (the ``Transaction.hash`` hex digests).
- **Pairing** combines two child hex digests as ``SHA-256(left + right)`` over
  their UTF-8 bytes. Concatenating the hex strings keeps the operation trivial
  to reproduce and verify by hand.
- **Odd number of nodes**: the last node is duplicated and paired with itself,
  so every level has an even width. This is the same rule Bitcoin uses.
- **Empty tree**: the root is ``SHA-256(b"")``, a fixed, well-defined constant.
  This lets a block with no transactions still have a valid root.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

# Root of a tree with no leaves: the SHA-256 of the empty byte string.
EMPTY_ROOT = hashlib.sha256(b"").hexdigest()


def _hash_pair(left: str, right: str) -> str:
    """Hash two child hex digests into their parent hex digest."""
    return hashlib.sha256((left + right).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class MerkleProof:
    """An inclusion (authentication) proof for a single leaf.

    Attributes:
        leaf_hash: The hash of the transaction being proven.
        path: Ordered steps from the leaf up to the root. Each step is a
            ``(sibling_hash, side)`` tuple, where ``side`` is ``"left"`` or
            ``"right"`` describing where the *sibling* sits relative to the
            running hash — needed because hashing is order-sensitive.
    """

    leaf_hash: str
    path: list[tuple[str, str]]


class MerkleTree:
    """A Merkle tree built from a list of transactions.

    The tree is built once at construction time and its intermediate levels are
    retained so inclusion proofs can be produced without rebuilding.
    """

    def __init__(self, transactions: list) -> None:
        """Build the tree from ``transactions`` (objects exposing ``.hash``)."""
        self._leaves = [tx.hash for tx in transactions]
        self._levels = self._build_levels(self._leaves)

    @staticmethod
    def _build_levels(leaves: list[str]) -> list[list[str]]:
        """Return every level of the tree, bottom (leaves) to top (root).

        ``levels[0]`` is the leaves and ``levels[-1]`` is a single-element list
        holding the root. An empty leaf set yields the constant EMPTY_ROOT.
        """
        if not leaves:
            return [[EMPTY_ROOT]]

        levels = [list(leaves)]
        while len(levels[-1]) > 1:
            current = levels[-1]
            # Duplicate the last node when the level width is odd.
            if len(current) % 2 == 1:
                current = current + [current[-1]]
            parents = [
                _hash_pair(current[i], current[i + 1])
                for i in range(0, len(current), 2)
            ]
            levels.append(parents)
        return levels

    @property
    def root(self) -> str:
        """The Merkle root hash (hex string)."""
        return self._levels[-1][0]

    def proof(self, tx) -> MerkleProof:
        """Return an inclusion proof for ``tx``.

        Raises:
            ValueError: if ``tx`` is not present in the tree.
        """
        leaf_hash = tx.hash
        try:
            index = self._leaves.index(leaf_hash)
        except ValueError:
            raise ValueError("transaction is not in this Merkle tree")

        path: list[tuple[str, str]] = []
        for level in self._levels[:-1]:  # every level except the root
            # Re-apply the odd-width duplication so indices line up with build.
            nodes = level if len(level) % 2 == 0 else level + [level[-1]]
            if index % 2 == 0:
                sibling, side = nodes[index + 1], "right"
            else:
                sibling, side = nodes[index - 1], "left"
            path.append((sibling, side))
            index //= 2

        return MerkleProof(leaf_hash=leaf_hash, path=path)


def verify(proof: MerkleProof, root: str) -> bool:
    """Verify that ``proof`` reconstructs ``root``.

    Recomputes the root by folding each sibling into the running hash on the
    side recorded in the proof. Returns ``True`` only if the result matches
    ``root`` exactly.
    """
    running = proof.leaf_hash
    for sibling, side in proof.path:
        if side == "right":
            running = _hash_pair(running, sibling)
        elif side == "left":
            running = _hash_pair(sibling, running)
        else:  # defensive: an unknown side means a malformed proof
            return False
    return running == root
