"""Tests for the Merkle tree, inclusion proofs, and verification."""

import unittest

from blockchain.merkle import EMPTY_ROOT, MerkleProof, MerkleTree, verify
from blockchain.transaction import Transaction


def make_txs(n: int) -> list[Transaction]:
    """Build ``n`` distinct, deterministic transactions."""
    return [
        Transaction(sender=f"peer{i}", payload={"i": i}, timestamp=float(i))
        for i in range(n)
    ]


class MerkleRootTests(unittest.TestCase):
    def test_root_is_stable(self):
        """The same transactions always produce the same root."""
        txs = make_txs(4)
        self.assertEqual(MerkleTree(txs).root, MerkleTree(txs).root)

    def test_single_leaf_root_is_leaf_hash(self):
        """A one-transaction tree's root is that transaction's hash."""
        txs = make_txs(1)
        self.assertEqual(MerkleTree(txs).root, txs[0].hash)

    def test_empty_tree_uses_constant_root(self):
        """An empty tree has the well-defined EMPTY_ROOT."""
        self.assertEqual(MerkleTree([]).root, EMPTY_ROOT)

    def test_odd_number_of_leaves_builds(self):
        """Odd leaf counts (last duplicated) still yield a stable root."""
        txs = make_txs(3)
        self.assertEqual(MerkleTree(txs).root, MerkleTree(txs).root)

    def test_root_changes_when_a_transaction_changes(self):
        """Tampering with any transaction changes the root."""
        txs = make_txs(4)
        root_before = MerkleTree(txs).root
        txs[2].payload = {"i": 999}  # tamper
        self.assertNotEqual(root_before, MerkleTree(txs).root)


class MerkleProofTests(unittest.TestCase):
    def test_valid_proof_verifies_for_every_leaf(self):
        """Each leaf's proof reconstructs the root (covers even and odd sizes)."""
        for n in (1, 2, 3, 4, 5):
            txs = make_txs(n)
            tree = MerkleTree(txs)
            for tx in txs:
                self.assertTrue(
                    verify(tree.proof(tx), tree.root),
                    msg=f"proof failed for n={n}, tx={tx.payload}",
                )

    def test_tampered_sibling_fails(self):
        """Corrupting a sibling hash in the path breaks verification."""
        txs = make_txs(4)
        tree = MerkleTree(txs)
        good = tree.proof(txs[0])

        sibling, side = good.path[0]
        bad_path = [("0" * 64, side)] + good.path[1:]
        bad = MerkleProof(leaf_hash=good.leaf_hash, path=bad_path)

        self.assertFalse(verify(bad, tree.root))

    def test_tampered_side_fails(self):
        """Flipping a step's side breaks verification (hashing is ordered)."""
        txs = make_txs(4)
        tree = MerkleTree(txs)
        good = tree.proof(txs[0])

        sibling, side = good.path[0]
        flipped = "left" if side == "right" else "right"
        bad = MerkleProof(good.leaf_hash, [(sibling, flipped)] + good.path[1:])

        self.assertFalse(verify(bad, tree.root))

    def test_proof_for_absent_transaction_raises(self):
        """Asking for a proof of a transaction not in the tree is an error."""
        tree = MerkleTree(make_txs(3))
        outsider = Transaction(sender="mallory", payload={"i": -1}, timestamp=-1.0)
        with self.assertRaises(ValueError):
            tree.proof(outsider)


if __name__ == "__main__":
    unittest.main()
