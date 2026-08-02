"""Tests for the Rubric application-layer object."""

import unittest

from attestation.rubric import Rubric
from blockchain.merkle import verify

CLAIMS = [
    "Can derive a Merkle root by hand",
    "Can explain proof-of-work difficulty",
    "Can validate a chain end to end",
]


class RubricRootTests(unittest.TestCase):
    def test_root_is_stable(self):
        """Same claims in the same order yield the same 64-char hex root."""
        a = Rubric(CLAIMS)
        b = Rubric(list(CLAIMS))

        self.assertEqual(a.root(), b.root())
        self.assertEqual(len(a.root()), 64)

    def test_root_changes_with_order(self):
        """Reordering claims changes what each index means, so the root moves."""
        a = Rubric(CLAIMS)
        b = Rubric(list(reversed(CLAIMS)))

        self.assertNotEqual(a.root(), b.root())


class RubricProofTests(unittest.TestCase):
    def test_valid_item_proof_verifies(self):
        """A proof for item i reconstructs the rubric root via core verify()."""
        rubric = Rubric(CLAIMS)
        for i in range(len(CLAIMS)):
            proof = rubric.proof(i)
            self.assertTrue(verify(proof, rubric.root()))

    def test_proof_does_not_verify_against_wrong_root(self):
        """A valid proof fails against a different rubric's root."""
        rubric = Rubric(CLAIMS)
        other = Rubric(["something", "entirely", "different"])

        proof = rubric.proof(0)
        self.assertFalse(verify(proof, other.root()))

    def test_verify_item_rejects_wrong_claim(self):
        """A correct index but wrong claim text does not verify."""
        rubric = Rubric(CLAIMS)

        self.assertTrue(rubric.verify_item(1, CLAIMS[1], rubric.root()))
        self.assertFalse(rubric.verify_item(1, CLAIMS[0], rubric.root()))

    def test_verify_item_rejects_wrong_index_for_claim(self):
        """The right claim text at the wrong index does not verify."""
        rubric = Rubric(CLAIMS)
        self.assertFalse(rubric.verify_item(2, CLAIMS[0], rubric.root()))

    def test_proof_out_of_range_raises(self):
        rubric = Rubric(CLAIMS)
        with self.assertRaises(IndexError):
            rubric.proof(len(CLAIMS))

    def test_verify_item_out_of_range_is_false(self):
        rubric = Rubric(CLAIMS)
        self.assertFalse(rubric.verify_item(99, "anything", rubric.root()))


class RubricRequiredItemsTests(unittest.TestCase):
    def test_default_is_all_items_required(self):
        """Unspecified required_items ⇒ every item index is required (strict default)."""
        rubric = Rubric(CLAIMS)
        self.assertEqual(rubric.required_items, [0, 1, 2])

    def test_explicit_subset_is_sorted_and_deduped(self):
        """A supplied set is snapshotted, de-duplicated, and sorted."""
        rubric = Rubric(CLAIMS, required_items=[2, 0, 2])
        self.assertEqual(rubric.required_items, [0, 2])

    def test_empty_subset_means_no_item_required(self):
        """An explicit empty list is honoured (threshold-only certification)."""
        self.assertEqual(Rubric(CLAIMS, required_items=[]).required_items, [])

    def test_out_of_range_required_item_raises(self):
        with self.assertRaises(IndexError):
            Rubric(CLAIMS, required_items=[len(CLAIMS)])

    def test_required_items_is_a_copy(self):
        """Callers cannot mutate the rubric's internal required set."""
        rubric = Rubric(CLAIMS)
        rubric.required_items.append(99)
        self.assertEqual(rubric.required_items, [0, 1, 2])


if __name__ == "__main__":
    unittest.main()
