"""Tests for the HTTP bridge's pure serialization helpers.

The live endpoints are exercised by running ``network.run_nodes`` and polling
them; here we lock the transaction-labelling and summary *shape* that every
endpoint depends on, without needing a server or an event loop.
"""

import unittest

from attestation.aggregator import make_certificate
from attestation.attestation import make_attestation
from attestation.submission import make_submission
from blockchain.transaction import Transaction
from crypto.keys import generate_keypair
from network.http_bridge import _tx_summary, _tx_type_label
from reputation.slashing import make_slash


class TxTypeLabelTests(unittest.TestCase):
    def test_labels_each_real_type_via_predicates(self):
        self.assertEqual(
            _tx_type_label(make_attestation("n", "s", "r", 0, True, 1)), "attestation"
        )
        self.assertEqual(
            _tx_type_label(make_submission("s", "d", "r", "t", "aa")), "submission"
        )
        self.assertEqual(
            _tx_type_label(make_certificate("s", "r", "d", ["a"])), "certificate"
        )
        self.assertEqual(
            _tx_type_label(make_slash("off", "d", "reason", "ref")), "slash"
        )

    def test_unknown_payload_is_other(self):
        self.assertEqual(
            _tx_type_label(Transaction(sender="alice", payload={"amount": 5})), "other"
        )


class TxSummaryTests(unittest.TestCase):
    def test_summary_shape_and_signature_flags(self):
        private_key, public_key_hex = generate_keypair()
        tx = make_submission(public_key_hex, "d", "r", "t", "aa", "n.pdf")
        tx.sign(private_key)

        summary = _tx_summary(tx)

        self.assertEqual(
            set(summary),
            {"hash", "type", "sender", "payload", "signed", "signature_valid"},
        )
        self.assertEqual(summary["hash"], tx.hash)
        self.assertEqual(summary["type"], "submission")
        self.assertEqual(summary["sender"], {"short": public_key_hex[:12], "full": public_key_hex})
        self.assertEqual(summary["payload"], tx.payload)
        self.assertTrue(summary["signed"])
        self.assertTrue(summary["signature_valid"])

    def test_unsigned_transaction_reports_invalid_signature(self):
        tx = make_attestation("n", "s", "r", 0, True, 1)
        summary = _tx_summary(tx)
        self.assertFalse(summary["signed"])
        self.assertFalse(summary["signature_valid"])


if __name__ == "__main__":
    unittest.main()
