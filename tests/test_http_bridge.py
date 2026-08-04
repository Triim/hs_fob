"""Tests for the HTTP bridge's pure serialization helpers.

The live endpoints are exercised by running ``network.run_nodes`` and polling
them; here we lock the transaction-labelling and summary *shape* that every
endpoint depends on, without needing a server or an event loop.
"""

import unittest
from types import SimpleNamespace

from attestation.aggregator import make_certificate
from attestation.attestation import make_attestation
from attestation.submission import make_submission
from blockchain.blockchain import Blockchain
from blockchain.transaction import Transaction
from crypto.did import did_key_to_public_hex, public_key_to_did_key
from crypto.keys import generate_keypair, keypair_from_seed
from network.http_bridge import (
    _chain_payload,
    _short_full,
    _tx_summary,
    _tx_type_label,
)
from reputation.genesis import CONSENSUS_DOMAIN
from reputation.slashing import approve_slash, make_slash


class TxTypeLabelTests(unittest.TestCase):
    def test_labels_each_real_type_via_predicates(self):
        self.assertEqual(
            _tx_type_label(make_attestation("n", "s", "r", 0, True, 1, "aa")), "attestation"
        )
        self.assertEqual(
            _tx_type_label(make_submission("s", "d", "r", "t", "aa")), "submission"
        )
        self.assertEqual(
            _tx_type_label(make_certificate("s", "r", "d", "aa", ["a"])), "certificate"
        )
        self.assertEqual(
            _tx_type_label(make_slash("off", "d", ["h1" * 8, "h2" * 8], {})), "slash"
        )

    def test_unknown_payload_is_other(self):
        self.assertEqual(
            _tx_type_label(Transaction(sender="alice", payload={"amount": 5})), "other"
        )


class ShortFullDidTests(unittest.TestCase):
    """Every identifier the UI renders carries a DID alongside the raw key."""

    def test_real_key_gets_a_resolvable_did(self):
        _, public_key_hex = generate_keypair()

        rendered = _short_full(public_key_hex)

        self.assertEqual(rendered["full"], public_key_hex)
        self.assertEqual(rendered["short"], public_key_hex[:12])
        self.assertEqual(did_key_to_public_hex(rendered["did"]), public_key_hex)

    def test_placeholder_and_empty_identifiers_render_without_a_did(self):
        """Genesis' absent producer and readable test names must not raise."""
        self.assertEqual(_short_full(""), {"short": "", "full": "", "did": None})
        self.assertIsNone(_short_full("alice")["did"])


class TxSummaryTests(unittest.TestCase):
    def test_summary_shape_and_signature_flags(self):
        private_key, public_key_hex = generate_keypair()
        tx = make_submission(public_key_hex, "d", "r", "t", "aa", "n.pdf")
        tx.sign(private_key)

        summary = _tx_summary(tx)

        self.assertEqual(
            set(summary),
            {"hash", "type", "sender", "payload", "signed", "signature_valid",
             "protocol_generated"},
        )
        self.assertEqual(summary["hash"], tx.hash)
        self.assertEqual(summary["type"], "submission")
        self.assertEqual(
            summary["sender"],
            {
                "short": public_key_hex[:12],
                "full": public_key_hex,
                "did": public_key_to_did_key(public_key_hex),
            },
        )
        self.assertEqual(summary["payload"], tx.payload)
        self.assertTrue(summary["signed"])
        self.assertTrue(summary["signature_valid"])
        # A submission is participant-authored, not protocol-generated.
        self.assertFalse(summary["protocol_generated"])

    def test_unsigned_transaction_reports_invalid_signature(self):
        tx = make_attestation("n", "s", "r", 0, True, 1, "aa")
        summary = _tx_summary(tx)
        self.assertFalse(summary["signed"])
        self.assertFalse(summary["signature_valid"])

    def test_certificate_is_flagged_protocol_generated(self):
        """Certificates are exempt from signing, so the UI can label them honestly."""
        from attestation.aggregator import make_certificate

        summary = _tx_summary(make_certificate("s", "r", "d", "aa", ["a"]))
        self.assertEqual(summary["type"], "certificate")
        self.assertTrue(summary["protocol_generated"])
        self.assertFalse(summary["signed"])

    def test_status_omitted_without_a_status_map(self):
        """Non-chain contexts (mempool) pass no status map, so no ``status`` key."""
        summary = _tx_summary(make_certificate("s", "r", "d", "aa", ["a"]))
        self.assertNotIn("status", summary)

    def test_status_surfaced_when_present_in_the_map(self):
        cert = make_certificate("s", "r", "d", "aa", ["a"])
        summary = _tx_summary(cert, {cert.hash: "contested"})
        self.assertEqual(summary["status"], "contested")


class ChainPayloadStatusTests(unittest.TestCase):
    """The /api/chain payload surfaces each committed certificate's chain-derived
    contest status: "valid" until a contributing attester is slashed for its
    submission, then "contested"."""

    _SUB = "5ab" + "0" * 61
    _OFFENDER_PRIV, _OFFENDER = keypair_from_seed(bytes.fromhex("0f" * 32))
    _VALIDATOR_PRIV, _VALIDATOR = keypair_from_seed(bytes.fromhex("02" * 32))

    def _community(self, chain):
        return SimpleNamespace(blockchain=chain)

    def _cert_status(self, payload, cert_hash):
        for block in payload:
            for tx in block["transactions"]:
                if tx["hash"] == cert_hash:
                    return tx.get("status")
        return None

    def test_valid_then_contested_after_slash(self):
        anchor = {
            self._OFFENDER: {"bioinformatics": 100},
            self._VALIDATOR: {CONSENSUS_DOMAIN: 100},
        }
        chain = Blockchain(genesis=anchor)
        yes = make_attestation(
            self._OFFENDER, "subj", "rub", 0, True, 1, self._SUB, "bioinformatics"
        )
        yes.sign(self._OFFENDER_PRIV)
        no = make_attestation(
            self._OFFENDER, "subj", "rub", 0, False, 1, self._SUB, "bioinformatics"
        )
        no.sign(self._OFFENDER_PRIV)
        cert = make_certificate(
            "student", "rub", "bioinformatics", self._SUB, [self._OFFENDER]
        )
        chain.add_transaction(cert)
        chain.add_transaction(yes)
        chain.add_transaction(no)
        chain.add_block()

        # Before the slash: the bridge reports "valid".
        payload = _chain_payload(self._community(chain))
        self.assertEqual(self._cert_status(payload, cert.hash), "valid")

        evidence = sorted([yes.hash, no.hash])
        approvals = dict(
            [approve_slash(self._VALIDATOR_PRIV, self._OFFENDER, "bioinformatics", 40, evidence)]
        )
        chain.add_transaction(
            make_slash(self._OFFENDER, "bioinformatics", evidence, approvals, amount=40)
        )
        chain.add_block()

        # After the slash: the bridge reports "contested".
        payload = _chain_payload(self._community(chain))
        self.assertEqual(self._cert_status(payload, cert.hash), "contested")


if __name__ == "__main__":
    unittest.main()
