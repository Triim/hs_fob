"""Tests for the chain-derived certificate contest status.

A certificate is an **immutable historical fact**: it is never deleted or
rewritten, and the reputation reward it credited is never clawed back. But when a
contributing attester is *later* successfully slashed (evidence + quorum) for the
very submission the certificate certifies, the certificate deterministically
transitions to a "contested" status — derived from the chain, not stored, so it
is identical on every node. These tests pin that policy.
"""

import unittest

from attestation.aggregator import (
    CERTIFICATE_CONTESTED,
    CERTIFICATE_VALID,
    certificate_statuses,
    make_certificate,
)
from attestation.attestation import make_attestation
from blockchain.blockchain import Blockchain
from crypto.keys import keypair_from_seed
from reputation.genesis import CONSENSUS_DOMAIN
from reputation.slashing import approve_slash, make_slash

SUBJECT = "student-pubkey"
RUBRIC = "rubric-root-hex"
DOMAIN = "bioinformatics"
SUB = "5ab" + "0" * 61
OTHER_SUB = "5cd" + "0" * 61

# An OFFENDER who reviews (and may equivocate) and a VALIDATOR who both produces
# blocks and approves slashes — mirroring the evidence + quorum model.
_OFFENDER_PRIV, OFFENDER = keypair_from_seed(bytes.fromhex("0f" * 32))
_VALIDATOR_PRIV, VALIDATOR = keypair_from_seed(bytes.fromhex("02" * 32))


def _anchor() -> dict:
    """Anchor giving OFFENDER competence and VALIDATOR sole consensus authority."""
    return {
        OFFENDER: {DOMAIN: 100},
        VALIDATOR: {CONSENSUS_DOMAIN: 100},
    }


def _mine(chain: Blockchain, *transactions) -> None:
    for tx in transactions:
        chain.add_transaction(tx)
    chain.add_block()


def _equivocation(submission_tx_hash: str = SUB):
    """OFFENDER's two contradictory attestations on one claim, bound to a submission."""
    yes = make_attestation(OFFENDER, "subj", "rub", 0, True, 1, submission_tx_hash, DOMAIN)
    yes.sign(_OFFENDER_PRIV)
    no = make_attestation(OFFENDER, "subj", "rub", 0, False, 1, submission_tx_hash, DOMAIN)
    no.sign(_OFFENDER_PRIV)
    return yes, no


def _slash_tx(evidence: list[str]):
    """A valid, quorum-approved slash of OFFENDER referencing ``evidence``."""
    evidence = sorted(evidence)
    approvals = dict([approve_slash(_VALIDATOR_PRIV, OFFENDER, DOMAIN, 40, evidence)])
    return make_slash(OFFENDER, DOMAIN, evidence, approvals, amount=40)


class CertificateStatusTests(unittest.TestCase):
    def test_certificate_with_no_slash_is_valid(self):
        """A certificate whose attesters are never slashed is valid."""
        chain = Blockchain(genesis=_anchor())
        cert = make_certificate(SUBJECT, RUBRIC, DOMAIN, SUB, [OFFENDER])
        _mine(chain, cert)

        statuses = certificate_statuses(chain)

        self.assertEqual(statuses, {cert.hash: CERTIFICATE_VALID})

    def test_slashing_contributing_attester_contests(self):
        """A later valid slash of a granted_by attester, bound to the certificate's
        submission, flips its status to contested — deterministically."""
        chain = Blockchain(genesis=_anchor())
        yes, no = _equivocation(SUB)
        cert = make_certificate(SUBJECT, RUBRIC, DOMAIN, SUB, [OFFENDER])
        # Block 1: the certificate is issued alongside the offender's equivocation.
        _mine(chain, cert, yes, no)
        # It is valid until the slash lands.
        self.assertEqual(certificate_statuses(chain)[cert.hash], CERTIFICATE_VALID)

        # Block 2 (after issuance): the offender is slashed for that same submission.
        _mine(chain, _slash_tx([yes.hash, no.hash]))

        self.assertEqual(certificate_statuses(chain)[cert.hash], CERTIFICATE_CONTESTED)

    def test_status_is_a_pure_function_of_the_chain(self):
        """The status derives only from the chain, so every node computes it
        identically — recomputing, and re-deriving on a rebuilt chain, agree."""
        anchor = _anchor()
        chain = Blockchain(genesis=anchor)
        yes, no = _equivocation(SUB)
        cert = make_certificate(SUBJECT, RUBRIC, DOMAIN, SUB, [OFFENDER])
        _mine(chain, cert, yes, no)
        _mine(chain, _slash_tx([yes.hash, no.hash]))

        first = certificate_statuses(chain)
        # Same chain, computed again — no hidden state, so identical.
        self.assertEqual(first, certificate_statuses(chain))

        # A second node reconstructs the chain from the same blocks + anchor and
        # must derive the very same status (contested).
        other_node = Blockchain(genesis=anchor)
        other_node.blocks = list(chain.blocks)
        self.assertEqual(certificate_statuses(other_node), first)
        self.assertEqual(first[cert.hash], CERTIFICATE_CONTESTED)

    def test_unrelated_slash_does_not_contest(self):
        """Slashing an attester who did NOT contribute to the certificate leaves it
        valid — the offender is not among its granted_by."""
        chain = Blockchain(genesis=_anchor())
        # The certificate credits VALIDATOR, not OFFENDER.
        cert = make_certificate(SUBJECT, RUBRIC, DOMAIN, SUB, [VALIDATOR])
        yes, no = _equivocation(SUB)
        _mine(chain, cert, yes, no)
        _mine(chain, _slash_tx([yes.hash, no.hash]))  # slashes OFFENDER, not credited

        self.assertEqual(certificate_statuses(chain)[cert.hash], CERTIFICATE_VALID)

    def test_slash_for_a_different_submission_does_not_contest(self):
        """A contributing attester slashed for a *different* submission does not
        contest this certificate — the dishonesty was not on this piece of work."""
        chain = Blockchain(genesis=_anchor())
        cert = make_certificate(SUBJECT, RUBRIC, DOMAIN, SUB, [OFFENDER])
        # The equivocation is bound to OTHER_SUB, not the certificate's SUB.
        yes, no = _equivocation(OTHER_SUB)
        _mine(chain, cert, yes, no)
        _mine(chain, _slash_tx([yes.hash, no.hash]))

        self.assertEqual(certificate_statuses(chain)[cert.hash], CERTIFICATE_VALID)

    def test_slash_before_issuance_does_not_contest(self):
        """Only a slash committed *after* the certificate contests it (the
        after-issuance clause): a slash in an earlier block leaves it valid."""
        chain = Blockchain(genesis=_anchor())
        yes, no = _equivocation(SUB)
        # Block 1: evidence + slash land BEFORE the certificate is issued.
        _mine(chain, yes, no, _slash_tx([yes.hash, no.hash]))
        cert = make_certificate(SUBJECT, RUBRIC, DOMAIN, SUB, [OFFENDER])
        _mine(chain, cert)  # block 2: issued after the slash

        self.assertEqual(certificate_statuses(chain)[cert.hash], CERTIFICATE_VALID)


if __name__ == "__main__":
    unittest.main()
