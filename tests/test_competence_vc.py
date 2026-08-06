"""Competence VCs — exporting a certificate the chain issued, and checking it later.

A certificate is a protocol fact locked inside this chain; a Competence VC is the
same fact in a form an employer's verifier can check without running a node. These
tests pin the three properties that make that safe:

* **the export is genuine** — it verifies against the *GradED Network* issuer key,
  and any edit to any signed field breaks it;
* **the export is backed** — a credential is linked to a committed certificate, and
  one that names a certificate this chain does not carry is reported as such;
* **the standing is live** — the signed document freezes, the chain does not, so
  status is resolved from the chain at verification time: valid, contested (a
  contributing attester was slashed for this submission afterwards), or revoked.

The chain fixtures mirror :mod:`tests.test_certificate_status`: a real submission,
a real certificate over it, and a real evidence-plus-quorum slash to contest it.
"""

import copy
import json
import unittest

from aiohttp.test_utils import TestClient, TestServer
from ipv8.test.base import TestBase

from attestation.aggregator import (
    CERTIFICATE_CONTESTED,
    certificate_id,
    make_certificate,
)
from attestation.attestation import make_attestation
from attestation.submission import make_submission
from blockchain.blockchain import Blockchain
from credentials.competence import (
    COMPETENCE_CREDENTIAL_TYPE,
    CREDENTIAL_URN_PREFIX,
    EVIDENCE_TYPE,
    NETWORK_DID,
    STATUS_CONTESTED,
    STATUS_REVOKED,
    STATUS_TYPE,
    STATUS_VALID,
    check_chain_linkage,
    credential_status,
    export_competence_credential,
    verify_competence_credential,
    verify_credential_report,
)
from credentials.jcs import canonicalize
from credentials.vc import CREDENTIAL_TYPE, VC_CONTEXT_V2, issue_reviewer_credential
from crypto.did import public_key_to_did_key
from crypto.keys import generate_keypair, keypair_from_seed
from network.community import AttestationCommunity, AttestationSettings
from network.http_bridge import (
    build_app,
    competence_credential_status,
    export_competence_vc,
    verify_competence_vc,
)
from reputation.genesis import CONSENSUS_DOMAIN
from reputation.slashing import approve_slash, make_slash

DOMAIN = "bioinformatics"
RUBRIC = "cafe" * 16
TITLE = "Draft manuscript"

# The learner the certificate is about; a reviewer who contributed to it (and can
# be caught equivocating); a validator who both produces blocks and approves slashes.
_LEARNER_PRIV, LEARNER = keypair_from_seed(bytes.fromhex("11" * 32))
_REVIEWER_PRIV, REVIEWER = keypair_from_seed(bytes.fromhex("0f" * 32))
_VALIDATOR_PRIV, VALIDATOR = keypair_from_seed(bytes.fromhex("02" * 32))


def _anchor() -> dict:
    """Reputation anchor: REVIEWER has competence, VALIDATOR has consensus authority."""
    return {
        REVIEWER: {DOMAIN: 100},
        VALIDATOR: {CONSENSUS_DOMAIN: 100},
    }


def certified_chain():
    """A chain holding a submission and a committed certificate over it.

    Returns ``(chain, submission_tx, certificate_tx)``. The certificate credits
    REVIEWER, is scoped to this exact submission, and is mined in block 1.
    """
    chain = Blockchain(genesis=_anchor())
    submission = make_submission(LEARNER, DOMAIN, RUBRIC, TITLE, "ab" * 32, "paper.pdf")
    submission.sign(_LEARNER_PRIV)
    chain.add_transaction(submission)
    chain.add_block()

    certificate = make_certificate(
        LEARNER, RUBRIC, DOMAIN, submission.hash, [REVIEWER], required_items=[]
    )
    chain.add_transaction(certificate)
    chain.add_block()
    return chain, submission, certificate


def contest(chain, submission_tx_hash: str) -> None:
    """Slash the crediting REVIEWER for equivocating on ``submission_tx_hash``.

    Mines the two contradictory attestations and, in a later block, a genuine
    evidence-plus-quorum slash — the only thing that flips a committed certificate
    to "contested" (:func:`attestation.aggregator.certificate_statuses`).
    """
    yes = make_attestation(
        REVIEWER, LEARNER, RUBRIC, 0, True, 1, submission_tx_hash, DOMAIN
    )
    yes.sign(_REVIEWER_PRIV)
    no = make_attestation(
        REVIEWER, LEARNER, RUBRIC, 0, False, 1, submission_tx_hash, DOMAIN
    )
    no.sign(_REVIEWER_PRIV)
    chain.add_transaction(yes)
    chain.add_transaction(no)
    chain.add_block()

    evidence = sorted([yes.hash, no.hash])
    approvals = dict([approve_slash(_VALIDATOR_PRIV, REVIEWER, DOMAIN, 40, evidence)])
    chain.add_transaction(make_slash(REVIEWER, DOMAIN, evidence, approvals, amount=40))
    chain.add_block()


class ExportTests(unittest.TestCase):
    """What a certificate becomes when it leaves the chain."""

    def test_exported_credential_verifies_against_the_issuer_key(self):
        chain, _submission, certificate = certified_chain()

        credential = export_competence_credential(chain, certificate.hash)

        ok, reason = verify_competence_credential(credential)
        self.assertTrue(ok, reason)
        self.assertEqual(credential["issuer"], NETWORK_DID)

    def test_document_shape_names_the_learner_and_its_chain_evidence(self):
        chain, submission, certificate = certified_chain()
        cert_id = certificate_id(certificate.payload)

        credential = export_competence_credential(
            chain, cert_id, base_url="http://127.0.0.1:8090"
        )

        self.assertEqual(credential["@context"][0], VC_CONTEXT_V2)
        self.assertEqual(
            credential["type"], [CREDENTIAL_TYPE, COMPETENCE_CREDENTIAL_TYPE]
        )
        self.assertEqual(credential["id"], CREDENTIAL_URN_PREFIX + cert_id)
        # The subject is the learner's key as a did:key — no name, no email, no
        # institution anywhere in the document.
        self.assertEqual(
            credential["credentialSubject"]["id"], public_key_to_did_key(LEARNER)
        )
        self.assertEqual(
            credential["credentialSubject"]["competence"], f"{DOMAIN}/{TITLE}"
        )
        # Evidence walks back to the exact protocol facts.
        evidence = credential["evidence"][0]
        self.assertEqual(evidence["type"], EVIDENCE_TYPE)
        self.assertEqual(evidence["certificateId"], cert_id)
        self.assertEqual(evidence["submissionTransaction"], submission.hash)
        self.assertEqual(evidence["rubricRoot"], RUBRIC)
        self.assertEqual(evidence["finalizedBlock"]["index"], 2)
        self.assertEqual(evidence["finalizedBlock"]["hash"], chain.blocks[2].hash)
        # And the status pointer is a URL, not a frozen answer.
        self.assertEqual(credential["credentialStatus"]["type"], STATUS_TYPE)
        self.assertEqual(
            credential["credentialStatus"]["id"],
            f"http://127.0.0.1:8090/api/credentials/{cert_id}/status",
        )

    def test_export_is_idempotent(self):
        """Every signed field derives from the chain, so re-exporting is identical —
        a holder can re-download without invalidating the copy someone already has."""
        chain, _submission, certificate = certified_chain()

        first = export_competence_credential(chain, certificate.hash)
        second = export_competence_credential(chain, certificate.hash)

        self.assertEqual(canonicalize(first), canonicalize(second))

    def test_export_accepts_either_identifier(self):
        chain, _submission, certificate = certified_chain()
        by_hash = export_competence_credential(chain, certificate.hash)
        by_id = export_competence_credential(
            chain, certificate_id(certificate.payload)
        )
        self.assertEqual(canonicalize(by_hash), canonicalize(by_id))

    def test_exporting_writes_nothing_to_the_chain(self):
        """Export is a read plus a signature: no transaction, no block, no mempool
        entry — and no credential data anywhere on-chain."""
        chain, _submission, certificate = certified_chain()
        before = (len(chain.blocks), len(chain.mempool))

        credential = export_competence_credential(chain, certificate.hash)

        self.assertEqual((len(chain.blocks), len(chain.mempool)), before)
        chain_json = json.dumps([b.to_dict() for b in chain.blocks])
        for marker in (COMPETENCE_CREDENTIAL_TYPE, NETWORK_DID, "proofValue",
                       credential["proof"]["proofValue"]):
            self.assertNotIn(marker, chain_json)

    def test_unknown_certificate_cannot_be_exported(self):
        chain, _submission, _certificate = certified_chain()
        with self.assertRaises(LookupError):
            export_competence_credential(chain, "ff" * 32)

    def test_subject_without_a_did_key_is_refused(self):
        """A certificate whose subject is not an Ed25519 key has no subject DID, and
        a credential nobody could verify is worse than no credential."""
        chain = Blockchain(genesis=_anchor())
        chain.add_transaction(
            make_certificate("not-a-key", RUBRIC, DOMAIN, "aa", [REVIEWER])
        )
        chain.add_block()
        with self.assertRaises(ValueError):
            export_competence_credential(chain, chain.blocks[1].transactions[0].hash)


class TamperTests(unittest.TestCase):
    """Every signed field is signed: editing one breaks the issuer's proof."""

    def setUp(self):
        self.chain, self.submission, self.certificate = certified_chain()
        self.credential = export_competence_credential(self.chain, self.certificate.hash)

    def _tampered(self, mutate):
        forged = copy.deepcopy(self.credential)
        mutate(forged)
        return forged

    def test_tampering_the_competence_fails_verification(self):
        forged = self._tampered(
            lambda c: c["credentialSubject"].__setitem__(
                "competence", "quantum-computing/Nobel-grade work"
            )
        )
        ok, reason = verify_competence_credential(forged)
        self.assertFalse(ok)
        self.assertIn("signature", reason)

    def test_repointing_the_subject_fails_verification(self):
        """Stealing a credential by putting your own DID in it breaks the signature."""
        _priv, thief = generate_keypair()
        forged = self._tampered(
            lambda c: c["credentialSubject"].__setitem__(
                "id", public_key_to_did_key(thief)
            )
        )
        self.assertFalse(verify_competence_credential(forged)[0])

    def test_tampering_the_evidence_fails_verification(self):
        forged = self._tampered(
            lambda c: c["evidence"][0].__setitem__("certificateId", "ff" * 32)
        )
        self.assertFalse(verify_competence_credential(forged)[0])

    def test_swapping_the_status_url_fails_verification(self):
        """The status *pointer* is signed, so a forger cannot redirect a verifier to
        a status endpoint of their own choosing."""
        forged = self._tampered(
            lambda c: c["credentialStatus"].__setitem__(
                "id", "http://evil.example/api/credentials/x/status"
            )
        )
        self.assertFalse(verify_competence_credential(forged)[0])

    def test_tampering_the_proof_metadata_fails_verification(self):
        """Proof options are hashed into the signed bytes, so the purpose cannot be
        swapped either."""
        forged = self._tampered(
            lambda c: c["proof"].__setitem__("proofPurpose", "authentication")
        )
        self.assertFalse(verify_competence_credential(forged)[0])

    def test_self_issued_credential_is_not_trusted(self):
        """A well-formed credential signed by somebody else's key is still refused —
        trust is in the issuer DID, not in the document being pretty."""
        impostor_priv, impostor_pub = generate_keypair()
        forged = export_competence_credential(
            self.chain,
            self.certificate.hash,
            issuer_private_key=impostor_priv,
            issuer_did=public_key_to_did_key(impostor_pub),
        )
        ok, reason = verify_competence_credential(forged)
        self.assertFalse(ok)
        self.assertIn("not a trusted", reason)

    def test_a_reviewer_credential_is_not_a_competence_credential(self):
        """The two credential types are separate powers; one must never pass as the
        other, even though both are signed in the same cryptosuite."""
        reviewer_vc = issue_reviewer_credential(
            public_key_to_did_key(LEARNER), [DOMAIN]
        )
        ok, reason = verify_competence_credential(reviewer_vc)
        self.assertFalse(ok)
        self.assertIn("GradEDCompetenceCredential", reason)


class StatusTests(unittest.TestCase):
    """The live status endpoint's answer is the chain's, not the document's."""

    def test_status_of_an_uncontested_certificate_is_valid(self):
        chain, _submission, certificate = certified_chain()
        cert_id = certificate_id(certificate.payload)

        status = credential_status(chain, cert_id)

        self.assertEqual(status["status"], STATUS_VALID)
        self.assertEqual(status["credentialId"], CREDENTIAL_URN_PREFIX + cert_id)
        self.assertEqual(status["evidence"]["certificateId"], cert_id)
        self.assertTrue(status["updatedAt"].endswith("Z"))

    def test_status_follows_the_chain_to_contested(self):
        """The same credential, unchanged, reads contested once a contributing
        attester is slashed for its submission — because the answer is re-derived."""
        chain, submission, certificate = certified_chain()
        cert_id = certificate_id(certificate.payload)
        self.assertEqual(credential_status(chain, cert_id)["status"], STATUS_VALID)

        contest(chain, submission.hash)

        self.assertEqual(credential_status(chain, cert_id)["status"], STATUS_CONTESTED)
        # And it is exactly the chain-derived certificate status, not a parallel rule.
        self.assertEqual(STATUS_CONTESTED, CERTIFICATE_CONTESTED)

    def test_status_accepts_the_urn_and_the_transaction_hash(self):
        chain, _submission, certificate = certified_chain()
        cert_id = certificate_id(certificate.payload)
        for identifier in (cert_id, CREDENTIAL_URN_PREFIX + cert_id, certificate.hash):
            self.assertEqual(
                credential_status(chain, identifier)["credentialId"],
                CREDENTIAL_URN_PREFIX + cert_id,
                identifier,
            )

    def test_unbacked_credential_is_revoked(self):
        """No committed certificate backs it, so it has no standing here at all."""
        chain, _submission, _certificate = certified_chain()

        status = credential_status(chain, "ff" * 32)

        self.assertEqual(status["status"], STATUS_REVOKED)
        self.assertIsNone(status["evidence"])


class VerifierReportTests(unittest.TestCase):
    """What the verifier page shows: four checks plus the live status."""

    def _checks(self, report):
        return {c["check"]: c["ok"] for c in report["checks"]}

    def test_a_genuine_credential_passes_every_check(self):
        chain, _submission, certificate = certified_chain()
        credential = export_competence_credential(chain, certificate.hash)

        report = verify_credential_report(chain, credential)

        self.assertTrue(report["verified"])
        self.assertEqual(
            self._checks(report),
            {"issuer": True, "signature": True, "subject": True, "chain": True},
        )
        self.assertEqual(report["status"], STATUS_VALID)
        self.assertEqual(report["subject"], public_key_to_did_key(LEARNER))
        self.assertEqual(report["competence"], f"{DOMAIN}/{TITLE}")

    def test_a_contested_certificates_credential_shows_contested(self):
        """The document still verifies — it was honestly issued — but the standing
        of the attestations behind it has changed, and the verifier says so."""
        chain, submission, certificate = certified_chain()
        credential = export_competence_credential(chain, certificate.hash)
        contest(chain, submission.hash)

        report = verify_credential_report(chain, credential)

        self.assertEqual(report["status"], STATUS_CONTESTED)
        self.assertTrue(self._checks(report)["signature"])
        self.assertTrue(self._checks(report)["chain"])

    def test_a_tampered_credential_fails_the_signature_check(self):
        chain, _submission, certificate = certified_chain()
        credential = export_competence_credential(chain, certificate.hash)
        credential["credentialSubject"]["competence"] = "astrophysics/forged"

        report = verify_credential_report(chain, credential)

        self.assertFalse(report["verified"])
        self.assertFalse(self._checks(report)["signature"])

    def test_a_credential_this_chain_does_not_back_fails_linkage(self):
        """Exported from one network, presented to another: the signature is fine,
        the chain link is not — and the status is revoked."""
        source, _submission, certificate = certified_chain()
        credential = export_competence_credential(source, certificate.hash)
        other_chain = Blockchain(genesis=_anchor())

        report = verify_credential_report(other_chain, credential)

        self.assertFalse(report["verified"])
        self.assertTrue(self._checks(report)["signature"])
        self.assertFalse(self._checks(report)["chain"])
        self.assertEqual(report["status"], STATUS_REVOKED)

    def test_chain_linkage_checks_every_exported_protocol_claim(self):
        """A chain link means more than finding one hash: the portable claims and
        block coordinates must still describe that exact certificate."""
        chain, _submission, certificate = certified_chain()
        credential = export_competence_credential(chain, certificate.hash)

        mutations = (
            lambda c: c.__setitem__("id", CREDENTIAL_URN_PREFIX + "ff" * 32),
            lambda c: c["credentialSubject"].__setitem__(
                "competence", "astrophysics/forged"
            ),
            lambda c: c["evidence"][0]["finalizedBlock"].__setitem__("index", 999),
            lambda c: c["evidence"][0]["finalizedBlock"].__setitem__(
                "finalized", not c["evidence"][0]["finalizedBlock"]["finalized"]
            ),
        )
        for mutate in mutations:
            forged = copy.deepcopy(credential)
            mutate(forged)
            self.assertFalse(check_chain_linkage(chain, forged)[0], forged)

    def test_garbage_input_is_reported_not_raised(self):
        chain, _submission, _certificate = certified_chain()
        for junk in ({}, {"credentialSubject": "nope"}, {"type": ["Whatever"]}):
            report = verify_credential_report(chain, junk)
            self.assertFalse(report["verified"], junk)


class CompetenceEndpointTests(TestBase):
    """The three HTTP routes: export, live status, verify."""

    def setUp(self):
        super().setUp()
        self.chain, self.submission, self.certificate = certified_chain()
        self.cert_id = certificate_id(self.certificate.payload)
        self.overlay_class = AttestationCommunity
        self.nodes = [self.create_node(AttestationSettings(blockchain=self.chain))]
        self.patch_overlays(0)

    async def _client(self):
        app = build_app(None, self.overlay(0), ws_interval=1000)
        client = TestClient(TestServer(app))
        await client.start_server()
        return client

    async def test_export_helper_returns_a_verifiable_credential(self):
        status, result = export_competence_vc(self.overlay(0), self.cert_id)

        self.assertEqual(status, 200)
        self.assertEqual(result["issuer"]["did"], NETWORK_DID)
        self.assertTrue(verify_competence_credential(result["credential"])[0])

    async def test_export_helper_reports_missing_and_unusable_certificates(self):
        self.assertEqual(export_competence_vc(self.overlay(0), "ff" * 32)[0], 404)

    async def test_status_helper_is_always_answerable(self):
        ok_status, body = competence_credential_status(self.overlay(0), self.cert_id)
        self.assertEqual((ok_status, body["status"]), (200, STATUS_VALID))

        missing_status, missing = competence_credential_status(
            self.overlay(0), "ff" * 32
        )
        self.assertEqual((missing_status, missing["status"]), (200, STATUS_REVOKED))

    async def test_verify_helper_accepts_the_export_envelope_unmodified(self):
        _status, exported = export_competence_vc(self.overlay(0), self.cert_id)

        # The whole downloaded body …
        status, wrapped = verify_competence_vc(self.overlay(0), exported)
        # … and the bare credential inside it.
        _s, bare = verify_competence_vc(self.overlay(0), exported["credential"])

        self.assertEqual(status, 200)
        self.assertTrue(wrapped["verified"])
        self.assertTrue(bare["verified"])
        self.assertEqual(verify_competence_vc(self.overlay(0), "nope")[0], 400)

    async def test_http_export_status_and_verify_round_trip(self):
        """The full holder journey over real HTTP: export a credential, follow its
        own credentialStatus URL, and hand the file back to a verifier."""
        client = await self._client()
        try:
            exported = await client.get(f"/api/credentials/competence/{self.cert_id}")
            self.assertEqual(exported.status, 200)
            credential = (await exported.json())["credential"]

            # The credential's own status URL is the route it points at.
            status_path = credential["credentialStatus"]["id"].split("/api/", 1)[1]
            status = await (await client.get("/api/" + status_path)).json()
            self.assertEqual(status["status"], STATUS_VALID)
            self.assertEqual(
                status["credentialId"], CREDENTIAL_URN_PREFIX + self.cert_id
            )

            verified = await (
                await client.post("/api/credentials/verify", json=credential)
            ).json()
            self.assertTrue(verified["verified"])

            # POST works for export too (browser download habits), and the
            # certificate transaction hash names the same credential.
            by_post = await client.post(
                f"/api/credentials/competence/{self.certificate.hash}"
            )
            self.assertEqual(
                (await by_post.json())["credential"]["id"], credential["id"]
            )
        finally:
            await client.close()

    async def test_http_status_tracks_a_later_contest(self):
        """A downloaded credential does not change; what it resolves to does."""
        client = await self._client()
        try:
            contest(self.chain, self.submission.hash)
            status = await (
                await client.get(f"/api/credentials/{self.cert_id}/status")
            ).json()
            self.assertEqual(status["status"], STATUS_CONTESTED)

            credential = (
                await (
                    await client.get(f"/api/credentials/competence/{self.cert_id}")
                ).json()
            )["credential"]
            report = await (
                await client.post("/api/credentials/verify", json=credential)
            ).json()
            self.assertEqual(report["status"], STATUS_CONTESTED)
        finally:
            await client.close()

    async def test_issuer_route_publishes_the_competence_issuer(self):
        """A verifier needs the trusted issuer DID from the node, never hardcoded."""
        client = await self._client()
        try:
            issuer = await (await client.get("/api/credentials/issuer")).json()
            self.assertEqual(issuer["competence_issuer"]["did"], NETWORK_DID)
            self.assertIn(NETWORK_DID, issuer["trusted_competence_issuers"])
            self.assertEqual(
                issuer["competence_credential_type"], COMPETENCE_CREDENTIAL_TYPE
            )
        finally:
            await client.close()

    async def test_submissions_payload_carries_the_certificate_id_to_export(self):
        """The UI's export button needs the certificate's scope id from the panel."""
        client = await self._client()
        try:
            subs = await (await client.get("/api/submissions")).json()
            entry = next(
                s for s in subs if s["submission_tx_hash"] == self.submission.hash
            )
            self.assertEqual(entry["certificate"]["certificate_id"], self.cert_id)
        finally:
            await client.close()


if __name__ == "__main__":
    unittest.main()
