"""Unit tests for Reviewer Verifiable Credentials and proof of possession.

Covers the three layers independently of any node: canonicalization
(:mod:`credentials.jcs`), issuance/verification of the credential itself
(:mod:`credentials.vc`), and the possession proof plus its challenge store
(:mod:`credentials.presentation`). The gate that *uses* them — a node admitting
an attestation — is tested in :mod:`tests.test_credential_gate`.
"""

import copy
import unittest
from datetime import datetime, timedelta, timezone

from credentials.jcs import canonicalize
from credentials.presentation import (
    POP_CONTEXT,
    ChallengeStore,
    make_presentation,
    pop_signing_bytes,
    sign_challenge,
    verify_presentation,
)
from credentials.vc import (
    AUTHORITY_DID,
    CRYPTOSUITE,
    PROOF_PURPOSE,
    REVIEWER_CREDENTIAL_TYPE,
    TRUSTED_ISSUER_DIDS,
    VC_CONTEXT_V2,
    credential_signing_bytes,
    issue_reviewer_credential,
    verify_credential,
)
from crypto.did import (
    did_key_to_public_hex,
    did_key_verification_method,
    multibase_decode,
    public_key_to_did_key,
)
from crypto.keys import generate_keypair, keypair_from_seed

DOMAIN = "computer-science"


def holder():
    """A fresh holder: ``(private_key, public_key_hex, did:key)``."""
    private_key, public_key = generate_keypair()
    return private_key, public_key, public_key_to_did_key(public_key)


class JcsTests(unittest.TestCase):
    """RFC 8785 canonicalization — the bytes a credential is signed over."""

    def test_object_keys_are_sorted_and_whitespace_free(self):
        self.assertEqual(
            canonicalize({"b": 1, "a": [1, 2], "c": {"z": True, "y": None}}),
            b'{"a":[1,2],"b":1,"c":{"y":null,"z":true}}',
        )

    def test_key_order_of_the_input_dict_does_not_matter(self):
        self.assertEqual(
            canonicalize({"a": 1, "b": 2}), canonicalize({"b": 2, "a": 1})
        )

    def test_non_ascii_is_emitted_as_utf8_not_escaped(self):
        self.assertEqual(canonicalize({"k": "é"}), '{"k":"é"}'.encode("utf-8"))

    def test_booleans_are_not_serialized_as_integers(self):
        # bool is a subclass of int; "true" must not become "1".
        self.assertEqual(canonicalize([True, False, 1, 0]), b"[true,false,1,0]")

    def test_floats_are_refused(self):
        # Rather than risk a subtly wrong ECMAScript number format, floats are
        # simply not part of the canonicalizable subset (see credentials.jcs).
        with self.assertRaises(TypeError):
            canonicalize({"n": 1.5})


class IssuanceTests(unittest.TestCase):
    """The credential the GradED Authority mints has the W3C VC 2.0 shape."""

    def setUp(self):
        self.priv, self.pub, self.did = holder()
        self.credential = issue_reviewer_credential(self.did, [DOMAIN])

    def test_credential_has_vc2_context_and_reviewer_type(self):
        self.assertEqual(self.credential["@context"][0], VC_CONTEXT_V2)
        self.assertIn(REVIEWER_CREDENTIAL_TYPE, self.credential["type"])
        self.assertIn("VerifiableCredential", self.credential["type"])

    def test_issuer_is_the_authority_did_and_subject_is_the_holder_did(self):
        self.assertEqual(self.credential["issuer"], AUTHORITY_DID)
        subject = self.credential["credentialSubject"]
        self.assertEqual(subject["id"], self.did)
        self.assertEqual(subject["role"], "reviewer")
        self.assertEqual(subject["domains"], [DOMAIN])

    def test_subject_did_resolves_back_to_the_holder_key(self):
        # No registry, no lookup: the credential names the key it is bound to.
        self.assertEqual(
            did_key_to_public_hex(self.credential["credentialSubject"]["id"]), self.pub
        )

    def test_proof_is_a_data_integrity_eddsa_jcs_2022_proof(self):
        proof = self.credential["proof"]
        self.assertEqual(proof["type"], "DataIntegrityProof")
        self.assertEqual(proof["cryptosuite"], CRYPTOSUITE)
        self.assertEqual(proof["proofPurpose"], PROOF_PURPOSE)
        self.assertEqual(
            proof["verificationMethod"], did_key_verification_method(AUTHORITY_DID)
        )

    def test_proof_value_is_a_multibase_ed25519_signature(self):
        signature = multibase_decode(self.credential["proof"]["proofValue"])
        self.assertEqual(len(signature), 64)

    def test_validity_window_is_bounded(self):
        self.assertLess(
            self.credential["validFrom"], self.credential["validUntil"]
        )

    def test_domains_are_sorted_and_deduplicated(self):
        credential = issue_reviewer_credential(self.did, ["b", "a", "b"])
        self.assertEqual(credential["credentialSubject"]["domains"], ["a", "b"])

    def test_issuing_to_a_non_did_key_is_refused(self):
        with self.assertRaises(ValueError):
            issue_reviewer_credential("not-a-did", [DOMAIN])

    def test_issuing_without_a_domain_is_refused(self):
        with self.assertRaises(ValueError):
            issue_reviewer_credential(self.did, [])


class CredentialVerificationTests(unittest.TestCase):
    """What a verifier accepts — and the five ways a credential fails."""

    def setUp(self):
        self.priv, self.pub, self.did = holder()
        self.credential = issue_reviewer_credential(self.did, [DOMAIN])

    def test_a_freshly_issued_credential_verifies(self):
        ok, reason = verify_credential(self.credential)
        self.assertTrue(ok, reason)

    def test_credential_from_an_untrusted_issuer_is_rejected(self):
        """A self-issued credential is well-formed and worthless."""
        rogue_priv, rogue_pub = keypair_from_seed(bytes.fromhex("77" * 32))
        rogue_did = public_key_to_did_key(rogue_pub)
        forged = issue_reviewer_credential(
            self.did, [DOMAIN], issuer_private_key=rogue_priv, issuer_did=rogue_did
        )
        ok, reason = verify_credential(forged)
        self.assertFalse(ok)
        self.assertIn("not a trusted", reason)

    def test_credential_claiming_the_authority_but_signed_by_another_key_is_rejected(self):
        """Naming the trusted issuer is not the same as being it."""
        rogue_priv, _ = keypair_from_seed(bytes.fromhex("78" * 32))
        forged = issue_reviewer_credential(
            self.did,
            [DOMAIN],
            issuer_private_key=rogue_priv,
            issuer_did=AUTHORITY_DID,  # claims the authority's DID …
        )
        ok, reason = verify_credential(forged)  # … but cannot sign as it
        self.assertFalse(ok)
        self.assertIn("signature", reason)

    def test_expired_credential_is_rejected(self):
        past = datetime.now(timezone.utc) - timedelta(days=30)
        expired = issue_reviewer_credential(
            self.did,
            [DOMAIN],
            valid_from=past,
            valid_until=past + timedelta(days=1),
        )
        ok, reason = verify_credential(expired)
        self.assertFalse(ok)
        self.assertIn("expired", reason)

    def test_not_yet_valid_credential_is_rejected(self):
        future = datetime.now(timezone.utc) + timedelta(days=30)
        early = issue_reviewer_credential(
            self.did,
            [DOMAIN],
            valid_from=future,
            valid_until=future + timedelta(days=1),
        )
        ok, reason = verify_credential(early)
        self.assertFalse(ok)
        self.assertIn("not valid before", reason)

    def test_tampering_with_the_domains_breaks_the_signature(self):
        """The obvious attack: widen your own credential after it is issued."""
        tampered = copy.deepcopy(self.credential)
        tampered["credentialSubject"]["domains"].append("bioinformatics")
        ok, reason = verify_credential(tampered)
        self.assertFalse(ok)
        self.assertIn("signature", reason)

    def test_repointing_the_subject_at_another_key_breaks_the_signature(self):
        """A thief cannot re-address a stolen credential to their own DID."""
        _, _, thief_did = holder()
        stolen = copy.deepcopy(self.credential)
        stolen["credentialSubject"]["id"] = thief_did
        ok, _ = verify_credential(stolen)
        self.assertFalse(ok)

    def test_extending_the_expiry_breaks_the_signature(self):
        tampered = copy.deepcopy(self.credential)
        tampered["validUntil"] = "2099-01-01T00:00:00Z"
        ok, _ = verify_credential(tampered)
        self.assertFalse(ok)

    def test_changing_the_proof_purpose_breaks_the_signature(self):
        # The proof options are hashed into the signing bytes, so the proof cannot
        # be re-purposed (e.g. assertionMethod -> authentication).
        tampered = copy.deepcopy(self.credential)
        tampered["proof"]["proofPurpose"] = "authentication"
        ok, _ = verify_credential(tampered)
        self.assertFalse(ok)

    def test_a_credential_of_another_type_is_rejected(self):
        tampered = copy.deepcopy(self.credential)
        tampered["type"] = ["VerifiableCredential"]
        ok, reason = verify_credential(tampered)
        self.assertFalse(ok)
        self.assertIn("GradEDReviewerCredential", reason)

    def test_a_non_reviewer_role_is_rejected(self):
        tampered = copy.deepcopy(self.credential)
        tampered["credentialSubject"]["role"] = "examiner"
        ok, _ = verify_credential(tampered)
        self.assertFalse(ok)

    def test_garbage_is_rejected_without_raising(self):
        for value in (None, "credential", 42, [], {}):
            ok, _ = verify_credential(value)
            self.assertFalse(ok)

    def test_signing_bytes_are_two_concatenated_sha256_digests(self):
        proof = {k: v for k, v in self.credential["proof"].items() if k != "proofValue"}
        self.assertEqual(len(credential_signing_bytes(self.credential, proof)), 64)

    def test_the_default_trusted_issuer_is_the_graded_authority(self):
        self.assertEqual(set(TRUSTED_ISSUER_DIDS), {AUTHORITY_DID})


class PresentationTests(unittest.TestCase):
    """Proof of possession: holding the JSON is not holding the key."""

    def setUp(self):
        self.priv, self.pub, self.did = holder()
        self.credential = issue_reviewer_credential(self.did, [DOMAIN])
        self.presentation = make_presentation(self.priv, self.credential, "chal-1")

    def test_valid_presentation_is_accepted(self):
        ok, reason = verify_presentation(self.presentation, self.pub, DOMAIN)
        self.assertTrue(ok, reason)

    def test_stolen_credential_without_the_key_is_rejected(self):
        """The whole point: a copied VC JSON is useless to the thief.

        The thief holds the credential, signs their own attestation with their own
        key, and cannot produce the possession proof the credential's subject DID
        demands — they do not have that private key.
        """
        thief_priv, thief_pub, _ = holder()
        stolen = {
            "credential": self.credential,          # copied verbatim
            "challenge": "chal-1",
            "challenge_signature": sign_challenge(thief_priv, "chal-1", self.did),
        }
        ok, reason = verify_presentation(stolen, thief_pub, DOMAIN)
        self.assertFalse(ok)
        self.assertIn("not the attesting key", reason)

    def test_stolen_credential_replayed_as_the_victim_still_fails(self):
        """Even claiming to be the victim fails: the PoP signature will not verify."""
        thief_priv, _, _ = holder()
        stolen = {
            "credential": self.credential,
            "challenge": "chal-2",
            "challenge_signature": sign_challenge(thief_priv, "chal-2", self.did),
        }
        # sender is the victim's key (the thief pretends), but the signature is the
        # thief's — possession fails.
        ok, reason = verify_presentation(stolen, self.pub, DOMAIN)
        self.assertFalse(ok)
        self.assertIn("proof of possession failed", reason)

    def test_captured_signature_cannot_be_moved_to_another_challenge(self):
        replayed = dict(self.presentation, challenge="a-different-challenge")
        ok, reason = verify_presentation(replayed, self.pub, DOMAIN)
        self.assertFalse(ok)
        self.assertIn("proof of possession failed", reason)

    def test_credential_for_another_domain_is_rejected(self):
        ok, reason = verify_presentation(self.presentation, self.pub, "bioinformatics")
        self.assertFalse(ok)
        self.assertIn("bioinformatics", reason)

    def test_expired_credential_is_rejected_even_with_valid_possession(self):
        past = datetime.now(timezone.utc) - timedelta(days=10)
        expired = issue_reviewer_credential(
            self.did, [DOMAIN], valid_from=past, valid_until=past + timedelta(hours=1)
        )
        ok, reason = verify_presentation(
            make_presentation(self.priv, expired, "c"), self.pub, DOMAIN
        )
        self.assertFalse(ok)
        self.assertIn("expired", reason)

    def test_untrusted_issuer_is_rejected_even_with_valid_possession(self):
        rogue_priv, rogue_pub = keypair_from_seed(bytes.fromhex("79" * 32))
        self_issued = issue_reviewer_credential(
            self.did,
            [DOMAIN],
            issuer_private_key=rogue_priv,
            issuer_did=public_key_to_did_key(rogue_pub),
        )
        ok, reason = verify_presentation(
            make_presentation(self.priv, self_issued, "c"), self.pub, DOMAIN
        )
        self.assertFalse(ok)
        self.assertIn("not a trusted", reason)

    def test_missing_presentation_is_rejected(self):
        for value in (None, {}, "vc", 7):
            ok, _ = verify_presentation(value, self.pub, DOMAIN)
            self.assertFalse(ok)

    def test_presentation_without_a_challenge_signature_is_rejected(self):
        bare = {"credential": self.credential, "challenge": "chal-1"}
        ok, reason = verify_presentation(bare, self.pub, DOMAIN)
        self.assertFalse(ok)
        self.assertIn("challenge signature", reason)

    def test_pop_bytes_are_domain_separated_and_bound_to_the_holder(self):
        message = pop_signing_bytes("abc", self.did)
        self.assertTrue(message.startswith(POP_CONTEXT.encode()))
        self.assertIn(self.did.encode(), message)
        # A different holder signs different bytes for the same challenge, so a
        # possession proof can never be transplanted between identities.
        _, _, other_did = holder()
        self.assertNotEqual(message, pop_signing_bytes("abc", other_did))

    def test_a_transaction_signature_can_never_serve_as_a_possession_proof(self):
        # The PoP context prefix is what keeps the two signature roles disjoint.
        self.assertFalse(pop_signing_bytes("abc", self.did).startswith(b"{"))


class ChallengeStoreTests(unittest.TestCase):
    """Freshness: a challenge is issued once, spent once, and then gone."""

    def setUp(self):
        self.store = ChallengeStore(ttl=60)

    def test_issued_challenge_can_be_consumed_once(self):
        challenge = self.store.issue()["challenge"]
        self.assertTrue(self.store.consume(challenge))
        self.assertFalse(self.store.consume(challenge))  # single use

    def test_unknown_challenge_is_refused(self):
        self.assertFalse(self.store.consume("never-issued"))

    def test_expired_challenge_is_refused(self):
        challenge = self.store.issue(now=0)["challenge"]
        self.assertFalse(self.store.consume(challenge, now=1000))

    def test_challenges_are_unique_and_high_entropy(self):
        issued = {self.store.issue()["challenge"] for _ in range(50)}
        self.assertEqual(len(issued), 50)
        self.assertTrue(all(len(c) == 64 for c in issued))

    def test_non_string_challenge_is_refused(self):
        self.assertFalse(self.store.consume(None))
        self.assertFalse(self.store.consume(42))


if __name__ == "__main__":
    unittest.main()
