"""Reviewer Verifiable Credentials — issuance and verification.

A **Reviewer VC** is a W3C-VC-2.0-shaped document in which a trusted issuer (the
demo's *GradED Authority*) says: *the key named by this ``did:key`` may act as a
reviewer in these domains, until this date*. It is signed with the issuer's
Ed25519 key over the JCS-canonicalized document (:mod:`credentials.jcs`), in the
``eddsa-jcs-2022`` Data Integrity style.

What a credential is — and is not
---------------------------------
The credential is an **eligibility** statement and nothing more:

* it decides **whether** a key may submit an attestation in a domain;
* it does **not** decide what that attestation is worth — that is reputation
  weight, derived from the chain (:mod:`reputation.tally`), and it is computed
  exactly the same whether the reviewer holds a credential or not;
* it does **not** confer validator authority — the right to produce and commit
  blocks is CONSENSUS_DOMAIN weight (:mod:`reputation.genesis`), a separate
  chain-derived quantity. Eligibility to review and authority to validate are
  deliberately different powers held by different mechanisms.

Where it lives
--------------
**Off-chain, always.** The full credential JSON never enters a transaction
payload, a block, or the mempool — it travels only in the request envelope a
holder presents to a node (see :mod:`credentials.presentation`), which is why
adding credentials required no change to any transaction or consensus format,
and why no personal data about a reviewer is ever written to the chain. The
credential subject is a ``did:key`` — i.e. the reviewer's own public key — so
even the credential itself carries no name, email, or institution.

Document shape
--------------
::

    {
      "@context": ["https://www.w3.org/ns/credentials/v2", <graded context>],
      "type": ["VerifiableCredential", "GradEDReviewerCredential"],
      "issuer": "did:key:z…",                       # the GradED Authority
      "validFrom": "2026-08-04T00:00:00Z",
      "validUntil": "2027-08-04T00:00:00Z",
      "credentialSubject": {
        "id": "did:key:z…",                         # the reviewer's key
        "role": "reviewer",
        "domains": ["computer-science", …]
      },
      "proof": {
        "type": "DataIntegrityProof",
        "cryptosuite": "eddsa-jcs-2022",
        "created": "2026-08-04T00:00:00Z",
        "verificationMethod": "did:key:z…#z…",
        "proofPurpose": "assertionMethod",
        "proofValue": "z…"                          # multibase Ed25519 signature
      }
    }

Signing bytes follow the cryptosuite: the signature covers
``sha256(JCS(proof options))`` ‖ ``sha256(JCS(credential without proof))``, so
the proof's own metadata (its purpose, its verification method, its creation
time) is bound into the signature and cannot be swapped out for another.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone

from credentials.jcs import canonicalize
from crypto.did import (
    did_key_to_public_hex,
    did_key_verification_method,
    multibase_decode,
    multibase_encode,
    public_key_to_did_key,
)
from crypto.keys import keypair_from_seed, sign, verify

# The W3C VC 2.0 context every verifiable credential must carry first, plus a
# project context naming the GradED-specific terms. The second entry is a URN,
# not a dereferenceable URL: nothing here resolves JSON-LD (the cryptosuite is
# JCS-based, so no RDF processing happens at any point) — it is a namespace
# label, and we neither fetch it nor require a verifier to.
VC_CONTEXT_V2 = "https://www.w3.org/ns/credentials/v2"
GRADED_CONTEXT = "urn:graded:credentials:v1"

CREDENTIAL_TYPE = "VerifiableCredential"
REVIEWER_CREDENTIAL_TYPE = "GradEDReviewerCredential"

# The one role this credential grants. Named explicitly so a future credential
# type (an "issuer" or "examiner" credential, say) cannot be silently accepted by
# the reviewer gate just because it is signed by the same authority.
REVIEWER_ROLE = "reviewer"

PROOF_TYPE = "DataIntegrityProof"
CRYPTOSUITE = "eddsa-jcs-2022"
PROOF_PURPOSE = "assertionMethod"

# The demo's trusted issuer. Derived from a fixed 32-byte seed exactly like the
# genesis authorities (:mod:`reputation.genesis`), so every node, test and demo
# run reproduces the *same* authority DID without shipping a key file. A real
# deployment would hold this key in an HSM at the accrediting body and publish
# only the DID; nodes need nothing but the DID to verify.
_GRADED_AUTHORITY_SEED = bytes.fromhex("9a" * 32)
AUTHORITY_KEYPAIR = keypair_from_seed(_GRADED_AUTHORITY_SEED)
AUTHORITY_PRIVATE_KEY, AUTHORITY_PUBLIC_HEX = AUTHORITY_KEYPAIR
AUTHORITY_DID = public_key_to_did_key(AUTHORITY_PUBLIC_HEX)
AUTHORITY_NAME = "GradED Authority"

# The issuers a node accepts reviewer credentials from. A set, because trust in
# issuers is plural and revocable configuration — not a protocol constant: a
# node operator could add a second accrediting body without touching consensus,
# since credentials are an admission-time policy and never enter the chain.
TRUSTED_ISSUER_DIDS: frozenset[str] = frozenset({AUTHORITY_DID})

# How long an issued reviewer credential is valid for by default. Bounded rather
# than eternal so eligibility has to be renewed, which is the only revocation
# mechanism this step needs (a status-list credential is the obvious extension).
DEFAULT_VALIDITY_DAYS = 365


def _utc_now() -> datetime:
    """Current UTC time, truncated to whole seconds (credential times are ISO-Z)."""
    return datetime.now(timezone.utc).replace(microsecond=0)


def _iso(moment: datetime) -> str:
    """Render ``moment`` as an XML-schema/ISO-8601 UTC timestamp ending in ``Z``."""
    return moment.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def parse_iso(text: str) -> datetime | None:
    """Parse an ISO-8601 timestamp (``Z`` or offset) to an aware UTC datetime.

    Returns ``None`` — never raises — for anything unparseable, so verification
    can treat a malformed date as "invalid credential" rather than crashing on
    hostile input.
    """
    if not isinstance(text, str):
        return None
    try:
        moment = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc)


def credential_signing_bytes(credential: dict, proof_options: dict) -> bytes:
    """The bytes an ``eddsa-jcs-2022`` proof signs for ``credential``.

    Per the cryptosuite: the SHA-256 of the canonical proof options, followed by
    the SHA-256 of the canonical credential *without* its ``proof``. Hashing the
    two halves separately and concatenating binds the proof metadata to the
    document while keeping each half independently canonical — so an attacker can
    neither move a valid proof onto a different credential nor re-purpose it
    (e.g. from ``assertionMethod`` to ``authentication``) without invalidating it.
    """
    unsecured = {k: v for k, v in credential.items() if k != "proof"}
    options = {k: v for k, v in proof_options.items() if k != "proofValue"}
    return (
        hashlib.sha256(canonicalize(options)).digest()
        + hashlib.sha256(canonicalize(unsecured)).digest()
    )


def issue_reviewer_credential(
    subject_did: str,
    domains: list[str],
    *,
    issuer_private_key=AUTHORITY_PRIVATE_KEY,
    issuer_did: str = AUTHORITY_DID,
    validity_days: int = DEFAULT_VALIDITY_DAYS,
    valid_from: datetime | None = None,
    valid_until: datetime | None = None,
) -> dict:
    """Issue a signed Reviewer VC to ``subject_did`` for ``domains``.

    Args:
        subject_did: The reviewer's ``did:key`` — i.e. their Ed25519 public key,
            self-certifying and resolvable with no registry. The credential is
            bound to *this key*, which is what makes proof-of-possession possible
            (:mod:`credentials.presentation`).
        domains: The competence domains the holder may review in. Non-empty; each
            attestation is later checked against this list, so a credential for
            ``computer-science`` grants nothing in ``bioinformatics``.
        issuer_private_key: The issuer's Ed25519 signing key. Defaults to the demo
            GradED Authority. **The holder's key is never involved in issuance** —
            the node signs as the issuer only, and no participant private key is
            ever held by the backend.
        validity_days: Lifetime, used when ``valid_until`` is not given explicitly.
        valid_from / valid_until: Explicit validity window, mainly so tests can
            mint an already-expired or not-yet-valid credential.

    Returns:
        The credential as a plain ``dict`` — ready to be stored by the holder
        (in their browser) and presented later. It is never persisted on the node
        and never written to the chain.

    Raises:
        ValueError: If ``subject_did`` is not an Ed25519 ``did:key`` or ``domains``
            is empty / not a list of non-empty strings. Issuing a credential no
            verifier could ever accept would be worse than refusing.
    """
    did_key_to_public_hex(subject_did)  # raises unless it is a real Ed25519 did:key
    if not isinstance(domains, (list, tuple)) or not domains:
        raise ValueError("a reviewer credential must name at least one domain")
    if not all(isinstance(d, str) and d for d in domains):
        raise ValueError("domains must be non-empty strings")

    start = valid_from or _utc_now()
    end = valid_until or (start + timedelta(days=validity_days))

    credential = {
        "@context": [VC_CONTEXT_V2, GRADED_CONTEXT],
        "type": [CREDENTIAL_TYPE, REVIEWER_CREDENTIAL_TYPE],
        "issuer": issuer_did,
        "validFrom": _iso(start),
        "validUntil": _iso(end),
        "credentialSubject": {
            "id": subject_did,
            "role": REVIEWER_ROLE,
            # Sorted + de-duplicated so the same grant always canonicalizes to the
            # same bytes, and so a domain can never be silently listed twice.
            "domains": sorted(set(domains)),
        },
    }
    proof_options = {
        "type": PROOF_TYPE,
        "cryptosuite": CRYPTOSUITE,
        "created": _iso(start),
        "verificationMethod": did_key_verification_method(issuer_did),
        "proofPurpose": PROOF_PURPOSE,
    }
    signature = sign(
        issuer_private_key, credential_signing_bytes(credential, proof_options)
    )
    credential["proof"] = {
        **proof_options,
        "proofValue": multibase_encode(bytes.fromhex(signature)),
    }
    return credential


def credential_domains(credential: dict) -> list[str]:
    """The domains a (already-verified) credential grants review rights in."""
    subject = credential.get("credentialSubject")
    domains = subject.get("domains") if isinstance(subject, dict) else None
    return list(domains) if isinstance(domains, list) else []


def credential_subject_did(credential: dict) -> str | None:
    """The holder ``did:key`` a credential names, or ``None`` if malformed."""
    subject = credential.get("credentialSubject")
    if not isinstance(subject, dict):
        return None
    did = subject.get("id")
    return did if isinstance(did, str) else None


def verify_credential(
    credential,
    *,
    trusted_issuers=TRUSTED_ISSUER_DIDS,
    now: datetime | None = None,
) -> tuple[bool, str]:
    """Check a Reviewer VC end to end.

    Returns ``(ok, reason)`` rather than raising, so callers can log *why* a
    credential was refused and tests can assert on the specific failure. The
    checks, in order:

    1. the document has the VC 2.0 context and both types;
    2. the issuer is one this node **trusts** — a credential signed by any other
       key, however well-formed, is refused (this is what stops a reviewer
       self-issuing their own eligibility);
    3. the subject is an Ed25519 ``did:key`` with ``role == "reviewer"`` and a
       non-empty domain list;
    4. ``validFrom <= now <= validUntil`` — an expired credential is refused;
    5. the proof is a ``DataIntegrityProof`` / ``eddsa-jcs-2022`` /
       ``assertionMethod`` proof whose ``verificationMethod`` belongs to the
       issuer DID;
    6. the issuer's Ed25519 signature over the JCS-canonicalized document
       verifies against the key *inside* the issuer DID — no key lookup, no
       registry, no network.

    Note what is **not** checked here: that the presenter actually holds the
    subject's private key. A credential is a public document; possession is a
    separate proof (:func:`credentials.presentation.verify_presentation`).
    """
    if not isinstance(credential, dict):
        return False, "credential must be a JSON object"

    context = credential.get("@context")
    if not isinstance(context, list) or VC_CONTEXT_V2 not in context:
        return False, f"missing @context {VC_CONTEXT_V2!r}"

    types = credential.get("type")
    if not isinstance(types, list) or not {
        CREDENTIAL_TYPE,
        REVIEWER_CREDENTIAL_TYPE,
    } <= set(types):
        return False, "not a GradEDReviewerCredential"

    issuer = credential.get("issuer")
    if not isinstance(issuer, str) or issuer not in set(trusted_issuers):
        return False, f"issuer {issuer!r} is not a trusted GradED issuer"
    try:
        issuer_public_hex = did_key_to_public_hex(issuer)
    except ValueError as exc:
        return False, f"issuer DID is unusable: {exc}"

    subject = credential.get("credentialSubject")
    if not isinstance(subject, dict):
        return False, "missing credentialSubject"
    subject_did = subject.get("id")
    if not isinstance(subject_did, str):
        return False, "credentialSubject.id must be a did:key string"
    try:
        did_key_to_public_hex(subject_did)
    except ValueError as exc:
        return False, f"credentialSubject.id is not an Ed25519 did:key: {exc}"
    if subject.get("role") != REVIEWER_ROLE:
        return False, f"credentialSubject.role must be {REVIEWER_ROLE!r}"
    domains = subject.get("domains")
    if not isinstance(domains, list) or not domains:
        return False, "credentialSubject.domains must be a non-empty list"
    if not all(isinstance(d, str) and d for d in domains):
        return False, "credentialSubject.domains must be non-empty strings"

    moment = now or _utc_now()
    valid_from = parse_iso(credential.get("validFrom"))
    if valid_from is None:
        return False, "missing or malformed validFrom"
    if moment < valid_from:
        return False, f"credential is not valid before {credential['validFrom']}"
    valid_until = parse_iso(credential.get("validUntil"))
    if valid_until is None:
        return False, "missing or malformed validUntil"
    if moment > valid_until:
        return False, f"credential expired at {credential['validUntil']}"

    proof = credential.get("proof")
    if not isinstance(proof, dict):
        return False, "missing proof"
    if proof.get("type") != PROOF_TYPE or proof.get("cryptosuite") != CRYPTOSUITE:
        return False, f"proof must be a {PROOF_TYPE} with cryptosuite {CRYPTOSUITE}"
    if proof.get("proofPurpose") != PROOF_PURPOSE:
        return False, f"proofPurpose must be {PROOF_PURPOSE}"
    method = proof.get("verificationMethod")
    if method != did_key_verification_method(issuer):
        return False, "verificationMethod does not belong to the issuer DID"
    proof_value = proof.get("proofValue")
    if not isinstance(proof_value, str):
        return False, "missing proofValue"
    try:
        signature = multibase_decode(proof_value).hex()
    except ValueError as exc:
        return False, f"proofValue is not multibase base58btc: {exc}"

    message = credential_signing_bytes(credential, proof)
    if not verify(issuer_public_hex, message, signature):
        return False, "issuer signature does not verify over the credential"
    return True, "ok"
