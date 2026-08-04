"""Competence Verifiable Credentials — a certificate, made portable.

A **certificate** (:mod:`attestation.aggregator`) is a protocol fact: a
transaction, committed in a block, saying that a subject met a rubric in a domain
for one specific submission, backed by enough collusion-capped reputation weight.
It is authoritative, it is verifiable — and it is *stuck inside this chain*. A
learner cannot hand it to an employer, a university admissions office, or a
wallet, because reading it means running a node.

A **Competence VC** is the same fact re-expressed in a format the outside world
already knows how to check: a W3C-VC-2.0-shaped JSON document, signed by the
demo's *GradED Network* issuer key in the ``eddsa-jcs-2022`` Data Integrity
style, exactly like the Reviewer VCs of :mod:`credentials.vc`. It is an **export**,
never a second source of truth:

* it is minted **from** an on-chain certificate and carries, in ``evidence``, the
  identifiers needed to walk back to it — the certificate id, the submission
  transaction, the rubric root, and the block that finalized it;
* it changes **nothing** on-chain. No transaction, block or payload format is
  touched; the export is a read of the chain plus a signature, and it can be
  re-run at any time to produce the identical document;
* it carries **no personal data**. The subject is a ``did:key`` — the learner's
  own public key, self-certifying and registry-free — and the competence is the
  domain and the submission's own title. Nothing about a person is written to the
  chain by exporting, and nothing needs to be: the chain already held the key.

Status is live, not frozen
--------------------------
A certificate's standing is a *pure function of the chain*: valid until a
contributing attester is later slashed for the very submission it certifies, then
**contested** (:func:`attestation.aggregator.certificate_statuses`). A signed
document cannot carry that — it was signed once, and the chain moves. So the
credential carries a ``credentialStatus`` pointer instead: a URL a verifier
dereferences to get the *current* chain-derived standing
(:func:`credential_status`). The signature covers the pointer, not the answer, so
a stale copy of the credential still resolves to today's truth.

Three statuses are possible:

``valid``
    The certificate is committed and no valid slash contests it.
``contested``
    A contributing attester was validly slashed for this submission after
    issuance. The certificate is *not* deleted and its reputation reward is not
    clawed back (history is immutable) — but the credential says so plainly.
``revoked``
    The certificate the credential rests on is **not on this chain at all**: the
    credential references something no committed block backs. A verifier should
    treat it exactly like a forgery.

Document shape
--------------
::

    {
      "@context": ["https://www.w3.org/ns/credentials/v2", <graded context>],
      "id": "urn:graded:competence:<certificate id>",
      "type": ["VerifiableCredential", "GradEDCompetenceCredential"],
      "issuer": "did:key:z…",                     # the GradED Network
      "validFrom": "2026-08-04T12:00:00Z",        # the certificate's block time
      "credentialSubject": {
        "id": "did:key:z…",                       # the learner's key
        "competence": "bioinformatics/Draft manuscript"
      },
      "credentialStatus": {
        "id": "http://…/api/credentials/<certificate id>/status",
        "type": "GradEDCredentialStatus"
      },
      "evidence": [{
        "type": "GradEDBlockchainEvidence",
        "certificateId": "…",                     # aggregator.certificate_id
        "submissionTransaction": "…",             # the work reviewed
        "rubricRoot": "…",                        # what it was judged against
        "finalizedBlock": {"index": 3, "hash": "…", "finalized": true}
      }],
      "proof": { … eddsa-jcs-2022 … }
    }

Determinism
-----------
``validFrom`` and the proof's ``created`` are the **certificate's block
timestamp**, not the moment of export, so exporting the same certificate twice
yields byte-identical documents (the status URL aside). That makes the export
idempotent and lets a holder re-download without invalidating a copy someone
already holds.
"""

from __future__ import annotations

from datetime import datetime, timezone

from attestation.aggregator import (
    CERTIFICATE_TYPE,
    certificate_id,
    certificate_statuses,
)
from attestation.submission import is_submission
from credentials.vc import (
    CREDENTIAL_TYPE,
    CRYPTOSUITE,
    GRADED_CONTEXT,
    PROOF_PURPOSE,
    PROOF_TYPE,
    VC_CONTEXT_V2,
    credential_signing_bytes,
    parse_iso,
)
from crypto.did import (
    did_key_to_public_hex,
    did_key_verification_method,
    multibase_decode,
    multibase_encode,
    public_key_to_did_key,
)
from crypto.keys import keypair_from_seed, sign, verify

COMPETENCE_CREDENTIAL_TYPE = "GradEDCompetenceCredential"
EVIDENCE_TYPE = "GradEDBlockchainEvidence"
STATUS_TYPE = "GradEDCredentialStatus"

# The credential's own identifier is a URN over the certificate id, so the
# document names the protocol fact it exports rather than inventing an identity
# of its own. Two exports of one certificate therefore share an id — they are the
# same credential, not two.
CREDENTIAL_URN_PREFIX = "urn:graded:competence:"

# The demo's competence issuer: the network itself, speaking for what its
# consensus certified. Distinct from the *GradED Authority* of
# :mod:`credentials.vc`, and deliberately so — that key vouches for **who may
# review** (an admissions decision by an accrediting body), this one attests
# **what the chain decided** (a consensus outcome). Different powers, different
# keys, so trusting one does not imply trusting the other. Derived from a fixed
# seed exactly like every other demo identity, so every node and test reproduces
# the same DID with no key file to ship.
_GRADED_NETWORK_SEED = bytes.fromhex("5e" * 32)
NETWORK_KEYPAIR = keypair_from_seed(_GRADED_NETWORK_SEED)
NETWORK_PRIVATE_KEY, NETWORK_PUBLIC_HEX = NETWORK_KEYPAIR
NETWORK_DID = public_key_to_did_key(NETWORK_PUBLIC_HEX)
NETWORK_NAME = "GradED Network"

# The competence issuers a verifier accepts. Plural and configurable for the same
# reason reviewer issuers are: whom you trust is policy, not protocol.
TRUSTED_COMPETENCE_ISSUER_DIDS: frozenset[str] = frozenset({NETWORK_DID})

# Status values. "valid"/"contested" mirror the chain-derived certificate status
# verbatim; "revoked" is this layer's own answer for a credential whose
# certificate no committed block backs.
STATUS_VALID = "valid"
STATUS_CONTESTED = "contested"
STATUS_REVOKED = "revoked"


def _iso(moment: datetime) -> str:
    """Render ``moment`` as an ISO-8601 UTC timestamp ending in ``Z``."""
    return (
        moment.astimezone(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _iso_from_unix(seconds) -> str:
    """A block's float unix timestamp as an ISO-8601 ``Z`` string.

    Block timestamps are floats; JCS deliberately refuses floats (see
    :mod:`credentials.jcs`), and a signed document should carry a human-checkable
    date anyway — so the credential records the instant as a string.
    """
    return _iso(datetime.fromtimestamp(float(seconds), tz=timezone.utc))


def credential_urn(cert_id: str) -> str:
    """The credential id for the certificate identified by ``cert_id``."""
    return CREDENTIAL_URN_PREFIX + cert_id


def strip_credential_urn(value: str) -> str:
    """The bare certificate identifier inside ``value``, URN-prefixed or not.

    The status endpoint is quoted in the credential as a URL built from the
    certificate id, but a verifier holding the document may equally have the
    ``urn:graded:competence:…`` form to hand. Accepting both means neither the UI
    nor a third-party verifier has to know which one this deployment used.
    """
    if isinstance(value, str) and value.startswith(CREDENTIAL_URN_PREFIX):
        return value[len(CREDENTIAL_URN_PREFIX) :]
    return value


def find_certificate(chain, identifier: str):
    """Locate a committed certificate by id, returning ``(tx, block)``.

    ``identifier`` may be either the certificate's *scope* identity
    (:func:`attestation.aggregator.certificate_id` — what a credential quotes) or
    the certificate transaction's own hash, which is what the ``/api/submissions``
    panel already shows. Both name the same object; accepting either saves every
    caller a lookup table. Returns ``(None, None)`` when nothing matches — the
    credential-was-never-backed case the ``revoked`` status exists for.
    """
    if not isinstance(identifier, str) or not identifier:
        return None, None
    identifier = strip_credential_urn(identifier)
    for block in chain.blocks:
        for tx in block.transactions:
            payload = tx.payload
            if not isinstance(payload, dict) or payload.get("type") != CERTIFICATE_TYPE:
                continue
            if identifier in (certificate_id(payload), tx.hash):
                return tx, block
    return None, None


def _submission_title(chain, submission_tx_hash: str) -> str:
    """The title of the submission a certificate certifies (``""`` if unknown).

    The title is the only human-readable string in the whole credential, and it
    comes from the submission the learner themselves published — it is not
    profile data, and it is already on-chain.
    """
    for block in chain.blocks:
        for tx in block.transactions:
            if is_submission(tx) and tx.hash == submission_tx_hash:
                return tx.payload.get("title", "") or ""
    return ""


def competence_label(domain: str, title: str) -> str:
    """The ``credentialSubject.competence`` string: ``"<domain>/<title>"``.

    Falls back to the bare domain when the submission carried no title, so the
    field is never a dangling separator. The domain comes first because it is the
    part that carries protocol meaning — reputation, thresholds and coverage are
    all domain-scoped.
    """
    return f"{domain}/{title}" if title else str(domain)


def certificate_evidence(chain, cert_tx, block) -> dict:
    """The ``GradEDBlockchainEvidence`` entry for one committed certificate.

    Everything a verifier needs to walk from the document back to the chain: the
    certificate's scope id, the exact submission its attesters reviewed, the
    rubric root they judged it against, and the block that carries it — with the
    block's **live** finality standing read straight off the core
    (:meth:`blockchain.blockchain.Blockchain.is_final`), never recomputed here.
    """
    payload = cert_tx.payload
    return {
        "type": EVIDENCE_TYPE,
        "certificateId": certificate_id(payload),
        "submissionTransaction": payload.get("submission_tx_hash"),
        "rubricRoot": payload.get("rubric_root"),
        "finalizedBlock": {
            "index": block.index,
            "hash": block.hash,
            "finalized": bool(chain.is_final(block)),
        },
    }


def status_url(base_url: str, cert_id: str) -> str:
    """The live-status URL a credential points its ``credentialStatus`` at.

    ``base_url`` is the origin the credential was exported from (e.g.
    ``http://127.0.0.1:8090``); an empty one yields a relative path, which is
    what a verifier loaded from the same origin resolves anyway.
    """
    return f"{base_url.rstrip('/')}/api/credentials/{cert_id}/status"


def export_competence_credential(
    chain,
    identifier: str,
    *,
    base_url: str = "",
    issuer_private_key=NETWORK_PRIVATE_KEY,
    issuer_did: str = NETWORK_DID,
) -> dict:
    """Export the certificate named by ``identifier`` as a signed Competence VC.

    Reads the chain, builds the document, signs it with the issuer's key in the
    ``eddsa-jcs-2022`` style, and returns it. Nothing is stored and nothing is
    written to the chain: the credential is an off-chain artefact the holder keeps
    (the UI downloads it as a file), and re-exporting reproduces it.

    Args:
        chain: The blockchain to read the certificate — and its status — from.
        identifier: The certificate's scope id or its transaction hash.
        base_url: Origin used to build the ``credentialStatus`` URL.
        issuer_private_key / issuer_did: The signing identity, defaulting to the
            demo *GradED Network* key. No participant key is ever involved: a
            certificate is protocol output, so the network signs its own export.

    Raises:
        LookupError: If no committed certificate matches ``identifier``.
        ValueError: If the certificate's subject is not an Ed25519 public key and
            therefore has no ``did:key`` to name a credential subject by. A
            credential with an unresolvable subject could never be verified, so
            refusing beats emitting one.
    """
    cert_tx, block = find_certificate(chain, identifier)
    if cert_tx is None:
        raise LookupError(f"no committed certificate for {identifier!r}")

    payload = cert_tx.payload
    subject = payload.get("subject")
    try:
        subject_did = public_key_to_did_key(subject)
    except (ValueError, TypeError) as exc:
        raise ValueError(
            f"certificate subject is not an Ed25519 public key, so it has no "
            f"did:key to issue a credential to: {exc}"
        ) from exc

    cert_id = certificate_id(payload)
    domain = payload.get("domain")
    title = _submission_title(chain, payload.get("submission_tx_hash"))
    issued_at = _iso_from_unix(block.timestamp)

    credential = {
        "@context": [VC_CONTEXT_V2, GRADED_CONTEXT],
        "id": credential_urn(cert_id),
        "type": [CREDENTIAL_TYPE, COMPETENCE_CREDENTIAL_TYPE],
        "issuer": issuer_did,
        "validFrom": issued_at,
        "credentialSubject": {
            "id": subject_did,
            "competence": competence_label(domain, title),
        },
        "credentialStatus": {
            "id": status_url(base_url, cert_id),
            "type": STATUS_TYPE,
        },
        "evidence": [certificate_evidence(chain, cert_tx, block)],
    }
    proof_options = {
        "type": PROOF_TYPE,
        "cryptosuite": CRYPTOSUITE,
        "created": issued_at,
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


def credential_evidence(credential) -> dict:
    """The first ``GradEDBlockchainEvidence`` entry of ``credential`` (or ``{}``)."""
    if not isinstance(credential, dict):
        return {}
    evidence = credential.get("evidence")
    if not isinstance(evidence, list):
        return {}
    for entry in evidence:
        if isinstance(entry, dict) and entry.get("type") == EVIDENCE_TYPE:
            return entry
    return {}


def credential_certificate_id(credential) -> str | None:
    """The certificate id a credential rests on — from evidence, else its ``id``."""
    cert_id = credential_evidence(credential).get("certificateId")
    if isinstance(cert_id, str) and cert_id:
        return cert_id
    identifier = credential.get("id") if isinstance(credential, dict) else None
    if isinstance(identifier, str) and identifier.startswith(CREDENTIAL_URN_PREFIX):
        return strip_credential_urn(identifier)
    return None


def verify_competence_credential(
    credential,
    *,
    trusted_issuers=TRUSTED_COMPETENCE_ISSUER_DIDS,
    now: datetime | None = None,
) -> tuple[bool, str]:
    """Check a Competence VC's *document* end to end — signature and shape.

    Returns ``(ok, reason)``, never raising, because this runs on pasted,
    uploaded, hostile input. The checks:

    1. VC 2.0 context and both types present;
    2. the issuer is one the verifier **trusts** (this is what stops anyone
       minting their own competence claim with a well-formed document);
    3. the subject is an Ed25519 ``did:key`` with a non-empty ``competence``;
    4. ``validFrom`` parses and is not in the future;
    5. a ``GradEDBlockchainEvidence`` entry naming a certificate id;
    6. the proof is ``DataIntegrityProof`` / ``eddsa-jcs-2022`` /
       ``assertionMethod`` with the issuer's own verification method, and the
       Ed25519 signature verifies over the JCS-canonicalized document.

    Any edit to any signed field — a swapped competence, a different subject, a
    re-pointed evidence hash — changes the canonical bytes and fails step 6.

    What this does **not** check is the chain: a perfectly signed credential can
    still reference a certificate that no block backs, or one since contested.
    That is :func:`check_chain_linkage` and :func:`credential_status`, and a
    verifier must run all three.
    """
    if not isinstance(credential, dict):
        return False, "credential must be a JSON object"

    context = credential.get("@context")
    if not isinstance(context, list) or VC_CONTEXT_V2 not in context:
        return False, f"missing @context {VC_CONTEXT_V2!r}"

    types = credential.get("type")
    if not isinstance(types, list) or not {
        CREDENTIAL_TYPE,
        COMPETENCE_CREDENTIAL_TYPE,
    } <= set(types):
        return False, "not a GradEDCompetenceCredential"

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
    competence = subject.get("competence")
    if not isinstance(competence, str) or not competence:
        return False, "credentialSubject.competence must be a non-empty string"

    moment = now or datetime.now(timezone.utc).replace(microsecond=0)
    valid_from = parse_iso(credential.get("validFrom"))
    if valid_from is None:
        return False, "missing or malformed validFrom"
    if moment < valid_from:
        return False, f"credential is not valid before {credential['validFrom']}"

    if not credential_certificate_id(credential):
        return False, "missing GradEDBlockchainEvidence certificateId"

    proof = credential.get("proof")
    if not isinstance(proof, dict):
        return False, "missing proof"
    if proof.get("type") != PROOF_TYPE or proof.get("cryptosuite") != CRYPTOSUITE:
        return False, f"proof must be a {PROOF_TYPE} with cryptosuite {CRYPTOSUITE}"
    if proof.get("proofPurpose") != PROOF_PURPOSE:
        return False, f"proofPurpose must be {PROOF_PURPOSE}"
    if proof.get("verificationMethod") != did_key_verification_method(issuer):
        return False, "verificationMethod does not belong to the issuer DID"
    proof_value = proof.get("proofValue")
    if not isinstance(proof_value, str):
        return False, "missing proofValue"
    try:
        signature = multibase_decode(proof_value).hex()
    except ValueError as exc:
        return False, f"proofValue is not multibase base58btc: {exc}"

    try:
        message = credential_signing_bytes(credential, proof)
    except TypeError as exc:  # a float or other uncanonicalizable value was spliced in
        return False, f"credential is not canonicalizable: {exc}"
    if not verify(issuer_public_hex, message, signature):
        return False, "issuer signature does not verify over the credential"
    return True, "ok"


def check_chain_linkage(chain, credential) -> tuple[bool, str]:
    """Whether ``credential``'s claims match the certificate actually on-chain.

    The signature proves the issuer said it; this proves the chain agrees. Every
    claim the document makes about the protocol is re-read from the committed
    certificate: the subject key, the submission reviewed, the rubric root, and
    the block carrying it. A credential that survives
    :func:`verify_competence_credential` but fails here is signed but unbacked —
    which is exactly the case a verifier most needs told about.
    """
    cert_id = credential_certificate_id(credential)
    cert_tx, block = find_certificate(chain, cert_id)
    if cert_tx is None:
        return False, f"no committed certificate {cert_id!r} on this chain"

    payload = cert_tx.payload
    expected_id = credential_urn(certificate_id(payload))
    if credential.get("id") != expected_id:
        return False, "credential id is not the certificate's credential id"

    subject_did = credential.get("credentialSubject", {}).get("id")
    try:
        if did_key_to_public_hex(subject_did) != payload.get("subject"):
            return False, "credential subject is not the certificate's subject"
    except (ValueError, TypeError):
        return False, "credential subject DID is unusable"

    title = _submission_title(chain, payload.get("submission_tx_hash"))
    expected_competence = competence_label(payload.get("domain"), title)
    if credential.get("credentialSubject", {}).get("competence") != expected_competence:
        return False, "credential competence does not match the certificate's claim"

    evidence = credential_evidence(credential)
    if evidence.get("submissionTransaction") != payload.get("submission_tx_hash"):
        return False, "evidence names a different submission than the certificate"
    if evidence.get("rubricRoot") != payload.get("rubric_root"):
        return False, "evidence names a different rubric root than the certificate"

    finalized_block = evidence.get("finalizedBlock")
    if not isinstance(finalized_block, dict):
        return False, "evidence is missing its finalizedBlock"
    if finalized_block.get("index") != block.index:
        return False, "evidence names a different block index"
    if finalized_block.get("hash") != block.hash:
        return False, "evidence names a block that does not carry the certificate"
    if finalized_block.get("finalized") is not bool(chain.is_final(block)):
        return False, "evidence finality does not match this chain"
    return True, "ok"


def _chain_updated_at(chain) -> str:
    """When the state this status was derived from was last extended.

    A status is a function of the whole chain, so the honest "as of" time is the
    timestamp of its newest block — not the moment the request happened to be
    served, which would imply a freshness the node cannot claim.
    """
    return _iso_from_unix(chain.blocks[-1].timestamp) if chain.blocks else _iso(
        datetime.now(timezone.utc)
    )


def credential_status(chain, identifier: str) -> dict:
    """The live, chain-derived status of the credential over ``identifier``.

    Returns the status-endpoint body: ``{credentialId, status, updatedAt,
    evidence}``. ``status`` is :data:`STATUS_VALID` / :data:`STATUS_CONTESTED`
    read straight from :func:`attestation.aggregator.certificate_statuses` — the
    same derivation every node performs, so two nodes answer identically — or
    :data:`STATUS_REVOKED` when no committed certificate matches at all.

    ``evidence`` repeats the chain pointers so a verifier that has *only* the
    status URL (following a credential it does not fully trust) can still see
    which certificate, submission and block the answer is about.
    """
    cert_id = strip_credential_urn(identifier)
    cert_tx, block = find_certificate(chain, cert_id)
    if cert_tx is None:
        return {
            "credentialId": credential_urn(cert_id),
            "status": STATUS_REVOKED,
            "updatedAt": _chain_updated_at(chain),
            "evidence": None,
            "reason": "no committed certificate on this chain backs this credential",
        }
    statuses = certificate_statuses(chain)
    return {
        "credentialId": credential_urn(certificate_id(cert_tx.payload)),
        "status": statuses.get(cert_tx.hash, STATUS_VALID),
        "updatedAt": _chain_updated_at(chain),
        "evidence": certificate_evidence(chain, cert_tx, block),
    }


def verify_credential_report(
    chain,
    credential,
    *,
    trusted_issuers=TRUSTED_COMPETENCE_ISSUER_DIDS,
    now: datetime | None = None,
) -> dict:
    """The full verifier answer for one pasted credential.

    Four independent checks, reported individually rather than collapsed into one
    boolean, because *why* a credential failed is the whole point of a verifier
    page: ``signature`` (issuer proof over the document), ``issuer`` (is that
    issuer trusted here), ``subject`` (is the subject a resolvable ``did:key``),
    and ``chain`` (does a committed certificate back these exact claims). The
    live ``status`` rides alongside — a credential can be perfectly valid *and*
    contested, and a verifier must be able to say so.

    ``verified`` is true only when every check passes **and** the live status is
    not revoked. A contested credential is reported as verified-but-contested:
    the document is genuine and the chain does back it; what changed is the
    standing of the attestations behind it.
    """
    checks: list[dict] = []

    def record(name: str, ok: bool, detail: str) -> bool:
        checks.append({"check": name, "ok": bool(ok), "detail": detail})
        return ok

    issuer = credential.get("issuer") if isinstance(credential, dict) else None
    trusted = isinstance(issuer, str) and issuer in set(trusted_issuers)
    record(
        "issuer",
        trusted,
        f"issuer {issuer!r} is trusted" if trusted else f"issuer {issuer!r} is not trusted",
    )

    sig_ok, sig_reason = verify_competence_credential(
        credential, trusted_issuers=trusted_issuers, now=now
    )
    record("signature", sig_ok, sig_reason)

    subject_did = None
    if isinstance(credential, dict) and isinstance(
        credential.get("credentialSubject"), dict
    ):
        subject_did = credential["credentialSubject"].get("id")
    try:
        did_key_to_public_hex(subject_did)
        record("subject", True, f"subject {subject_did} resolves to an Ed25519 key")
    except (ValueError, TypeError) as exc:
        record("subject", False, f"subject DID is unusable: {exc}")

    chain_ok, chain_reason = check_chain_linkage(chain, credential)
    record("chain", chain_ok, chain_reason)

    cert_id = credential_certificate_id(credential) or ""
    status = credential_status(chain, cert_id)
    verified = all(c["ok"] for c in checks) and status["status"] != STATUS_REVOKED
    return {
        "verified": verified,
        "checks": checks,
        "status": status["status"],
        "credentialId": status["credentialId"],
        "updatedAt": status["updatedAt"],
        "evidence": status["evidence"],
        "issuer": {"did": issuer, "name": NETWORK_NAME if trusted else None},
        "subject": subject_did,
        "competence": (
            credential.get("credentialSubject", {}).get("competence")
            if isinstance(credential, dict)
            and isinstance(credential.get("credentialSubject"), dict)
            else None
        ),
    }
