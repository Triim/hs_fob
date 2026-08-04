"""Proof of possession — why a stolen credential is worthless.

A Verifiable Credential is a **public document**. It is handed to the holder, it
travels with requests, it may be logged, cached, screenshotted, or copied out of
someone's browser storage. If holding the JSON were enough to attest, then the
credential would be a bearer token and stealing it would be stealing the right
to review.

It is not enough here. A credential names its holder by ``did:key`` — which *is*
an Ed25519 public key — so eligibility can be tied to demonstrated control of the
matching **private** key, which never leaves the holder's browser and is never
stored by any node. The demonstration is a challenge-response:

1. the holder asks a node for a fresh random **challenge** (:class:`ChallengeStore`);
2. the holder signs the challenge — bound to their own DID — with the private key
   behind that DID;
3. the holder submits the attestation together with a **presentation**:
   ``{credential, challenge, challenge_signature}``;
4. the node verifies the issuer's signature on the credential, that the
   credential's subject DID is *the very key signing the attestation*, that the
   challenge signature verifies under that same key, that the credential is
   currently valid, and that the attestation's domain is one the credential
   grants.

A thief who copies the credential JSON fails at step 2: producing a signature
over *any* challenge requires the private key, and the credential's subject DID
pins exactly which key that must be. They also cannot re-point the credential at
their own key — that would change the signed document and break the issuer's
signature. And they cannot lift a captured presentation onto an attestation of
their own, because the attestation is separately signed by its ``sender`` and the
gate requires ``subject DID == sender``.

The challenge adds freshness on top of that: it is single-use and short-lived on
the node that issued it, so a presentation captured in flight cannot be replayed
to attach a *different* attestation later.

The signed message is domain-separated (:data:`POP_CONTEXT`) and includes the
holder's DID, so a signature made for proof-of-possession can never be mistaken
for — or replayed as — a transaction signature, a block commit, or a view-change
vote, which sign entirely different byte prefixes.
"""

from __future__ import annotations

import secrets
import time
from datetime import datetime

from credentials.vc import (
    TRUSTED_ISSUER_DIDS,
    credential_domains,
    credential_subject_did,
    verify_credential,
)
from crypto.did import did_key_to_public_hex, public_key_to_did_key
from crypto.keys import sign, verify

# Domain separation tag for the proof-of-possession signature. Any byte string a
# key signs in this system starts with a context that says what it *means*, so
# one signature can never be replayed in another role.
POP_CONTEXT = "GradED-Reviewer-PoP-v1"

# How long an issued challenge stays usable. Long enough for a human to finish
# filling in an attestation form, short enough that a captured challenge is
# stale before it is useful.
CHALLENGE_TTL_SECONDS = 300

# Bytes of entropy per challenge. 32 bytes makes guessing or colliding a
# challenge computationally irrelevant.
CHALLENGE_BYTES = 32


def pop_signing_bytes(challenge: str, holder_did: str) -> bytes:
    """The exact bytes a holder signs to prove possession of ``holder_did``'s key.

    Binds three things together: the context (so the signature has one meaning
    only), the node-issued challenge (freshness), and the holder's DID (so a
    signature made by one holder can never be presented as another's).
    """
    return f"{POP_CONTEXT}|{challenge}|{holder_did}".encode("utf-8")


def sign_challenge(private_key, challenge: str, holder_did: str | None = None) -> str:
    """Sign ``challenge`` as the holder — the browser's job, mirrored here.

    Provided so tests, the demo and the scripted scenarios can act as a holder
    without a browser. **Nodes never call this**: a node has no participant
    private key to call it with. ``holder_did`` defaults to the DID of the signing
    key itself, which is the only value a verifier will accept.
    """
    from crypto.keys import public_hex

    did = holder_did or public_key_to_did_key(public_hex(private_key))
    return sign(private_key, pop_signing_bytes(challenge, did))


def make_presentation(private_key, credential: dict, challenge: str) -> dict:
    """Bundle a credential with a fresh proof of possession over ``challenge``.

    The holder-side counterpart of :func:`verify_presentation`; the browser builds
    the identical structure in JavaScript. Returns the envelope that rides
    *alongside* an attestation — never inside its payload, so no transaction or
    block format changes and no credential data reaches the chain.
    """
    subject_did = credential_subject_did(credential) or ""
    return {
        "credential": credential,
        "challenge": challenge,
        "challenge_signature": sign_challenge(private_key, challenge, subject_did),
    }


def verify_presentation(
    presentation,
    attester_public_hex: str,
    domain: str,
    *,
    trusted_issuers=TRUSTED_ISSUER_DIDS,
    now: datetime | None = None,
) -> tuple[bool, str]:
    """Whether ``presentation`` entitles ``attester_public_hex`` to attest in ``domain``.

    Returns ``(ok, reason)`` — total, never raising, because this runs on
    untrusted input from the network and the HTTP boundary alike.

    ``attester_public_hex`` is the transaction's ``sender``: the key that signed
    the attestation. Requiring the credential's subject DID to resolve to *that
    same key* is what welds eligibility to the attester and makes a copied
    credential useless to anyone else.

    Freshness of ``challenge`` is **not** checked here: only the node that issued
    a challenge can know it is fresh and unused (see :class:`ChallengeStore`,
    applied at the submission boundary). A peer receiving a gossiped attestation
    still gets the full cryptographic guarantee — issuer signature, holder key
    possession, validity window, domain scope — which is what prevents credential
    theft; the challenge store adds replay resistance where it can be enforced.
    """
    if not isinstance(presentation, dict):
        return False, "a reviewer credential presentation is required to attest"

    credential = presentation.get("credential")
    ok, reason = verify_credential(
        credential, trusted_issuers=trusted_issuers, now=now
    )
    if not ok:
        return False, reason

    challenge = presentation.get("challenge")
    if not isinstance(challenge, str) or not challenge:
        return False, "presentation is missing a challenge"
    signature = presentation.get("challenge_signature")
    if not isinstance(signature, str) or not signature:
        return False, "presentation is missing a challenge signature"

    subject_did = credential_subject_did(credential)
    try:
        subject_public_hex = did_key_to_public_hex(subject_did)
    except ValueError as exc:
        return False, f"credential subject is not an Ed25519 did:key: {exc}"
    if subject_public_hex != attester_public_hex:
        # The credential belongs to somebody else — this is the stolen-credential
        # case, refused before the signature check even matters.
        return False, "credential subject is not the attesting key"

    if not verify(subject_public_hex, pop_signing_bytes(challenge, subject_did), signature):
        # The presenter cannot sign for the key the credential names: they do not
        # possess it. A copied credential JSON stops exactly here.
        return False, "proof of possession failed: challenge signature invalid"

    if domain not in credential_domains(credential):
        return False, f"credential does not grant review rights in {domain!r}"
    return True, "ok"


class ChallengeStore:
    """Node-side issue-once, use-once store of proof-of-possession challenges.

    Small on purpose: a challenge is random bytes plus an expiry. Issuing records
    it; consuming removes it, so the same challenge can never authorise two
    presentations, and anything older than :data:`CHALLENGE_TTL_SECONDS` is
    dropped. It is in-memory and per-node, which is the right scope — a challenge
    is a liveness check between one holder and one node, not shared state the
    network has to agree on (and so it never touches consensus).
    """

    def __init__(self, ttl: float = CHALLENGE_TTL_SECONDS) -> None:
        self.ttl = ttl
        self._issued: dict[str, float] = {}

    def issue(self, now: float | None = None) -> dict:
        """Mint a fresh challenge; returns ``{"challenge", "expires_in", "context"}``.

        ``context`` tells the holder exactly what to sign, so a client never has
        to hardcode the domain-separation format.
        """
        moment = time.time() if now is None else now
        self._purge(moment)
        challenge = secrets.token_hex(CHALLENGE_BYTES)
        self._issued[challenge] = moment + self.ttl
        return {
            "challenge": challenge,
            "expires_in": self.ttl,
            "context": POP_CONTEXT,
        }

    def consume(self, challenge, now: float | None = None) -> bool:
        """Spend ``challenge`` once; ``False`` if unknown, already used, or expired."""
        moment = time.time() if now is None else now
        self._purge(moment)
        if not isinstance(challenge, str):
            return False
        expiry = self._issued.pop(challenge, None)
        return expiry is not None and expiry >= moment

    def _purge(self, now: float) -> None:
        """Drop expired challenges so the store cannot grow without bound."""
        for challenge in [c for c, exp in self._issued.items() if exp < now]:
            del self._issued[challenge]
