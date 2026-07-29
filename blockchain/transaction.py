"""The Transaction — the smallest domain object in the chain.

A transaction records that some ``sender`` submitted some ``payload`` at a
point in time. The payload is a generic ``dict`` on purpose: the core makes no
assumptions about its shape, so a later application layer (e.g. a
competence-attestation record) can live inside a transaction without changing
this module.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field

from crypto.keys import sign as _sign
from crypto.keys import verify as _verify


@dataclass
class Transaction:
    """A single, content-addressed transaction.

    Attributes:
        sender: Identity of the submitter — a hex-encoded Ed25519 public key. It
            doubles as the key that ``verify_signature`` checks the signature
            against.
        payload: Arbitrary, JSON-serializable contents. Intentionally
            unconstrained so future record types need no schema change here.
        timestamp: Unix time (seconds) the transaction was created. Defaults to
            the current time, but is an explicit field so a transaction can be
            reconstructed deterministically from serialized data.
        signature: Hex Ed25519 signature over ``signing_bytes()`` (the sender+
            payload+timestamp content), or ``None`` if unsigned. Deliberately
            *outside* the hashed/signed content: the signature is computed from
            the hash's content, so folding it back in would be circular.
    """

    sender: str
    payload: dict
    timestamp: float = field(default_factory=time.time)
    signature: str | None = None

    def _signable_content(self) -> dict:
        """The content the hash and the signature both commit to.

        Exactly ``sender``, ``payload`` and ``timestamp`` — never the signature.
        This single method is the source of truth for what gets hashed and what
        gets signed, so the two can never drift apart.
        """
        return {
            "sender": self.sender,
            "payload": self.payload,
            "timestamp": self.timestamp,
        }

    def signing_bytes(self) -> bytes:
        """Canonical bytes the signature commits to (same content the hash is derived from).

        A *canonical* JSON encoding — keys sorted and whitespace stripped — of
        the signable content, so a signer and a verifier on different machines
        produce byte-for-byte identical input.
        """
        canonical = json.dumps(
            self._signable_content(), sort_keys=True, separators=(",", ":")
        )
        return canonical.encode("utf-8")

    def to_dict(self) -> dict:
        """Return a JSON-serializable dict of the transaction, including the signature.

        Carries the ``signature`` alongside the signable fields so it survives
        serialization/transport. The signature is *not* part of the hashed
        content — ``hash`` is computed from ``signing_bytes`` — so including it
        here does not affect the hash.
        """
        return {**self._signable_content(), "signature": self.signature}

    @property
    def hash(self) -> str:
        """Deterministic SHA-256 hex digest of the transaction's signable content.

        Computed over ``signing_bytes()`` — the same canonical bytes the
        signature covers — so signing a transaction never changes its hash.
        Recomputed on every access so it can never go stale relative to the
        fields.
        """
        return hashlib.sha256(self.signing_bytes()).hexdigest()

    def sign(self, private_key) -> None:
        """Sign this transaction in place, storing the hex signature.

        Signs ``signing_bytes()`` — the exact content the hash covers — so the
        signature commits to the same thing the hash does.
        """
        self.signature = _sign(private_key, self.signing_bytes())

    def is_signed(self) -> bool:
        """Whether a signature is present (not whether it is valid)."""
        return self.signature is not None

    def verify_signature(self) -> bool:
        """Whether ``signature`` is a valid signature by ``sender`` over the content.

        Treats ``sender`` as the hex public key. Returns ``False`` for an
        unsigned transaction and for any bad/malformed signature — never raises.
        """
        if self.signature is None:
            return False
        return _verify(self.sender, self.signing_bytes(), self.signature)
