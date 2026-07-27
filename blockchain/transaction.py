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


@dataclass
class Transaction:
    """A single, content-addressed transaction.

    Attributes:
        sender: Identity of the submitter. A plain string for now (a public key
            or node id); cryptographic signatures are a later step.
        payload: Arbitrary, JSON-serializable contents. Intentionally
            unconstrained so future record types need no schema change here.
        timestamp: Unix time (seconds) the transaction was created. Defaults to
            the current time, but is an explicit field so a transaction can be
            reconstructed deterministically from serialized data.
    """

    sender: str
    payload: dict
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        """Return a JSON-serializable dict of the transaction's contents.

        This is the single source of truth for both hashing and (later)
        wire/serialization, so the hash always covers exactly what gets sent.
        """
        return {
            "sender": self.sender,
            "payload": self.payload,
            "timestamp": self.timestamp,
        }

    @property
    def hash(self) -> str:
        """Deterministic SHA-256 hex digest of the transaction's contents.

        Computed from a *canonical* JSON encoding — keys sorted and whitespace
        stripped — so the same logical transaction always produces the same
        digest regardless of dict insertion order, Python version, or machine.
        Recomputed on every access so it can never go stale relative to the
        fields.
        """
        canonical = json.dumps(
            self.to_dict(), sort_keys=True, separators=(",", ":")
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
