"""Ed25519 keypairs, signing and verification — the signature primitive.

This module is the *only* place that touches ``cryptography`` directly, so the
rest of the system speaks in hex strings and ``bytes``. The public key doubles
as an identity: its hex encoding is what a transaction records in ``sender``.

Ed25519 is chosen deliberately:

- **Small and fixed-size.** 32-byte public keys and 64-byte signatures, which
  keep transactions compact and their wire form predictable.
- **Deterministic signing.** A given (key, message) pair always yields the same
  signature — no per-signature randomness to get wrong — so tests can assert on
  exact bytes and there is no nonce-reuse footgun.

Verification is written to be *total*: it returns ``False`` for any bad or
malformed input rather than raising, so callers can treat it as a plain
predicate without wrapping every check in a ``try``.
"""

from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def generate_keypair() -> tuple[Ed25519PrivateKey, str]:
    """Generate a fresh Ed25519 keypair.

    Returns:
        A ``(private_key, public_key_hex)`` pair. The private key is the live
        key object used for signing; the public key is returned as a hex string
        because that is the form the chain stores (in ``sender``) and sends over
        the wire.
    """
    private_key = Ed25519PrivateKey.generate()
    public_key_hex = private_key.public_key().public_bytes_raw().hex()
    return private_key, public_key_hex


def keypair_from_seed(seed: bytes) -> tuple[Ed25519PrivateKey, str]:
    """Derive a *reproducible* Ed25519 keypair from a fixed 32-byte ``seed``.

    Unlike :func:`generate_keypair`, this is deterministic: the same seed always
    yields the same key. That is exactly what genesis authorities need — the
    genesis anchor must name real public keys whose private halves the demo and
    tests can regenerate, so an authority can actually *sign* blocks. Ed25519's
    private key *is* its 32-byte seed, so we feed the seed straight in.
    """
    private_key = Ed25519PrivateKey.from_private_bytes(seed)
    return private_key, private_key.public_key().public_bytes_raw().hex()


def public_hex(private_key: Ed25519PrivateKey) -> str:
    """Hex encoding of ``private_key``'s public key — the identity it signs as."""
    return private_key.public_key().public_bytes_raw().hex()


def sign(private_key: Ed25519PrivateKey, message: bytes) -> str:
    """Sign ``message`` with ``private_key``, returning a hex signature."""
    return private_key.sign(message).hex()


def verify(public_key_hex: str, message: bytes, signature_hex: str) -> bool:
    """Check that ``signature_hex`` is ``public_key_hex``'s signature over ``message``.

    Total by design: returns ``False`` for a wrong signature, a wrong key, or
    malformed hex/key input, and never raises. This lets callers use it as a
    boolean predicate without guarding against exceptions.
    """
    try:
        public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
        public_key.verify(bytes.fromhex(signature_hex), message)
        return True
    except (InvalidSignature, ValueError):
        # InvalidSignature: the signature does not match. ValueError: malformed
        # hex, or a byte string that is not a valid 32-byte Ed25519 public key.
        return False
