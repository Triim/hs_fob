"""did:key identities — a *naming* layer over the existing Ed25519 keys.

This module introduces no new cryptography and no new key material. Every
identity in the system is still exactly what it was: a 32-byte Ed25519 public
key, hex-encoded, recorded verbatim in a transaction's ``sender``. What a
``did:key`` adds is a second, standards-shaped *rendering* of that same key —
self-certifying (the key is inside the identifier), resolvable without any
registry, and portable to any wallet or verifier that speaks W3C DIDs.

The encoding is the one the did:key method specifies for Ed25519:

    did:key:z<base58btc( 0xed 0x01 || raw_public_key_bytes )>

- ``0xed 0x01`` is the ``ed25519-pub`` multicodec code (0xed) written as an
  unsigned varint, which is why the low-order byte comes first.
- ``z`` is the multibase prefix for base58btc, so the identifier declares its
  own base rather than leaving it to convention.

Because the key is the whole payload, :func:`did_key_to_public_key` is a pure
inverse: it recovers the same bytes, with no lookup and no trust in anything
but the string. Nothing here touches private keys, hashing, signing, or
consensus — a DID is derived from a public key on demand and never stored.
"""

from __future__ import annotations

# The ed25519-pub multicodec code (0xed) as an unsigned varint: values above
# 0x7f are emitted low-7-bits-first with the continuation bit set on all but
# the last byte, so 0xed becomes 0xed 0x01.
ED25519_MULTICODEC_PREFIX = b"\xed\x01"

# The multibase prefix declaring "the rest of this string is base58btc".
MULTIBASE_BASE58BTC = "z"

DID_KEY_PREFIX = "did:key:"

# Bitcoin's base58 alphabet: the digits and letters minus 0, O, I and l, which
# are the characters people mistake for one another when reading a key aloud.
_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_INDEX = {char: value for value, char in enumerate(_B58_ALPHABET)}

_ED25519_PUBLIC_KEY_LEN = 32


def _b58encode(data: bytes) -> str:
    """base58btc-encode ``data`` (Bitcoin alphabet, leading zeros as ``1``).

    Leading zero bytes carry no weight in the big-integer conversion, so they
    are counted separately and re-emitted as ``1`` characters — that is what
    makes the encoding injective and the decode exactly reversible.
    """
    leading_zeros = len(data) - len(data.lstrip(b"\x00"))
    number = int.from_bytes(data, "big")
    digits = ""
    while number > 0:
        number, remainder = divmod(number, 58)
        digits = _B58_ALPHABET[remainder] + digits
    return "1" * leading_zeros + digits


def _b58decode(text: str) -> bytes:
    """Inverse of :func:`_b58encode`. Raises ``ValueError`` on any stray character."""
    number = 0
    for char in text:
        value = _B58_INDEX.get(char)
        if value is None:
            raise ValueError(f"invalid base58btc character: {char!r}")
        number = number * 58 + value
    leading_zeros = len(text) - len(text.lstrip("1"))
    body = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    return b"\x00" * leading_zeros + body


def public_key_to_did_key(public_key_hex: str) -> str:
    """Render a hex Ed25519 public key as its ``did:key`` identifier.

    Args:
        public_key_hex: The 64-character hex encoding of a 32-byte Ed25519
            public key — the same string the chain stores in ``sender``.

    Returns:
        ``"did:key:z..."`` — a deterministic function of the key alone, so the
        same key always names the same DID on every node and in the browser.

    Raises:
        ValueError: If the input is not 32 bytes of valid hex. A DID that does
            not decode back to a usable verification key would be worse than no
            DID at all, so this is checked rather than papered over.
    """
    try:
        key_bytes = bytes.fromhex(public_key_hex)
    except ValueError as exc:
        raise ValueError(f"not a hex public key: {public_key_hex!r}") from exc
    if len(key_bytes) != _ED25519_PUBLIC_KEY_LEN:
        raise ValueError(
            f"expected a {_ED25519_PUBLIC_KEY_LEN}-byte Ed25519 public key, "
            f"got {len(key_bytes)} bytes"
        )
    payload = ED25519_MULTICODEC_PREFIX + key_bytes
    return DID_KEY_PREFIX + MULTIBASE_BASE58BTC + _b58encode(payload)


def did_key_to_public_key(did: str) -> bytes:
    """Recover the raw Ed25519 verification key bytes from a ``did:key``.

    The exact inverse of :func:`public_key_to_did_key`: no resolution step and
    no network, because the key *is* the identifier.

    Raises:
        ValueError: If ``did`` is not a base58btc ``did:key`` carrying an
            ``ed25519-pub`` multicodec payload of the right length. Other key
            types are legal did:keys but are not identities this chain can
            verify a signature against, so they are rejected explicitly.
    """
    if not isinstance(did, str) or not did.startswith(DID_KEY_PREFIX):
        raise ValueError(f"not a did:key identifier: {did!r}")
    body = did[len(DID_KEY_PREFIX) :]
    if not body.startswith(MULTIBASE_BASE58BTC):
        raise ValueError("did:key must use the base58btc multibase prefix 'z'")
    payload = _b58decode(body[len(MULTIBASE_BASE58BTC) :])
    if not payload.startswith(ED25519_MULTICODEC_PREFIX):
        raise ValueError("did:key is not an ed25519-pub key")
    key_bytes = payload[len(ED25519_MULTICODEC_PREFIX) :]
    if len(key_bytes) != _ED25519_PUBLIC_KEY_LEN:
        raise ValueError(
            f"did:key payload is {len(key_bytes)} bytes, "
            f"expected {_ED25519_PUBLIC_KEY_LEN}"
        )
    return key_bytes


def did_key_to_public_hex(did: str) -> str:
    """:func:`did_key_to_public_key` in the hex form the rest of the system uses."""
    return did_key_to_public_key(did).hex()


def try_public_key_to_did_key(value: str) -> str | None:
    """Best-effort DID for ``value``, or ``None`` if it is not an Ed25519 key.

    The UI labels things that are not always real keys — the genesis block's
    absent producer, readable placeholder names in tests and fixtures. Those
    should render without a DID rather than fail the whole response, so display
    code calls this instead of the strict function.
    """
    try:
        return public_key_to_did_key(value)
    except (ValueError, TypeError):
        return None
