"use strict";
/*
 * did:key in the browser — the exact mirror of crypto/did.py.
 *
 * The browser generates and holds Ed25519 keys already (see app.js); this file
 * only *renders* one of those public keys as a W3C did:key identifier, so the
 * UI can show a portable, self-certifying name for the identity instead of a
 * bare 64-character hex blob. No new key material, no signing, nothing sent to
 * the node: the hex public key remains what gets put in a transaction's
 * `sender`.
 *
 * Encoding (must stay byte-for-byte identical to the Python side, which is
 * what tests/test_did_js.py asserts):
 *
 *   did:key:z<base58btc( 0xed 0x01 || 32 raw public key bytes )>
 *
 * where 0xed 0x01 is the ed25519-pub multicodec varint and "z" is multibase
 * base58btc.
 */

(function (global) {
  const ED25519_MULTICODEC_PREFIX = [0xed, 0x01];
  const MULTIBASE_BASE58BTC = "z";
  const DID_KEY_PREFIX = "did:key:";
  const PUBLIC_KEY_LEN = 32;

  // Bitcoin's base58 alphabet — no 0, O, I or l, the characters readers confuse.
  const B58_ALPHABET =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

  /*
   * base58btc encode. JS has no big integers in Uint8Array form, and the keys
   * here are far past Number's exact range, so this does long division on the
   * byte array itself (repeatedly divide the whole buffer by 58, collecting
   * remainders) — the standard byte-wise algorithm, exact for any length.
   * Leading zero bytes carry no weight in that division and are re-emitted as
   * "1", which is what makes the encoding reversible.
   */
  function b58encode(bytes) {
    let zeros = 0;
    while (zeros < bytes.length && bytes[zeros] === 0) zeros++;

    const digits = [];
    const buf = Array.from(bytes.slice(zeros));
    let start = 0;
    while (start < buf.length) {
      let remainder = 0;
      for (let i = start; i < buf.length; i++) {
        const acc = remainder * 256 + buf[i];
        buf[i] = Math.floor(acc / 58);
        remainder = acc % 58;
      }
      digits.push(remainder);
      while (start < buf.length && buf[start] === 0) start++;
    }

    return (
      "1".repeat(zeros) +
      digits
        .reverse()
        .map((d) => B58_ALPHABET[d])
        .join("")
    );
  }

  // Inverse of b58encode: multiply-and-add across the byte buffer.
  function b58decode(text) {
    let zeros = 0;
    while (zeros < text.length && text[zeros] === "1") zeros++;

    const bytes = [];
    for (let i = zeros; i < text.length; i++) {
      let value = B58_ALPHABET.indexOf(text[i]);
      if (value < 0) throw new Error("invalid base58btc character: " + text[i]);
      for (let j = 0; j < bytes.length; j++) {
        const acc = bytes[j] * 58 + value;
        bytes[j] = acc & 0xff;
        value = acc >> 8;
      }
      while (value > 0) {
        bytes.push(value & 0xff);
        value >>= 8;
      }
    }
    bytes.reverse();
    return Uint8Array.from(new Array(zeros).fill(0).concat(bytes));
  }

  function hexToBytes(hex) {
    if (typeof hex !== "string" || hex.length % 2 !== 0 || /[^0-9a-fA-F]/.test(hex)) {
      throw new Error("not a hex public key: " + hex);
    }
    const out = new Uint8Array(hex.length / 2);
    for (let i = 0; i < out.length; i++) {
      out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    }
    return out;
  }

  function bytesToHex(bytes) {
    return Array.from(bytes)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  }

  // hex Ed25519 public key -> "did:key:z…". Throws on anything that is not a
  // 32-byte key, so a malformed DID is never displayed as if it were real.
  function publicKeyToDidKey(publicKeyHex) {
    const key = hexToBytes(publicKeyHex);
    if (key.length !== PUBLIC_KEY_LEN) {
      throw new Error(
        "expected a " + PUBLIC_KEY_LEN + "-byte Ed25519 public key, got " + key.length
      );
    }
    const payload = Uint8Array.from(ED25519_MULTICODEC_PREFIX.concat(Array.from(key)));
    return DID_KEY_PREFIX + MULTIBASE_BASE58BTC + b58encode(payload);
  }

  // "did:key:z…" -> the raw 32 verification-key bytes (exact inverse).
  function didKeyToPublicKey(did) {
    if (typeof did !== "string" || did.indexOf(DID_KEY_PREFIX) !== 0) {
      throw new Error("not a did:key identifier: " + did);
    }
    const body = did.slice(DID_KEY_PREFIX.length);
    if (body[0] !== MULTIBASE_BASE58BTC) {
      throw new Error("did:key must use the base58btc multibase prefix 'z'");
    }
    const payload = b58decode(body.slice(1));
    if (
      payload[0] !== ED25519_MULTICODEC_PREFIX[0] ||
      payload[1] !== ED25519_MULTICODEC_PREFIX[1]
    ) {
      throw new Error("did:key is not an ed25519-pub key");
    }
    const key = payload.slice(ED25519_MULTICODEC_PREFIX.length);
    if (key.length !== PUBLIC_KEY_LEN) {
      throw new Error("did:key payload is " + key.length + " bytes");
    }
    return key;
  }

  function didKeyToPublicHex(did) {
    return bytesToHex(didKeyToPublicKey(did));
  }

  // Display helper: a DID when the value really is an Ed25519 key, else null.
  // The UI labels placeholders too (the genesis block's absent producer), and
  // those should render without a DID rather than throw mid-render.
  function tryPublicKeyToDidKey(value) {
    try {
      return publicKeyToDidKey(value);
    } catch {
      return null;
    }
  }

  const api = {
    publicKeyToDidKey,
    didKeyToPublicKey,
    didKeyToPublicHex,
    tryPublicKeyToDidKey,
  };

  global.didKey = api;
  // Also reachable from Node (tests/test_did_js.py runs this file directly to
  // check the mirror against the Python implementation).
  if (typeof module !== "undefined" && module.exports) module.exports = api;
})(typeof window !== "undefined" ? window : globalThis);
