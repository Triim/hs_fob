"""Tests for the did:key identity layer over the existing Ed25519 keys."""

import unittest

from blockchain.transaction import Transaction
from crypto.did import (
    DID_KEY_PREFIX,
    did_key_to_public_hex,
    did_key_to_public_key,
    public_key_to_did_key,
    try_public_key_to_did_key,
)
from crypto.keys import generate_keypair, keypair_from_seed, sign, verify

# Published did:key test vectors for Ed25519 (W3C did:key method spec). These
# are the known answers: the strings are fixed by the spec, so encoding one of
# their keys must reproduce the string character for character, and decoding
# must yield exactly 32 verification-key bytes.
SPEC_VECTORS = [
    "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
    "did:key:z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG",
    "did:key:z6MknGc3ocHs3zdPiJbnaaqDi58NGb4pk1Sp9WxWufuXSdxf",
]


class DidKeyEncodingTests(unittest.TestCase):
    def test_spec_vectors_decode_to_32_byte_keys(self):
        """Each spec did:key carries exactly one 32-byte Ed25519 public key."""
        for did in SPEC_VECTORS:
            with self.subTest(did=did):
                self.assertEqual(len(did_key_to_public_key(did)), 32)

    def test_spec_vectors_re_encode_exactly(self):
        """Known answer: decoding then re-encoding reproduces the spec string."""
        for did in SPEC_VECTORS:
            with self.subTest(did=did):
                key_hex = did_key_to_public_hex(did)
                self.assertEqual(public_key_to_did_key(key_hex), did)

    def test_ed25519_dids_start_with_z6Mk(self):
        """The 0xed01 multicodec prefix forces the well-known ``z6Mk`` opening.

        This is the cheap signal that the multicodec bytes and the base58btc
        alphabet are both right: get either wrong and the prefix changes.
        """
        _, public_key_hex = generate_keypair()
        self.assertTrue(public_key_to_did_key(public_key_hex).startswith("did:key:z6Mk"))

    def test_known_key_encodes_to_expected_did(self):
        """Known answer, pinned end to end: fixed seed -> fixed key -> fixed DID.

        Locks the whole pipeline (multicodec prefix, base58btc digits, multibase
        tag) to literal expected values, so any drift in the encoding fails here
        rather than silently producing DIDs no other implementation agrees with.
        """
        _, public_key_hex = keypair_from_seed(b"\x01" * 32)

        self.assertEqual(
            public_key_hex,
            "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c",
        )
        self.assertEqual(
            public_key_to_did_key(public_key_hex),
            "did:key:z6Mkon3Necd6NkkyfoGoHxid2znGc59LU3K7mubaRcFbLfLX",
        )
        self.assertEqual(
            did_key_to_public_hex(
                "did:key:z6Mkon3Necd6NkkyfoGoHxid2znGc59LU3K7mubaRcFbLfLX"
            ),
            public_key_hex,
        )


class RoundTripTests(unittest.TestCase):
    def test_round_trip_for_generated_keys(self):
        """did:key round-trips back to the very same public key bytes."""
        for _ in range(25):
            _, public_key_hex = generate_keypair()
            did = public_key_to_did_key(public_key_hex)

            self.assertEqual(did_key_to_public_key(did).hex(), public_key_hex)

    def test_distinct_keys_get_distinct_dids(self):
        _, pub_a = generate_keypair()
        _, pub_b = generate_keypair()

        self.assertNotEqual(public_key_to_did_key(pub_a), public_key_to_did_key(pub_b))

    def test_did_is_prefixed_and_multibase_tagged(self):
        _, public_key_hex = generate_keypair()
        did = public_key_to_did_key(public_key_hex)

        self.assertTrue(did.startswith(DID_KEY_PREFIX + "z"))


class RejectionTests(unittest.TestCase):
    def test_non_hex_key_rejected(self):
        with self.assertRaises(ValueError):
            public_key_to_did_key("not-a-key")

    def test_wrong_length_key_rejected(self):
        with self.assertRaises(ValueError):
            public_key_to_did_key("aabb")

    def test_non_did_string_rejected(self):
        with self.assertRaises(ValueError):
            did_key_to_public_key("z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")

    def test_wrong_multibase_rejected(self):
        _, public_key_hex = generate_keypair()
        did = public_key_to_did_key(public_key_hex)

        with self.assertRaises(ValueError):
            did_key_to_public_key(DID_KEY_PREFIX + "f" + did[len(DID_KEY_PREFIX) + 1 :])

    def test_non_ed25519_multicodec_rejected(self):
        """A did:key for some other key type is not an identity we can verify."""
        # 0xec 0x01 is x25519-pub — a legal did:key, but not a signing key.
        from crypto.did import _b58encode

        did = DID_KEY_PREFIX + "z" + _b58encode(b"\xec\x01" + b"\x11" * 32)

        with self.assertRaises(ValueError):
            did_key_to_public_key(did)

    def test_invalid_base58_character_rejected(self):
        with self.assertRaises(ValueError):
            did_key_to_public_key(DID_KEY_PREFIX + "z6Mk0OIl")

    def test_try_variant_returns_none_for_placeholders(self):
        """Display code gets ``None``, not an exception, for non-key labels."""
        self.assertIsNone(try_public_key_to_did_key(""))
        self.assertIsNone(try_public_key_to_did_key("alice"))
        self.assertIsNone(try_public_key_to_did_key(None))

    def test_try_variant_returns_did_for_real_key(self):
        _, public_key_hex = generate_keypair()

        self.assertEqual(
            try_public_key_to_did_key(public_key_hex),
            public_key_to_did_key(public_key_hex),
        )


class IdentityLayerIsAdditiveTests(unittest.TestCase):
    """The DID layer must not disturb signing, hashing, or on-chain identity."""

    def test_transaction_hash_unchanged_by_did_derivation(self):
        private_key, public_key_hex = generate_keypair()
        tx = Transaction(sender=public_key_hex, payload={"a": 1}, timestamp=1234.0)
        before = tx.hash

        public_key_to_did_key(tx.sender)  # deriving a DID touches nothing

        self.assertEqual(tx.hash, before)

    def test_sender_stays_the_hex_public_key(self):
        """On-chain identity is the hex key — a DID is never written to a tx."""
        private_key, public_key_hex = generate_keypair()
        tx = Transaction(sender=public_key_hex, payload={"a": 1}, timestamp=1234.0)
        tx.sign(private_key)

        self.assertEqual(tx.sender, public_key_hex)
        self.assertNotIn("did:key:", tx.signing_bytes().decode())
        self.assertTrue(tx.verify_signature())

    def test_signature_verifies_against_key_recovered_from_did(self):
        """The DID really does carry the verification key: it validates a signature."""
        private_key, public_key_hex = generate_keypair()
        message = b"attestation contents"
        signature = sign(private_key, message)

        did = public_key_to_did_key(public_key_hex)
        recovered_hex = did_key_to_public_key(did).hex()

        self.assertTrue(verify(recovered_hex, message, signature))


if __name__ == "__main__":
    unittest.main()
