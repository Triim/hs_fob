"""Tests for the Ed25519 keypair / sign / verify primitive."""

import unittest

from crypto.keys import generate_keypair, sign, verify


class KeyPairTests(unittest.TestCase):
    def test_generate_keypair_shape(self):
        """A keypair is a live private key plus a 32-byte (64 hex char) pubkey."""
        private_key, public_key_hex = generate_keypair()

        self.assertEqual(len(public_key_hex), 64)
        int(public_key_hex, 16)  # valid hex
        # The private key can actually sign — it is a usable key object.
        self.assertIsInstance(sign(private_key, b"hello"), str)

    def test_keypairs_are_distinct(self):
        _, pub_a = generate_keypair()
        _, pub_b = generate_keypair()
        self.assertNotEqual(pub_a, pub_b)


class SignVerifyTests(unittest.TestCase):
    def test_sign_verify_round_trip(self):
        """A signature made with a key verifies against its public key."""
        private_key, public_key_hex = generate_keypair()
        message = b"attestation contents"

        signature = sign(private_key, message)

        self.assertTrue(verify(public_key_hex, message, signature))

    def test_signing_is_deterministic(self):
        """Ed25519 is deterministic: same key + message -> same signature."""
        private_key, _ = generate_keypair()
        message = b"attestation contents"

        self.assertEqual(sign(private_key, message), sign(private_key, message))

    def test_tampered_message_fails(self):
        private_key, public_key_hex = generate_keypair()
        signature = sign(private_key, b"original")

        self.assertFalse(verify(public_key_hex, b"tampered", signature))

    def test_wrong_public_key_fails(self):
        private_key, _ = generate_keypair()
        _, other_public_key_hex = generate_keypair()
        message = b"attestation contents"
        signature = sign(private_key, message)

        self.assertFalse(verify(other_public_key_hex, message, signature))

    def test_malformed_public_key_hex_returns_false(self):
        """Bad input is a False, not an exception — verify is a total predicate."""
        private_key, _ = generate_keypair()
        signature = sign(private_key, b"message")

        self.assertFalse(verify("not-hex", b"message", signature))
        self.assertFalse(verify("abcd", b"message", signature))  # valid hex, wrong length

    def test_malformed_signature_hex_returns_false(self):
        _, public_key_hex = generate_keypair()

        self.assertFalse(verify(public_key_hex, b"message", "not-hex"))
        self.assertFalse(verify(public_key_hex, b"message", "00"))  # valid hex, too short


if __name__ == "__main__":
    unittest.main()
