"""Cryptographic primitives for the chain (CS414 — Fundamentals of Blockchain).

A thin, purpose-built wrapper over Ed25519 keypairs, signing and verification.
It exists so the rest of the system deals only in hex strings and ``bytes`` and
never has to import ``cryptography`` directly — keeping the signature scheme a
single, replaceable seam.
"""
