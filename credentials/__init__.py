"""Reviewer Verifiable Credentials — the *right* to attest.

A Reviewer VC answers one question and only one: **may this key submit an
attestation in this domain at all?** It is an eligibility gate, never a weight.
Reputation still decides how much an accepted attestation counts for (see
:mod:`reputation.tally`), and stake still makes the reviewer accountable for it.
A credential grants no reputation, and it is entirely separate from *validator
authority* (which is chain-derived consensus weight — see
:mod:`reputation.genesis`): holding a Reviewer VC never makes you a validator,
and being a validator never lets you attest without one.
"""
