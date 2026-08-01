"""Genesis reputation — the axiomatic trust anchor.

Reputation is meant to be *earned*: weight accrues to a participant because
other weighty participants attested to them. That creates a bootstrap paradox —
the very first participants have no one weighty to vouch for them, so their
weight cannot be derived from chain events. Some initial weights must simply be
*declared*. ``GENESIS_REPUTATION`` is that declaration: a hardcoded mapping of
``pubkey -> domain -> weight`` that the protocol takes as given. It is the
unavoidable external trust anchor; everything else is computed from the chain.

Design choice (imposed for this coursework, documented here so it can be
defended): the genesis reputation lives as a standalone constant, **not** as a
transaction inside the genesis block. This keeps the registry independently
testable and decouples reputation bootstrapping from block internals at this
stage.

    Alternative, noted as a future option: encode the genesis weights as a
    special "genesis reputation" transaction in the genesis block, so the trust
    anchor is itself on-chain and covered by the block hash. That couples the
    registry to block construction and is deferred.

The concrete pubkeys below are illustrative placeholders (short readable
strings, not real Ed25519 keys). A deployment would replace them with the hex
public keys of its founding authorities.
"""

from __future__ import annotations

from crypto.keys import keypair_from_seed

# Domain every founding block-producer authority holds infrastructural weight in.
# Authority to produce blocks is any-domain (see ReputationRegistry.is_authority),
# so this domain is deliberately distinct from the competence domains attesters
# vote in — a producer records transactions, it does not judge competence.
CONSENSUS_DOMAIN = "consensus"

# Founding block-producer authorities. Unlike the illustrative attester anchors
# below, these are **real** Ed25519 keys, derived from fixed 32-byte seeds so the
# demo and the tests can reproduce the private half. A producer must actually
# sign its blocks, so a genesis authority has to be a real public key, not a
# readable placeholder. ``name -> (private_key, public_key_hex)``.
_GENESIS_AUTHORITY_SEEDS: dict[str, bytes] = {
    "genesis-authority": bytes.fromhex("01" * 32),
}
GENESIS_AUTHORITY_KEYS = {
    name: keypair_from_seed(seed) for name, seed in _GENESIS_AUTHORITY_SEEDS.items()
}

# pubkey -> domain -> weight. The canonical anchor: two illustrative founding
# participants with weight across overlapping domains (so tests can exercise both
# single-domain and cross-domain / any-domain rules), plus the real genesis
# authority key(s) above, which carry consensus weight so they may produce blocks
# under Proof-of-Authority. This constant is *only* the canonical set; a demo or
# deployment with its own participants injects its own anchor via
# ``derive_registry(..., genesis=...)`` / ``Blockchain(genesis=...)`` rather than
# adding entries here (see network/demo.py).
GENESIS_REPUTATION: dict[str, dict[str, int]] = {
    "genesis-alice": {"bioinformatics": 100, "statistics": 40},
    "genesis-bob": {"bioinformatics": 60},
    **{
        pubkey: {CONSENSUS_DOMAIN: 100}
        for _private, pubkey in GENESIS_AUTHORITY_KEYS.values()
    },
}

# --- Token balances — the economic bond layer -------------------------------
# Reputation is *earned* competence (default 0, accrued by attestation). Tokens
# are a *medium*: a reviewer locks a stake as a bond for honesty when they attest
# and earns a reward when their review holds up (see :mod:`reputation.balances`
# and :mod:`reputation.derive`). A bond system only works if participants have
# tokens to bond with, so — unlike reputation — every identity starts with a
# positive **genesis endowment** rather than zero.
#
# DEFAULT_ENDOWMENT is the uniform baseline any participant the anchor never
# names starts with. It models a testnet faucet so freshly-generated keys can
# post bonds out of the box.
#
#     Known tradeoff (documented for defence): identity here is just a keypair,
#     so a positive universal endowment is effectively a sybil-able faucet — a
#     production system would gate token issuance (purchase, rate-limited faucet,
#     identity binding). The security property that matters still holds *per
#     identity*: you can never bond more than you hold, and a dishonest bond is
#     burned. Crucially, tokens never buy influence — certification is decided by
#     reputation weight, never by stake size (see :mod:`attestation.aggregator`).
DEFAULT_ENDOWMENT = 1000

# Explicit per-participant endowments, overriding the baseline for named founders
# (the concrete "genesis endows initial balances"). Like GENESIS_REPUTATION this
# is *only* the canonical set; a demo or deployment injects its own via
# ``Blockchain(balances=...)`` / ``derive_balances(..., endowments=...)`` rather
# than editing this constant. ``pubkey -> token balance``.
GENESIS_BALANCES: dict[str, int] = {
    "genesis-alice": 5000,
    "genesis-bob": 5000,
    **{pubkey: 5000 for _private, pubkey in GENESIS_AUTHORITY_KEYS.values()},
}
