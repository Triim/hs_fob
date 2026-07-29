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

# pubkey -> domain -> weight. A small, deliberately illustrative anchor set: two
# founding participants with weight across overlapping domains, so tests can
# exercise both single-domain and cross-domain (any-domain) rules — plus the real
# genesis authority key(s) above, which carry consensus weight so they may
# produce blocks under Proof-of-Authority.
GENESIS_REPUTATION: dict[str, dict[str, int]] = {
    "genesis-alice": {"bioinformatics": 100, "statistics": 40},
    "genesis-bob": {"bioinformatics": 60},
    # Founding attesters used by the multi-node demo (network/demo.py). They are
    # declared here — rather than hand-built into a throwaway registry — because
    # reputation is derived only from the chain seeded by this anchor, so their
    # standing must be part of the anchor for the demo's certification to carry.
    "attester-alice": {"general": 100},
    "attester-bob": {"general": 100},
    "attester-carol": {"general": 100},
    **{
        pubkey: {CONSENSUS_DOMAIN: 100}
        for _private, pubkey in GENESIS_AUTHORITY_KEYS.values()
    },
}
