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

# pubkey -> domain -> weight. A small, deliberately illustrative anchor set: two
# founding participants with weight across overlapping domains, so tests can
# exercise both single-domain and cross-domain (any-domain) rules.
GENESIS_REPUTATION: dict[str, dict[str, int]] = {
    "genesis-alice": {"bioinformatics": 100, "statistics": 40},
    "genesis-bob": {"bioinformatics": 60},
}
