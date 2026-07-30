"""The Blockchain — an ordered, tamper-evident list of produced blocks.

The chain starts from a fixed **genesis block** (a trusted anchor every node
builds identically) and grows as authorities produce new blocks from pending
transactions.

Consensus: Proof-of-Authority
-----------------------------
Validity is decided by **Proof-of-Authority**, not proof-of-work. A non-genesis
block is valid only if its ``producer_signature`` verifies against its
``producer`` *and* that producer is an authority under the reputation derived
from the chain **prefix before this block** (blocks ``0 .. N-1`` when validating
block N). Checking against the prefix — never including block N itself — is what
breaks the circularity: a block's validity depends on state that is already
agreed *before* it, so a block can never bootstrap its own producer's authority
(see :func:`reputation.derive.derive_registry`). There is no proof-of-work: block
production is a signature, not a mining search.

How tampering is caught
-----------------------
Each block exposes ``hash`` and ``merkle_root`` as *computed* properties, so a
block can never disagree with itself. Detection comes from chain-level invariants
that ``is_valid_chain`` enforces:

1. **Link integrity** — every block stores its predecessor's hash in
   ``previous_hash``. Tampering with a *past* transaction changes that block's
   hash, but the following block still carries the old value, so the link breaks.
2. **Producer signature** — every non-genesis block's header is signed by its
   producer. Tampering with the *last* block's transaction changes its Merkle
   root and therefore its header, so the producer's signature no longer verifies.
3. **Authority by prefix** — the producer must hold authority weight under the
   reputation implied by all earlier blocks.

Together these cover tampering anywhere in the chain.
"""

from __future__ import annotations

from blockchain.block import Block
from blockchain.merkle import MerkleTree
from blockchain.transaction import Transaction
from reputation.derive import derive_registry

# Fixed genesis parameters — identical on every node so chains share one root.
GENESIS_PREVIOUS_HASH = "0" * 64
GENESIS_TIMESTAMP = 0.0

# Minimum reputation weight (in any single domain) a block producer must hold to
# be an authority. A documented constant so the security/liveness trade-off is
# tunable and explicit. Genesis authorities carry 100 consensus weight, well
# above this floor.
AUTHORITY_THRESHOLD = 50


class Blockchain:
    """An append-only chain of produced blocks with a pending-transaction pool."""

    def __init__(self) -> None:
        """Create a chain with only the genesis block."""
        self.blocks: list[Block] = [self._create_genesis_block()]
        self.mempool: list[Transaction] = []

    @staticmethod
    def _create_genesis_block() -> Block:
        """Build the fixed genesis block.

        Uses hardcoded values (no transactions, fixed timestamp, nonce 0) so the
        genesis block — and therefore its hash — is identical on every node. The
        genesis block is a trusted anchor and is not mined.
        """
        return Block(
            index=0,
            previous_hash=GENESIS_PREVIOUS_HASH,
            transactions=[],
            timestamp=GENESIS_TIMESTAMP,
            nonce=0,
        )

    @property
    def last_block(self) -> Block:
        """The most recent block in the chain."""
        return self.blocks[-1]

    def add_transaction(self, transaction: Transaction) -> None:
        """Add a transaction to the pending pool (mempool).

        Pooled transactions are not part of the chain until a block that
        includes them is mined via :meth:`add_block`.
        """
        self.mempool.append(transaction)

    def add_block(self, producer_key=None) -> Block:
        """Pack all pending transactions into a new block and append it.

        Links the new block to the current tip. Under Proof-of-Authority there is
        no mining loop: if a ``producer_key`` is given the block is signed by that
        authority (the live validity rule); if omitted the block is left
        unproduced (useful for unit tests that only need blocks to *exist* for
        scanning, and never validate the chain). Clears the mempool and returns
        the new block.

        Args:
            producer_key: Optional Ed25519 private key of the producing authority.
                When provided, the block's ``producer`` and ``producer_signature``
                are set so it passes :meth:`is_valid_chain`.
        """
        block = Block(
            index=len(self.blocks),
            previous_hash=self.last_block.hash,
            transactions=list(self.mempool),  # snapshot so later edits can't sneak in
        )
        if producer_key is not None:
            block.sign_as_producer(producer_key)
        self.blocks.append(block)
        self.mempool.clear()
        return block

    def replace_chain(self, candidate_blocks: list[Block]) -> bool:
        """Adopt ``candidate_blocks`` if it is a strictly longer, valid PoA chain.

        This is the **fork-choice rule**: *the longest valid chain wins*. A
        competing chain is accepted only when it (a) is strictly longer than the
        current one and (b) validates end to end as a PoA chain — same genesis,
        intact links, every producer signature valid, every producer an authority
        by the prefix. Ties (equal length) keep the current chain, so a node never
        churns between chains of the same height.

        On acceptance the blocks are swapped in and the mempool is recomputed:
        any pending transaction that the adopted chain already commits is dropped,
        so it is not mined twice.

        Returns:
            ``True`` if the candidate was adopted, ``False`` if it was refused.
        """
        if len(candidate_blocks) <= len(self.blocks):
            return False

        # Validate the candidate in isolation by reusing is_valid_chain (which
        # also checks the genesis matches the canonical one).
        candidate = Blockchain()
        candidate.blocks = list(candidate_blocks)
        if not candidate.is_valid_chain():
            return False

        self.blocks = list(candidate_blocks)
        committed = {tx.hash for block in self.blocks for tx in block.transactions}
        self.mempool = [tx for tx in self.mempool if tx.hash not in committed]
        return True

    def is_valid_chain(self) -> bool:
        """Validate the whole chain under Proof-of-Authority.

        Checks, for the genesis block, that it matches the canonical genesis, and
        for every later block: correct index, an intact ``previous_hash`` link, a
        Merkle root that matches its transactions, a valid ``producer_signature``,
        and a ``producer`` who is an authority under reputation derived from the
        chain **prefix before that block**. Returns ``True`` only if every check
        passes.
        """
        if self.blocks[0].hash != self._create_genesis_block().hash:
            return False

        for i in range(1, len(self.blocks)):
            block = self.blocks[i]
            previous = self.blocks[i - 1]

            if block.index != i:
                return False
            # Link integrity: catches tampering with any earlier block.
            if block.previous_hash != previous.hash:
                return False
            # Merkle root commits to the block's transactions.
            if block.merkle_root != MerkleTree(block.transactions).root:
                return False
            # PoA (1): the header must be signed by its producer. Tampering the
            # last block changes its header, so this catches it (replaces PoW).
            if not block.verify_producer_signature():
                return False
            # PoA (2): the producer must be an authority under reputation derived
            # from the PREFIX (blocks 0..i-1), never from this block itself — the
            # prefix rule that breaks the validity/authority circularity.
            prefix_registry = derive_registry(self, upto_index=block.index)
            if not prefix_registry.is_authority(block.producer, AUTHORITY_THRESHOLD):
                return False

        return True
