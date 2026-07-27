"""The Blockchain — an ordered, tamper-evident list of mined blocks.

The chain starts from a fixed **genesis block** (a trusted anchor every node
builds identically) and grows by mining pending transactions into new blocks.

How tampering is caught
-----------------------
Each block exposes ``hash`` and ``merkle_root`` as *computed* properties, so a
block can never disagree with itself — re-hashing a block in isolation always
matches. Detection therefore comes from two chain-level invariants that
``is_valid_chain`` enforces:

1. **Link integrity** — every block stores its predecessor's hash in
   ``previous_hash``. Tampering with a *past* transaction changes that block's
   hash, but the following block still carries the old value, so the link
   breaks.
2. **Proof-of-work** — every mined block's hash must meet the difficulty target.
   Tampering with the *last* block's transaction changes its hash, which almost
   certainly no longer has enough leading zero bits, so the PoW check fails.

Together these cover tampering anywhere in the chain.
"""

from __future__ import annotations

from blockchain.block import Block
from blockchain.merkle import MerkleTree
from blockchain.proof_of_work import hash_meets_target
from blockchain.transaction import Transaction

# Fixed genesis parameters — identical on every node so chains share one root.
GENESIS_PREVIOUS_HASH = "0" * 64
GENESIS_TIMESTAMP = 0.0


class Blockchain:
    """An append-only chain of mined blocks with a pending-transaction pool."""

    def __init__(self, difficulty: int = 12) -> None:
        """Create a chain with only the genesis block.

        Args:
            difficulty: Required leading zero bits for every mined block. A
                parameter (not hardcoded) so demos and tests can trade security
                for speed.
        """
        self.difficulty = difficulty
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

    def add_block(self) -> Block:
        """Mine all pending transactions into a new block and append it.

        Links the new block to the current tip, mines it to the chain's
        difficulty, appends it, and clears the mempool. Returns the new block.
        """
        block = Block(
            index=len(self.blocks),
            previous_hash=self.last_block.hash,
            transactions=list(self.mempool),  # snapshot so later edits can't sneak in
        )
        block.mine(self.difficulty)
        self.blocks.append(block)
        self.mempool.clear()
        return block

    def is_valid_chain(self) -> bool:
        """Validate the whole chain.

        Checks, for the genesis block, that it matches the canonical genesis,
        and for every later block: correct index, an intact ``previous_hash``
        link, a Merkle root that matches its transactions, and a hash that meets
        the difficulty target. Returns ``True`` only if every check passes.
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
            # Proof-of-work: catches tampering with the latest block.
            if not hash_meets_target(block.hash, self.difficulty):
                return False

        return True
