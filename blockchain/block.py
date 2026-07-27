"""The Block — a batch of transactions committed under one header hash.

A block groups transactions and links to its predecessor by hash, forming the
"chain". Its integrity rests on two hashes:

- the **Merkle root**, which commits to every transaction in the block, and
- the **block hash**, computed over the header (index, previous hash, Merkle
  root, timestamp, nonce), which commits to the block as a whole and to its
  place in the chain.

Because the block hash includes the Merkle root, tampering with any single
transaction changes the root and therefore the block hash — which in turn
breaks the ``previous_hash`` link of the next block. That cascade is what makes
the chain tamper-evident.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field

from blockchain.merkle import MerkleTree
from blockchain.proof_of_work import hash_meets_target
from blockchain.transaction import Transaction


@dataclass
class Block:
    """A single block in the chain.

    Attributes:
        index: Height of the block (0 for genesis). Part of the hashed header.
        previous_hash: Hash of the preceding block, linking the chain together.
        transactions: The transactions this block commits to.
        timestamp: Unix time the block was created. An explicit field so a block
            can be reconstructed deterministically from serialized data.
        nonce: Proof-of-work counter, mutated during mining (a later step) until
            the block hash meets the difficulty target.
    """

    index: int
    previous_hash: str
    transactions: list[Transaction]
    timestamp: float = field(default_factory=time.time)
    nonce: int = 0

    @property
    def merkle_root(self) -> str:
        """Merkle root over this block's transactions.

        Computed on access so it always reflects the current transactions; an
        empty block yields the Merkle tree's constant empty root.
        """
        return MerkleTree(self.transactions).root

    def header(self) -> dict:
        """The hashed portion of the block.

        This deliberately excludes the transactions themselves — they are
        committed to via ``merkle_root`` — so the header is small and fixed-size
        regardless of how many transactions the block carries.
        """
        return {
            "index": self.index,
            "previous_hash": self.previous_hash,
            "merkle_root": self.merkle_root,
            "timestamp": self.timestamp,
            "nonce": self.nonce,
        }

    @property
    def hash(self) -> str:
        """Deterministic SHA-256 hex digest of the block header.

        Uses the same canonical (sorted-key, no-whitespace) JSON encoding as
        transactions, so the digest is stable across runs and machines and can
        be recomputed by any peer. Recomputed on access, so it always reflects
        the current nonce during mining.
        """
        canonical = json.dumps(
            self.header(), sort_keys=True, separators=(",", ":")
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def mine(self, difficulty: int) -> int:
        """Search for a nonce whose block hash meets ``difficulty``.

        Increments the nonce until the block hash has at least ``difficulty``
        leading zero bits. Mutates ``self.nonce`` in place and returns the
        number of nonce values tried, so callers can report the work done.

        Difficulty is a parameter (not hardcoded) so tests can stay fast and the
        chain can tune it later.
        """
        attempts = 1
        while not hash_meets_target(self.hash, difficulty):
            self.nonce += 1
            attempts += 1
        return attempts

    def to_dict(self) -> dict:
        """Full JSON-serializable view: header fields plus the transactions.

        This is the shape a peer would send and re-hash to validate the block.
        """
        return {
            "index": self.index,
            "previous_hash": self.previous_hash,
            "merkle_root": self.merkle_root,
            "timestamp": self.timestamp,
            "nonce": self.nonce,
            "hash": self.hash,
            "transactions": [tx.to_dict() for tx in self.transactions],
        }
