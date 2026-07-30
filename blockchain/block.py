"""The Block — a batch of transactions committed under one header hash.

A block groups transactions and links to its predecessor by hash, forming the
"chain". Its integrity rests on two hashes:

- the **Merkle root**, which commits to every transaction in the block, and
- the **block hash**, computed over the header (index, previous hash, Merkle
  root, timestamp, producer), which commits to the block as a whole and to its
  place in the chain.

Under Proof-of-Authority the block also carries a ``producer_signature`` — the
producing authority's signature over the header — kept alongside the header
rather than inside it (see ``signing_bytes``), so the signature is not part of
what it signs.

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
from blockchain.transaction import Transaction
from crypto.keys import public_hex
from crypto.keys import sign as _sign
from crypto.keys import verify as _verify


@dataclass
class Block:
    """A single block in the chain.

    Attributes:
        index: Height of the block (0 for genesis). Part of the hashed header.
        previous_hash: Hash of the preceding block, linking the chain together.
        transactions: The transactions this block commits to.
        timestamp: Unix time the block was created. An explicit field so a block
            can be reconstructed deterministically from serialized data.
        producer: Hex Ed25519 public key of the authority that produced this
            block. Empty for the genesis block. It is part of the hashed header,
            so the block commits to who produced it.
        producer_signature: Hex Ed25519 signature by ``producer`` over
            ``signing_bytes()`` (the header), or ``None`` if unproduced. Kept
            *outside* the hashed header — like a transaction's signature — because
            the signature is computed from the header, so folding it back in would
            be circular.
    """

    index: int
    previous_hash: str
    transactions: list[Transaction]
    timestamp: float = field(default_factory=time.time)
    producer: str = ""
    producer_signature: str | None = None

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
            "producer": self.producer,
        }

    def signing_bytes(self) -> bytes:
        """Canonical header bytes — what the block hash and producer signature both cover.

        A canonical (sorted-key, no-whitespace) JSON encoding of the header, the
        single source of truth for what gets hashed *and* what the producer
        signs, so the two can never drift. The ``producer_signature`` is excluded
        (it lives outside the header), avoiding the circularity of signing a value
        that would then include the signature.
        """
        canonical = json.dumps(
            self.header(), sort_keys=True, separators=(",", ":")
        )
        return canonical.encode("utf-8")

    @property
    def hash(self) -> str:
        """Deterministic SHA-256 hex digest of the block header.

        Uses the same canonical encoding as transactions, so the digest is stable
        across runs and machines and can be recomputed by any peer. Recomputed on
        access, so it always reflects the current header (producer, merkle_root, …).
        """
        return hashlib.sha256(self.signing_bytes()).hexdigest()

    def sign_as_producer(self, private_key) -> None:
        """Record the producer and sign the header in place.

        Sets ``producer`` to ``private_key``'s public key, then signs
        ``signing_bytes()`` — so the producer identity is fixed *before* it is
        signed and is itself part of what the signature (and the hash) commit to.
        """
        self.producer = public_hex(private_key)
        self.producer_signature = _sign(private_key, self.signing_bytes())

    def verify_producer_signature(self) -> bool:
        """Whether ``producer_signature`` is a valid signature by ``producer`` over the header.

        Returns ``False`` for an unsigned/unproduced block and for any
        bad/malformed signature — never raises, so callers can treat it as a
        plain predicate.
        """
        if self.producer_signature is None:
            return False
        return _verify(self.producer, self.signing_bytes(), self.producer_signature)

    def to_dict(self) -> dict:
        """Full JSON-serializable view: header fields plus the transactions.

        This is the shape a peer would send and re-hash to validate the block.
        """
        return {
            "index": self.index,
            "previous_hash": self.previous_hash,
            "merkle_root": self.merkle_root,
            "timestamp": self.timestamp,
            "producer": self.producer,
            "producer_signature": self.producer_signature,
            "hash": self.hash,
            "transactions": [tx.to_dict() for tx in self.transactions],
        }
