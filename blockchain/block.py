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

Finality is BFT-style: beyond the single producer signature, a block collects
``commit_signatures`` — a map of ``validator_pubkey -> signature`` over the same
canonical header. A block is *final* once a quorum of the current validator set
has committed it (the quorum test lives in :mod:`blockchain.blockchain`, which
knows the validator set). Like ``producer_signature``, commit signatures live
**outside** the hashed header: they are computed *from* the header, so folding
them back into the hash would be circular, and different nodes may hold different
subsets of the same signatures without changing the block's identity.

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


def view_change_signing_bytes(height: int, view: int) -> bytes:
    """Canonical bytes a validator signs to vote for advancing to ``view`` at ``height``.

    A sorted-key, whitespace-free JSON encoding of the ``(height, view)`` statement,
    so a voter and every verifier produce byte-for-byte identical input regardless
    of machine. A view-change vote is a validator asserting "the proposer scheduled
    for the previous view at this height did not deliver, so I agree to rotate to
    ``view``". Binding the signature to *both* height and view means a vote can
    never be replayed to justify a different height or a further view advance.
    """
    canonical = json.dumps(
        {"type": "view-change", "height": height, "view": view},
        sort_keys=True,
        separators=(",", ":"),
    )
    return canonical.encode("utf-8")


@dataclass
class Block:
    """A single block in the chain.

    Attributes:
        index: Height of the block (0 for genesis). Part of the hashed header.
        previous_hash: Hash of the preceding block, linking the chain together.
        transactions: The transactions this block commits to.
        timestamp: Unix time the block was created. An explicit field so a block
            can be reconstructed deterministically from serialized data.
        view: The consensus *view* this block was produced in (0 for the normal,
            first-attempt proposer). Part of the hashed header, so the block
            commits to the view it claims: the producer must be the proposer the
            deterministic schedule assigns to ``(index, view)``, and any view above
            0 must be justified by a quorum of ``view_change_messages`` (both rules
            live in :meth:`blockchain.blockchain.Blockchain.is_valid_chain`). This
            is what lets a stalled proposer be rotated past without halting the
            chain, while keeping every produced block deterministically attributable.
        producer: Hex Ed25519 public key of the authority that produced this
            block. Empty for the genesis block. It is part of the hashed header,
            so the block commits to who produced it.
        producer_signature: Hex Ed25519 signature by ``producer`` over
            ``signing_bytes()`` (the header), or ``None`` if unproduced. Kept
            *outside* the hashed header — like a transaction's signature — because
            the signature is computed from the header, so folding it back in would
            be circular.
        commit_signatures: Map of ``validator_pubkey -> hex signature`` over
            ``signing_bytes()`` (the same header the producer signs). Each entry is
            one validator's vote that this block is valid; a block is *final* once a
            quorum of the current validator set appears here with valid signatures
            (see :mod:`blockchain.blockchain`). Like ``producer_signature`` these
            live outside the hashed header, so collecting more of them never changes
            the block's hash or identity.
        view_change_messages: Map of ``validator_pubkey -> hex signature`` over
            :func:`view_change_signing_bytes` for this block's ``(index, view)``.
            Present only on a block produced in a view above 0, where they are the
            **justification** that a quorum of validators agreed to rotate to that
            view after the earlier proposer(s) stalled. Like ``commit_signatures``
            they ride *outside* the hashed header (they are computed from the header
            fields, not part of them), so gathering them never changes the block's
            identity; consensus re-verifies them in ``is_valid_chain``.
    """

    index: int
    previous_hash: str
    transactions: list[Transaction]
    timestamp: float = field(default_factory=time.time)
    view: int = 0
    producer: str = ""
    producer_signature: str | None = None
    commit_signatures: dict[str, str] = field(default_factory=dict)
    view_change_messages: dict[str, str] = field(default_factory=dict)

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
            "view": self.view,
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

    def add_commit_signature(self, validator_private_key) -> None:
        """Record one validator's commit vote for this block, in place.

        Signs ``signing_bytes()`` — the exact header the producer signed — with
        ``validator_private_key`` and stores it under that key's public hex. A
        commit signature is a validator asserting "I have seen this block and
        consider it valid"; enough of them (a quorum of the validator set) make the
        block final. Re-committing by the same validator simply overwrites its own
        (identical, since Ed25519 is deterministic) entry, so committing twice is
        idempotent and cannot inflate the count.
        """
        pubkey = public_hex(validator_private_key)
        self.commit_signatures[pubkey] = _sign(
            validator_private_key, self.signing_bytes()
        )

    def commit_signers(self) -> set[str]:
        """The set of pubkeys whose commit signature *validly* covers this header.

        Each stored ``commit_signatures`` entry is re-verified against
        ``signing_bytes()``, so a forged or malformed signature is silently
        dropped rather than counted. This returns cryptographically genuine
        signers only; whether each is an actual *validator* (and whether they reach
        quorum) is decided by the caller against the chain-derived validator set
        (see :meth:`blockchain.blockchain.Blockchain.is_final`).
        """
        return {
            pubkey
            for pubkey, signature in self.commit_signatures.items()
            if _verify(pubkey, self.signing_bytes(), signature)
        }

    def view_change_signers(self) -> set[str]:
        """Pubkeys whose ``view_change_messages`` entry validly votes for this view.

        Each stored entry is re-verified against
        :func:`view_change_signing_bytes` for this block's own ``(index, view)``, so
        a forged, malformed, or wrong-height/view signature is silently dropped
        rather than counted. This returns cryptographically genuine view-change
        voters only; whether each is an actual *validator* (and whether they reach
        quorum, justifying ``view > 0``) is decided by the caller against the
        chain-derived validator set (see
        :meth:`blockchain.blockchain.Blockchain.is_valid_chain`).
        """
        message = view_change_signing_bytes(self.index, self.view)
        return {
            pubkey
            for pubkey, signature in self.view_change_messages.items()
            if _verify(pubkey, message, signature)
        }

    def to_dict(self) -> dict:
        """Full JSON-serializable view: header fields plus the transactions.

        This is the shape a peer would send and re-hash to validate the block.
        ``commit_signatures`` and ``view_change_messages`` ride alongside (outside
        the header, like ``producer_signature``) so finality votes and — for a
        view-changed block — its rotation justification propagate with the block.
        """
        return {
            "index": self.index,
            "previous_hash": self.previous_hash,
            "merkle_root": self.merkle_root,
            "timestamp": self.timestamp,
            "view": self.view,
            "producer": self.producer,
            "producer_signature": self.producer_signature,
            "commit_signatures": dict(self.commit_signatures),
            "view_change_messages": dict(self.view_change_messages),
            "hash": self.hash,
            "transactions": [tx.to_dict() for tx in self.transactions],
        }
