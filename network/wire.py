"""Wire serialization bridge — the seam between the core and the network.

Peers exchange transactions and blocks as text. This module is the *only* place
that turns core objects into wire strings and back, so the rest of the system
never has to think about encoding. It is built entirely on the serialization
that already exists — ``Transaction.to_dict`` / ``Block.to_dict`` — rather than
any new binary format: the wire form is just JSON of those dicts.

Two properties make this the trust boundary:

- **Round-trip fidelity.** ``wire_to_tx(tx_to_wire(tx))`` reconstructs an object
  equal (same hash) to the original, because it feeds the exact recorded fields
  back through the real constructors.
- **Self-checking blocks.** ``Block.to_dict`` also carries the *derived*
  ``merkle_root`` and ``hash``. On decode these are recomputed from the
  reconstructed block and compared against the values that arrived; a mismatch
  means the payload was corrupted or forged, and we refuse it rather than hand a
  quietly-wrong block to the core.

Keys are emitted sorted so a given object always produces the same wire bytes —
useful later for signing and for byte-for-byte equality in tests.
"""

from __future__ import annotations

import json

from blockchain.block import Block
from blockchain.transaction import Transaction


def tx_to_wire(tx: Transaction) -> str:
    """Serialize a transaction to its JSON wire string."""
    return json.dumps(tx.to_dict(), sort_keys=True, separators=(",", ":"))


def wire_to_tx(s: str) -> Transaction:
    """Reconstruct a transaction from its wire string.

    Feeds the recorded ``sender``, ``payload`` and ``timestamp`` back through the
    ``Transaction`` constructor, so the timestamp is preserved and the rebuilt
    transaction hashes identically to the original.

    Raises:
        ValueError: if the string is not valid JSON or is missing a field.
    """
    try:
        data = json.loads(s)
    except json.JSONDecodeError as exc:
        raise ValueError(f"malformed transaction wire data: {exc}") from exc
    return _tx_from_dict(data)


def block_to_wire(block: Block) -> str:
    """Serialize a block to its JSON wire string.

    Uses ``Block.to_dict``, which includes the transactions and the derived
    ``merkle_root``/``hash`` — the latter two let the decoder verify integrity.
    """
    return json.dumps(block.to_dict(), sort_keys=True, separators=(",", ":"))


def wire_to_block(s: str) -> Block:
    """Reconstruct and verify a block from its wire string.

    Rebuilds the block from its *stored* fields (never from the derived
    ``merkle_root``/``hash``, which are computed properties), then recomputes
    those derived values and checks them against what arrived. This makes the
    seam self-checking: a tampered block is rejected here, before it can reach
    the chain.

    Raises:
        ValueError: on malformed JSON, a missing field, or a merkle-root/hash
            mismatch between the recomputed and the transmitted values.
    """
    try:
        data = json.loads(s)
    except json.JSONDecodeError as exc:
        raise ValueError(f"malformed block wire data: {exc}") from exc
    return _block_from_dict(data)


def chain_to_wire(blocks: list[Block]) -> str:
    """Serialize a whole chain (list of blocks) to a single JSON wire string.

    Used by fork choice: on divergence a node ships its entire chain so a peer
    can validate and possibly adopt it (see :meth:`Blockchain.replace_chain`).
    """
    return json.dumps(
        [block.to_dict() for block in blocks], sort_keys=True, separators=(",", ":")
    )


def wire_to_chain(s: str) -> list[Block]:
    """Reconstruct and verify a whole chain from its wire string.

    Each block is rebuilt and integrity-checked exactly as in
    :func:`wire_to_block`. Consensus validity of the chain as a whole (links,
    producer signatures, authority) is *not* checked here — that is the core's
    job in :meth:`Blockchain.replace_chain`; this only guarantees each block was
    transmitted intact.

    Raises:
        ValueError: on malformed JSON, a non-list payload, or any block that
            fails its own integrity check.
    """
    try:
        data = json.loads(s)
    except json.JSONDecodeError as exc:
        raise ValueError(f"malformed chain wire data: {exc}") from exc
    if not isinstance(data, list):
        raise ValueError("chain wire data must be a list of blocks")
    return [_block_from_dict(d) for d in data]


def _block_from_dict(data: dict) -> Block:
    """Rebuild and integrity-check a single Block from a ``to_dict`` mapping.

    Raises:
        ValueError: on a missing field or a merkle-root/hash mismatch between the
            recomputed and the transmitted values.
    """
    for key in ("index", "previous_hash", "timestamp", "nonce", "transactions"):
        if key not in data:
            raise ValueError(f"block wire data missing field: {key!r}")

    transactions = [_tx_from_dict(tx) for tx in data["transactions"]]
    block = Block(
        index=data["index"],
        previous_hash=data["previous_hash"],
        transactions=transactions,
        timestamp=data["timestamp"],
        nonce=data["nonce"],
        # ``producer`` is part of the hashed header, so it must be restored before
        # the integrity check below; ``producer_signature`` rides alongside (it is
        # outside the header) and is optional — the genesis block has none.
        producer=data.get("producer", ""),
        producer_signature=data.get("producer_signature"),
    )

    # Integrity gate: the derived values must match what the sender committed to.
    if "merkle_root" in data and block.merkle_root != data["merkle_root"]:
        raise ValueError("merkle_root mismatch: block failed integrity check")
    if "hash" in data and block.hash != data["hash"]:
        raise ValueError("hash mismatch: block failed integrity check")

    return block


def _tx_from_dict(data: dict) -> Transaction:
    """Rebuild a Transaction from a ``to_dict`` mapping, validating its shape.

    ``signature`` is optional — an unsigned transaction omits it or carries
    ``null`` — so it is read with a default and never required, unlike the
    content fields that the hash depends on.
    """
    for key in ("sender", "payload", "timestamp"):
        if key not in data:
            raise ValueError(f"transaction wire data missing field: {key!r}")
    return Transaction(
        sender=data["sender"],
        payload=data["payload"],
        timestamp=data["timestamp"],
        signature=data.get("signature"),
    )
