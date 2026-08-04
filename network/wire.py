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


# Envelope key carrying a reviewer's credential presentation alongside — never
# inside — a transaction. See :func:`tx_to_wire`.
PRESENTATION_KEY = "credential_presentation"


def tx_to_wire(tx: Transaction, presentation: dict | None = None) -> str:
    """Serialize a transaction to its JSON wire string.

    ``presentation`` is an optional reviewer-credential presentation
    (:mod:`credentials.presentation`) that an attestation must travel with to be
    admitted. It is written as a **sibling** of the transaction's own fields
    under :data:`PRESENTATION_KEY`, not into the payload: the transaction's
    ``to_dict`` shape, its signing bytes and its hash are untouched, so no
    transaction, block or consensus format changes and no credential ever reaches
    the chain. A transaction with no presentation serializes byte-for-byte as it
    always did.
    """
    data = tx.to_dict()
    if presentation is not None:
        data = {**data, PRESENTATION_KEY: presentation}
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


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


def wire_to_presentation(s: str) -> dict | None:
    """Extract the credential presentation riding on a transaction wire string.

    Returns ``None`` when the envelope carries none (or carries something that is
    not a JSON object), so the caller can treat "absent" and "malformed" alike —
    both simply fail the eligibility gate rather than raising.

    Raises:
        ValueError: if the string is not valid JSON at all, mirroring
            :func:`wire_to_tx` so a malformed envelope is rejected once.
    """
    try:
        data = json.loads(s)
    except json.JSONDecodeError as exc:
        raise ValueError(f"malformed transaction wire data: {exc}") from exc
    if not isinstance(data, dict):
        return None
    presentation = data.get(PRESENTATION_KEY)
    return presentation if isinstance(presentation, dict) else None


def block_to_wire(block: Block) -> str:
    """Serialize a block to its JSON wire string.

    Uses ``Block.to_dict``, which includes the transactions, the derived
    ``merkle_root``/``hash`` (the latter two let the decoder verify integrity), and
    the ``commit_signatures`` — so a block carries its finality votes with it, and
    a peer that syncs the block also learns which validators have committed it.
    """
    return json.dumps(block.to_dict(), sort_keys=True, separators=(",", ":"))


def commit_to_wire(block_hash: str, signer: str, signature: str) -> str:
    """Serialize one validator's commit vote to its JSON wire string.

    A commit references the block it finalizes **by hash** (commit signatures live
    outside the block hash, so the hash is a stable id), and carries the signer's
    public key and their Ed25519 signature over that block's header. Identity is
    the pubkey, never an address.
    """
    return json.dumps(
        {"block_hash": block_hash, "signer": signer, "signature": signature},
        sort_keys=True,
        separators=(",", ":"),
    )


def view_change_to_wire(height: int, view: int, signer: str, signature: str) -> str:
    """Serialize one validator's view-change vote to its JSON wire string.

    A view-change vote says "advance to ``view`` at ``height``" and carries the
    voter's public key plus their Ed25519 signature over
    :func:`blockchain.block.view_change_signing_bytes`. Identity is the pubkey,
    never an address — mirroring :func:`commit_to_wire`.
    """
    return json.dumps(
        {"height": height, "view": view, "signer": signer, "signature": signature},
        sort_keys=True,
        separators=(",", ":"),
    )


def wire_to_view_change(s: str) -> dict:
    """Reconstruct a view-change vote ``{height, view, signer, signature}`` from wire.

    Raises:
        ValueError: on malformed JSON, a non-object, a missing/wrong-typed field
            (``height``/``view`` must be ints, ``signer``/``signature`` strings), so
            the caller can drop an ill-formed vote without ever raising.
    """
    try:
        data = json.loads(s)
    except json.JSONDecodeError as exc:
        raise ValueError(f"malformed view-change wire data: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError("view-change wire data must be an object")
    for key in ("height", "view"):
        if isinstance(data.get(key), bool) or not isinstance(data.get(key), int):
            raise ValueError(f"view-change wire data missing/!int field: {key!r}")
    for key in ("signer", "signature"):
        if not isinstance(data.get(key), str):
            raise ValueError(f"view-change wire data missing/!str field: {key!r}")
    return {k: data[k] for k in ("height", "view", "signer", "signature")}


def wire_to_commit(s: str) -> dict:
    """Reconstruct a commit vote ``{block_hash, signer, signature}`` from wire.

    Raises:
        ValueError: on malformed JSON, a missing field, or a non-string field —
            so the caller can drop an ill-formed commit without ever raising.
    """
    try:
        data = json.loads(s)
    except json.JSONDecodeError as exc:
        raise ValueError(f"malformed commit wire data: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError("commit wire data must be an object")
    for key in ("block_hash", "signer", "signature"):
        if not isinstance(data.get(key), str):
            raise ValueError(f"commit wire data missing/!str field: {key!r}")
    return {k: data[k] for k in ("block_hash", "signer", "signature")}


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
    for key in ("index", "previous_hash", "timestamp", "transactions"):
        if key not in data:
            raise ValueError(f"block wire data missing field: {key!r}")

    transactions = [_tx_from_dict(tx) for tx in data["transactions"]]

    # Commit signatures ride outside the hashed header (like producer_signature),
    # so they are restored but do not affect the integrity check below. Read
    # defensively: keep only well-formed ``str -> str`` entries, so a malformed map
    # cannot crash the decoder — each signature is re-verified as a real validator
    # commit by consensus (is_valid_chain / on_commit) before it counts anyway.
    raw_commits = data.get("commit_signatures", {})
    commit_signatures = (
        {k: v for k, v in raw_commits.items() if isinstance(k, str) and isinstance(v, str)}
        if isinstance(raw_commits, dict)
        else {}
    )

    # View-change justification rides outside the hashed header too (like
    # commit_signatures): restored defensively as ``str -> str`` so a malformed map
    # can't crash the decoder. Each entry is re-verified as a genuine validator
    # view-change vote by consensus (is_valid_chain) before it justifies anything.
    raw_vc = data.get("view_change_messages", {})
    view_change_messages = (
        {k: v for k, v in raw_vc.items() if isinstance(k, str) and isinstance(v, str)}
        if isinstance(raw_vc, dict)
        else {}
    )

    block = Block(
        index=data["index"],
        previous_hash=data["previous_hash"],
        transactions=transactions,
        timestamp=data["timestamp"],
        # ``view`` is part of the hashed header (like ``producer``), so it must be
        # restored before the integrity check below; it defaults to 0 for a normal
        # first-attempt block and older payloads that predate view-change.
        view=data.get("view", 0),
        # ``producer`` is part of the hashed header, so it must be restored before
        # the integrity check below; ``producer_signature`` rides alongside (it is
        # outside the header) and is optional — the genesis block has none.
        producer=data.get("producer", ""),
        producer_signature=data.get("producer_signature"),
        commit_signatures=commit_signatures,
        view_change_messages=view_change_messages,
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
