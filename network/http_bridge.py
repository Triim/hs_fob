"""HTTP bridge — a JSON view of, and write path into, a live IPv8 node.

This is the UI-facing layer. It exposes a running
:class:`~network.community.AttestationCommunity`'s state to a browser over HTTP,
reading **through the real objects** (the node's :class:`Blockchain`, its
chain-derived :class:`~reputation.registry.ReputationRegistry`, its mempool and
its peers) — never a parallel copy that could drift.

Write model (client-side signing)
---------------------------------
Writes follow the real trust model, not a simulation: the **client** holds the
key and signs the transaction; the node only **validates and relays**. ``POST
/api/tx`` accepts a fully-formed, already-signed participant transaction, runs it
through the exact same gate the gossip receiver and the chain use
(:meth:`AttestationCommunity.accepts_transaction` — a well-formed
attestation/submission/slash whose signature verifies against its ``sender``),
and only then pools and gossips it. **The node never signs participant
transactions and never holds a participant's private key.** ``POST /api/mine``
tells the node to produce a block from its own mempool with its *own* producer
key (a producer producing its own blocks — not impersonation).

Event-loop integration
-----------------------
IPv8 runs on an asyncio event loop. This bridge shares that *same* loop: it uses
aiohttp (async-native) started via :class:`~aiohttp.web.AppRunner` +
:class:`~aiohttp.web.TCPSite`, awaited on the running loop — **not**
``web.run_app`` (which owns and blocks the loop) and **not** a WSGI server on a
second thread (which would race IPv8's single-threaded state). :func:`attach_http_bridge`
is therefore a coroutine: you ``await`` it from inside the loop that is already
running IPv8, and it returns the ``AppRunner`` so the caller can ``cleanup()``.

Identity
--------
Two distinct keys meet here, and the bridge keeps them separate:

* the **network/transport identity** — the node's IPv8 peer public key, whose
  20-byte ``mid`` is the short id peers are known by (used for ``/api/node``'s
  ``id``/``public_key`` and all of ``/api/peers``); and
* the **producer identity** — the Ed25519 key the node signs blocks with, which
  is what reputation and authority are keyed on (used for ``/api/node``'s
  ``is_authority`` and ``weights``).

Everyone is identified by public key, never by network address.

Endpoints: five read-only GETs (``/api/node``, ``/api/chain``, ``/api/mempool``,
``/api/reputation``, ``/api/peers``) and two writes (``/api/tx``, ``/api/mine``).
No WebSocket yet — that is a later step.
"""

from __future__ import annotations

import json

from aiohttp import web

from attestation.attestation import is_attestation
from attestation.aggregator import CERTIFICATE_TYPE
from attestation.submission import is_submission
from blockchain.blockchain import AUTHORITY_THRESHOLD
from blockchain.tx_signing import requires_signature
from crypto.keys import public_hex
from network.wire import wire_to_tx
from reputation.slashing import is_slash

# Length of the truncated "short" form shown alongside every full hex key, so the
# UI can render something legible while the full key stays available.
_SHORT_LEN = 12


def _short_full(key: str) -> dict:
    """Render an identifier as both a short prefix and the full value.

    ``key`` is a hex public key (or a readable placeholder name); an empty string
    (e.g. the genesis block's absent producer) yields empty fields rather than
    raising.
    """
    return {"short": key[:_SHORT_LEN], "full": key}


def _tx_type_label(tx) -> str:
    """Label a transaction by its real payload type, using the actual predicates.

    Order matters only in that each predicate is mutually exclusive by
    discriminator; anything unrecognised is ``"other"``.
    """
    if is_attestation(tx):
        return "attestation"
    if is_submission(tx):
        return "submission"
    if is_slash(tx):
        return "slash"
    payload = tx.payload
    if isinstance(payload, dict) and payload.get("type") == CERTIFICATE_TYPE:
        return "certificate"
    return "other"


def _tx_summary(tx) -> dict:
    """Canonical JSON summary of a transaction, shared by chain and mempool.

    Kept in one place so a transaction looks identical wherever it appears. The
    full ``payload`` is included verbatim (it never contains file bytes — only
    hashes and metadata), along with the content-addressed ``hash`` and whether
    the signature verifies.

    ``protocol_generated`` marks transactions exempt from the author-signature
    requirement (certificates, and other non-participant txs): the UI can label
    them honestly as protocol output rather than showing them as "unsigned".
    """
    return {
        "hash": tx.hash,
        "type": _tx_type_label(tx),
        "sender": _short_full(tx.sender),
        "payload": tx.payload,
        "signed": tx.is_signed(),
        "signature_valid": tx.verify_signature(),
        "protocol_generated": not requires_signature(tx),
    }


def _block_summary(block) -> dict:
    """JSON summary of one block, including a summary of each transaction."""
    return {
        "index": block.index,
        "hash": block.hash,
        "previous_hash": block.previous_hash,
        "producer": _short_full(block.producer),
        "timestamp": block.timestamp,
        "transactions": [_tx_summary(tx) for tx in block.transactions],
    }


def _json(data, status: int = 200) -> web.Response:
    """A JSON response with the given status; CORS is added by the middleware."""
    return web.json_response(data, status=status)


# Permissive CORS so a static HTML file opened locally (file:// or any origin)
# can both poll the GETs and POST to the writes, including the preflight it sends.
_CORS_HEADERS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
}


@web.middleware
async def _cors_middleware(request: web.Request, handler):
    """Answer CORS preflight (OPTIONS) and stamp CORS headers on every response."""
    if request.method == "OPTIONS":
        return web.Response(status=204, headers=_CORS_HEADERS)
    response = await handler(request)
    response.headers.update(_CORS_HEADERS)
    return response


# ------------------------------------------------------------ write operations


def submit_transaction(community, body) -> tuple[int, dict]:
    """Validate a client-signed transaction and, if good, pool + gossip it.

    ``body`` is the parsed JSON of a transaction (the ``Transaction.to_dict``
    shape: ``sender``, ``payload``, ``timestamp``, ``signature``). The node never
    signs here — it only accepts an already-signed participant transaction that
    passes :meth:`AttestationCommunity.accepts_transaction` (the same gate gossip
    and the chain use). Returns an ``(http_status, json)`` pair.
    """
    if not isinstance(body, dict):
        return 400, {"error": "expected a JSON transaction object"}
    try:
        # Reconstruct through the one canonical decode path (network.wire), so the
        # rebuilt tx hashes and verifies exactly as the author's did.
        tx = wire_to_tx(json.dumps(body))
    except ValueError as exc:
        return 400, {"error": f"malformed transaction: {exc}"}

    if not community.accepts_transaction(tx):
        return 400, {
            "error": (
                "rejected: must be a signed attestation/submission/slash whose "
                "signature verifies against its sender"
            )
        }

    if community._already_seen(tx):
        return 200, {"status": "already_known", "transaction": _tx_summary(tx)}

    community.blockchain.add_transaction(tx)
    fanout = community.broadcast_transaction(tx)
    return 201, {
        "status": "pooled",
        "broadcast_to": fanout,
        "transaction": _tx_summary(tx),
    }


def produce_block(community) -> tuple[int, dict]:
    """Have the node produce a block from its mempool with its own producer key.

    A producer producing its own blocks — the node signs the block header with the
    key it already holds (checked as an authority by PoA). Returns ``(status, json)``.
    """
    if not community.blockchain.mempool:
        return 200, {"status": "empty", "message": "mempool empty; no block produced"}
    block = community.mine_and_broadcast_block()
    return 201, {
        "status": "produced",
        "broadcast_to": len(community.get_peers()),
        "block": _block_summary(block),
    }


# --------------------------------------------------------------------- handlers


async def _node(request: web.Request) -> web.Response:
    """This node's identity plus its producer standing (authority + weights)."""
    community = request.app["community"]
    registry = community.reputation

    peer = community.my_peer
    producer_key = public_hex(community.producer_key)
    weights = registry.snapshot().get(producer_key, {})

    return _json(
        {
            # Network/transport identity — the key peers know this node by.
            "id": peer.mid.hex()[:_SHORT_LEN],
            "public_key": peer.public_key.key_to_bin().hex(),
            # Producer identity — what reputation and authority key on.
            "producer": _short_full(producer_key),
            "is_authority": registry.is_authority(producer_key, AUTHORITY_THRESHOLD),
            "weights": weights,
        }
    )


async def _chain(request: web.Request) -> web.Response:
    """The ordered list of blocks, each with its transaction summaries."""
    community = request.app["community"]
    return _json([_block_summary(b) for b in community.blockchain.blocks])


async def _mempool(request: web.Request) -> web.Response:
    """Pending transactions not yet committed to a block."""
    community = request.app["community"]
    return _json([_tx_summary(tx) for tx in community.blockchain.mempool])


async def _reputation(request: web.Request) -> web.Response:
    """The current derived reputation table: pubkey (short+full) -> domain -> weight."""
    community = request.app["community"]
    table = community.reputation.snapshot()
    return _json(
        [
            {"pubkey": _short_full(pubkey), "weights": domains}
            for pubkey, domains in table.items()
        ]
    )


async def _peers(request: web.Request) -> web.Response:
    """Connected peers, identified by public key (never by address)."""
    community = request.app["community"]
    return _json(
        [
            {
                "id": peer.mid.hex()[:_SHORT_LEN],
                "public_key": peer.public_key.key_to_bin().hex(),
            }
            for peer in community.get_peers()
        ]
    )


async def _submit_tx(request: web.Request) -> web.Response:
    """POST a client-signed participant transaction; the node validates and relays."""
    community = request.app["community"]
    try:
        body = await request.json()
    except Exception:
        return _json({"error": "invalid JSON body"}, status=400)
    status, result = submit_transaction(community, body)
    return _json(result, status=status)


async def _mine(request: web.Request) -> web.Response:
    """POST to have this node produce a block from its mempool (its own producer key)."""
    community = request.app["community"]
    status, result = produce_block(community)
    return _json(result, status=status)


async def attach_http_bridge(
    ipv8,
    community,
    host: str = "127.0.0.1",
    port: int = 8080,
) -> web.AppRunner:
    """Start the JSON HTTP bridge for ``community`` on the running loop.

    Creates an aiohttp application, registers the five read GETs and the two write
    POSTs (with a CORS middleware), and starts it on the **already-running** event
    loop via ``AppRunner`` + ``TCPSite`` (awaited, never ``web.run_app``). Returns
    the runner so the caller can call ``await runner.cleanup()`` on shutdown.

    Args:
        ipv8: The node's IPv8 instance. Kept for symmetry and future lifecycle
            use; state is read from ``community``.
        community: The :class:`AttestationCommunity` whose live state to expose.
        host: Interface to bind (loopback by default).
        port: TCP port to serve on.

    Returns:
        The started :class:`aiohttp.web.AppRunner`.
    """
    app = web.Application(middlewares=[_cors_middleware])
    app["ipv8"] = ipv8
    app["community"] = community
    app.add_routes(
        [
            web.get("/api/node", _node),
            web.get("/api/chain", _chain),
            web.get("/api/mempool", _mempool),
            web.get("/api/reputation", _reputation),
            web.get("/api/peers", _peers),
            web.post("/api/tx", _submit_tx),
            web.post("/api/mine", _mine),
        ]
    )

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, host, port)
    await site.start()
    return runner
