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

Endpoints: five read GETs (``/api/node``, ``/api/chain``, ``/api/mempool``,
``/api/reputation``, ``/api/peers``), two writes (``/api/tx``, ``/api/mine``), and
one WebSocket (``/ws``) for live updates.

Live updates (WebSocket)
------------------------
``/ws`` lets the UI update without polling. On connect the node pushes a full
snapshot (a ``chain`` / ``mempool`` / ``reputation`` / ``peers`` message, each
carrying that category's current payload — the *same* shapes the GETs return).
Thereafter, a small watcher task on the IPv8 loop compares cheap fingerprints of
the real objects each tick and pushes only the category that changed. It observes
the real state rather than instrumenting consensus, so no core mutation site is
touched (MVP choice; event hooks in the community are a possible refinement).
"""

from __future__ import annotations

import asyncio
import json

from aiohttp import WSMsgType, web

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


# State payload builders — the single source of each category's JSON shape, shared
# by the REST GET handlers and the WebSocket push so a client sees identical data
# whether it polls or subscribes.


def _chain_payload(community) -> list:
    return [_block_summary(b) for b in community.blockchain.blocks]


def _mempool_payload(community) -> list:
    return [_tx_summary(tx) for tx in community.blockchain.mempool]


def _reputation_payload(community) -> list:
    return [
        {"pubkey": _short_full(pubkey), "weights": domains}
        for pubkey, domains in community.reputation.snapshot().items()
    ]


def _peers_payload(community) -> list:
    return [
        {
            "id": peer.mid.hex()[:_SHORT_LEN],
            "public_key": peer.public_key.key_to_bin().hex(),
        }
        for peer in community.get_peers()
    ]


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


# ----------------------------------------------------------- websocket / live push

# Category -> event builder. An event is {"type": <category>, <category>: <payload>}
# (the "chain" event also carries a convenience ``height``). Sending the full
# current payload per changed category keeps the client trivial: replace-on-message.
_EVENT_BUILDERS = {
    "chain": lambda c: {
        "type": "chain",
        "height": len(c.blockchain.blocks),
        "chain": _chain_payload(c),
    },
    "mempool": lambda c: {"type": "mempool", "mempool": _mempool_payload(c)},
    "reputation": lambda c: {"type": "reputation", "reputation": _reputation_payload(c)},
    "peers": lambda c: {"type": "peers", "peers": _peers_payload(c)},
}


def _fingerprints(community) -> dict:
    """Cheap change-detection keys for each state category (no full serialization)."""
    chain = community.blockchain
    return {
        "chain": (len(chain.blocks), chain.last_block.hash),
        "mempool": tuple(tx.hash for tx in chain.mempool),
        "reputation": json.dumps(community.reputation.snapshot(), sort_keys=True),
        "peers": tuple(sorted(p.mid.hex() for p in community.get_peers())),
    }


def _snapshot_events(community) -> list:
    """Every category as a full event — the initial push a client gets on connect."""
    return [build(community) for build in _EVENT_BUILDERS.values()]


async def _broadcast(clients, event) -> None:
    """Send ``event`` to every open WebSocket client, dropping any that are closed."""
    for ws in list(clients):
        if ws.closed:
            clients.discard(ws)
            continue
        try:
            await ws.send_json(event)
        except ConnectionError:
            clients.discard(ws)


async def push_updates(app) -> list:
    """Diff the node's state against the last push and send only changed categories.

    The fingerprint store (a dict mutated in place) is advanced **before** awaiting
    the sends, so if this runs concurrently with the watcher tick the second call
    sees no change and nothing is sent twice. Returns the categories pushed (handy
    for tests).
    """
    community = app["community"]
    clients = app["ws_clients"]
    current = _fingerprints(community)
    last = app["ws_fingerprints"]
    changed = [cat for cat in _EVENT_BUILDERS if current.get(cat) != last.get(cat)]
    last.clear()
    last.update(current)  # mutate in place (never reassign the app key post-start)
    if clients:
        for cat in changed:
            await _broadcast(clients, _EVENT_BUILDERS[cat](community))
    return changed


async def _state_watcher(app) -> None:
    """Poll the real objects on the IPv8 loop and push deltas to WS subscribers."""
    interval = app["ws_interval"]
    last = app["ws_fingerprints"]
    last.clear()
    last.update(_fingerprints(app["community"]))  # baseline so we don't burst
    while True:
        await asyncio.sleep(interval)
        await push_updates(app)


async def _ws(request: web.Request) -> web.WebSocketResponse:
    """Live updates: push a full snapshot on connect, then deltas as state changes."""
    ws = web.WebSocketResponse()
    await ws.prepare(request)
    clients = request.app["ws_clients"]
    clients.add(ws)
    try:
        for event in _snapshot_events(request.app["community"]):
            await ws.send_json(event)
        # Keep the socket open; we don't act on client messages (read-only stream),
        # but iterating lets aiohttp surface close/error and clean up promptly.
        async for msg in ws:
            if msg.type == WSMsgType.ERROR:
                break
    finally:
        clients.discard(ws)
    return ws


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
    return _json(_chain_payload(request.app["community"]))


async def _mempool(request: web.Request) -> web.Response:
    """Pending transactions not yet committed to a block."""
    return _json(_mempool_payload(request.app["community"]))


async def _reputation(request: web.Request) -> web.Response:
    """The current derived reputation table: pubkey (short+full) -> domain -> weight."""
    return _json(_reputation_payload(request.app["community"]))


async def _peers(request: web.Request) -> web.Response:
    """Connected peers, identified by public key (never by address)."""
    return _json(_peers_payload(request.app["community"]))


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


async def _watcher_ctx(app):
    """Run the WS state-watcher for the app's lifetime; cancel + close on cleanup."""
    task = asyncio.create_task(_state_watcher(app))
    yield
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass
    for ws in list(app["ws_clients"]):
        await ws.close()


def build_app(ipv8, community, ws_interval: float = 0.3) -> web.Application:
    """Construct the aiohttp application (routes, CORS, WebSocket, watcher).

    Separated from :func:`attach_http_bridge` so it can be exercised by an aiohttp
    test client without binding a real port. ``ws_interval`` is how often the
    watcher polls the node's state for the live push (tests set it high and drive
    :func:`push_updates` directly for determinism).
    """
    app = web.Application(middlewares=[_cors_middleware])
    app["ipv8"] = ipv8
    app["community"] = community
    app["ws_clients"] = set()
    app["ws_interval"] = ws_interval
    app["ws_fingerprints"] = {}  # mutated in place by the watcher / push_updates
    app.add_routes(
        [
            web.get("/api/node", _node),
            web.get("/api/chain", _chain),
            web.get("/api/mempool", _mempool),
            web.get("/api/reputation", _reputation),
            web.get("/api/peers", _peers),
            web.post("/api/tx", _submit_tx),
            web.post("/api/mine", _mine),
            web.get("/ws", _ws),
        ]
    )
    app.cleanup_ctx.append(_watcher_ctx)
    return app


async def attach_http_bridge(
    ipv8,
    community,
    host: str = "127.0.0.1",
    port: int = 8080,
) -> web.AppRunner:
    """Start the JSON+WebSocket HTTP bridge for ``community`` on the running loop.

    Builds the application (:func:`build_app`) and starts it on the
    **already-running** event loop via ``AppRunner`` + ``TCPSite`` (awaited, never
    ``web.run_app``). The live-update watcher starts with the app and is cancelled
    by ``runner.cleanup()``. Returns the runner so the caller can clean up.

    Args:
        ipv8: The node's IPv8 instance. Kept for symmetry and future lifecycle
            use; state is read from ``community``.
        community: The :class:`AttestationCommunity` whose live state to expose.
        host: Interface to bind (loopback by default).
        port: TCP port to serve on.

    Returns:
        The started :class:`aiohttp.web.AppRunner`.
    """
    app = build_app(ipv8, community)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, host, port)
    await site.start()
    return runner
