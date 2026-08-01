"""Run live, HTTP-pollable nodes for the browser UI — with on-demand scenarios.

This is the *live* counterpart to :mod:`network.demo`. It starts ``N`` real IPv8
nodes (all genesis validators) on one asyncio loop, attaches a read-only HTTP
bridge (:func:`network.http_bridge.attach_http_bridge`) to each on its own port,
and keeps the process running so a browser (or ``curl``) can poll the endpoints.

Unlike the earlier version, the nodes start **idle** — genesis only, no scripted
history is auto-played. Instead, node 0 exposes on-demand scenario triggers
(:mod:`network.scenarios`), each of which runs one scripted story against the
live network and returns a step-by-step JSON log for the UI:

* ``GET  /api/scenarios``         — list the available scenarios + descriptions.
* ``POST /api/scenario/sunny``    — honest attestations → certificate, finalized.
* ``POST /api/scenario/rainy``    — forged rubric root → no certificate.
* ``POST /api/scenario/slash``    — equivocation → evidence+quorum slash → burn.
* ``POST /api/scenario/view_change`` — a validator offline → view-change rotates
  the proposer → the block still finalizes with the remaining quorum.
* ``POST /api/scenario/collusion``   — an over-concentrated cross-attesting
  cluster → the ALPHA cap rejects certification.

Scenarios accumulate on one shared, inspectable chain (they do not reset between
runs); each run uses a fresh subject so repeats stay independent. See
:mod:`network.scenarios` for the state model.

Run with::

    uv run python -m network.run_nodes                 # 4 validators, HTTP on 8080…
    uv run python -m network.run_nodes --nodes 7       # 7 validators (quorum 5)
    uv run python -m network.run_nodes --http-port 9000 --udp-port 9500

The base HTTP port also honours ``$HS_FOB_HTTP_PORT``; node ``i`` serves on
``http_base + i`` (HTTP) and ``udp_base + i`` (IPv8 UDP).
"""

from __future__ import annotations

import argparse
import asyncio
import os

from blockchain.blockchain import quorum_size
from network.http_bridge import attach_http_bridge
from network.scenarios import BASE_UDP_PORT, ScenarioRegistry, start_network

# Default HTTP bridge base port, one bridge per node, distinct from the IPv8 UDP
# ports. Overridable via CLI or $HS_FOB_HTTP_PORT.
HTTP_BASE_PORT = 8080

# Environment variable that overrides the default HTTP base port.
HTTP_PORT_ENV = "HS_FOB_HTTP_PORT"

# Minimum validators so the BFT quorum tolerates one faulty/offline node
# (n=4, f=1, quorum=3). Fewer cannot demonstrate view-change with a live quorum.
MIN_NODES = 4


def _default_http_port() -> int:
    """Default HTTP base port: ``$HS_FOB_HTTP_PORT`` if set, else :data:`HTTP_BASE_PORT`."""
    raw = os.environ.get(HTTP_PORT_ENV)
    if raw is None:
        return HTTP_BASE_PORT
    try:
        return int(raw)
    except ValueError:
        raise SystemExit(f"invalid {HTTP_PORT_ENV} {raw!r}: expected an integer")


def parse_args(argv=None) -> argparse.Namespace:
    """Parse ``--nodes`` / ``--http-port`` / ``--udp-port`` for a live run."""
    parser = argparse.ArgumentParser(prog="network.run_nodes", description=__doc__)
    parser.add_argument(
        "--nodes", type=int, default=MIN_NODES,
        help=f"number of genesis validators to run (default {MIN_NODES}, minimum {MIN_NODES})",
    )
    parser.add_argument(
        "--http-port", type=int, default=_default_http_port(),
        help="base HTTP port; node i serves on this + i (env: HS_FOB_HTTP_PORT)",
    )
    parser.add_argument(
        "--udp-port", type=int, default=BASE_UDP_PORT,
        help=f"base IPv8 UDP port; node i listens on this + i (default {BASE_UDP_PORT})",
    )
    args = parser.parse_args(argv)
    if args.nodes < MIN_NODES:
        parser.error(f"--nodes must be at least {MIN_NODES} for BFT (n={MIN_NODES}, f=1, quorum=3)")
    return args


async def main(argv=None) -> None:
    args = parse_args(argv)
    n = args.nodes
    q = quorum_size(n)
    print(f"Starting {n} live genesis-validator nodes (quorum {q}, tolerates {n - q} faulty) …")

    net = await start_network(n, base_udp_port=args.udp_port)
    nodes = net.nodes

    # Node 0 carries the scenario registry; every node serves the read endpoints.
    registry = ScenarioRegistry(net)
    runners = []
    for i, (ipv8, community) in enumerate(zip(net.instances, nodes)):
        port = args.http_port + i
        runner = await attach_http_bridge(
            ipv8, community, port=port, scenarios=registry if i == 0 else None,
        )
        runners.append(runner)
        print(f"  node {i} ({community.validator_pubkey[:12]}…) "
              f"HTTP http://127.0.0.1:{port}  UDP {args.udp_port + i}")

    print(f"\nValidator set size: {n}   BFT quorum: {q}   fault tolerance: {n - q}")
    print("Read endpoints per node: /api/node /api/chain /api/mempool "
          "/api/reputation /api/balances /api/peers  (+ /ws)")
    print(f"Scenario endpoints on node 0 (http://127.0.0.1:{args.http_port}):")
    print("  GET  /api/scenarios")
    for entry in registry.list():
        print(f"  POST /api/scenario/{entry['name']:<12} — {entry['description']}")
    print("\nNodes are idle (genesis only). Trigger a scenario to drive the network.")
    print("Serving on the IPv8 event loop. Press Ctrl-C to stop.")
    try:
        await asyncio.Event().wait()  # run forever, sharing IPv8's loop
    finally:
        for runner in runners:
            await runner.cleanup()
        for ipv8 in net.instances:
            await ipv8.stop()
        print("Stopped.")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
