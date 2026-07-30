"""Run live, HTTP-pollable nodes for the browser UI.

This is the *live* counterpart to :mod:`network.demo`. It reuses the demo's node
setup and its three scenarios to populate real chain state, then attaches a
read-only HTTP bridge (:func:`network.http_bridge.attach_http_bridge`) to each
node on its own port and keeps the process running so a browser (or ``curl``) can
poll the endpoints. Nothing about consensus, gossip, or the scenarios changes —
this only adds a live window onto the same real objects.

Run with::

    uv run python -m network.run_nodes

Then, for example::

    curl http://127.0.0.1:8080/api/chain

Each node's IPv8 UDP port stays as in the demo (9090+); its HTTP bridge is on
8080+ (node 0 → 8080, node 1 → 8081, …). Everything runs on one asyncio loop,
shared with IPv8.
"""

from __future__ import annotations

import asyncio

from attestation.submission import hash_artifact, make_submission
from crypto.keys import generate_keypair
from network.demo import (
    DEMO_DOMAIN,
    RUBRIC,
    introduce,
    overlays,
    rainy_day,
    slashing_day,
    start_nodes,
    sunny_day,
)
from network.http_bridge import attach_http_bridge

# HTTP bridge ports, one per node, distinct from the IPv8 UDP ports.
HTTP_BASE_PORT = 8080


def _seed_pending_submission(node) -> None:
    """Pool one signed submission (unmined) so /api/mempool shows live content.

    Demonstrates the submission transaction type and a passing signature in the
    live view. The artifact bytes are hashed here and thrown away — only the hash
    reaches the chain, exactly as intended.
    """
    private_key, public_key_hex = generate_keypair()
    tx = make_submission(
        subject=public_key_hex,
        domain=DEMO_DOMAIN,
        rubric_root=RUBRIC.root(),
        title="Draft manuscript",
        artifact_hash=hash_artifact(b"the artifact bytes never touch the chain"),
        artifact_name="draft.pdf",
    )
    tx.sign(private_key)
    node.blockchain.add_transaction(tx)


async def main() -> None:
    print("Starting live nodes …")
    instances = await start_nodes()
    introduce(instances)
    await asyncio.sleep(0.5)  # settle peer tables
    nodes = overlays(instances)

    # Populate real state with the existing demo scenarios (blocks, certificates,
    # a slash), then leave one pending submission so the mempool is non-empty.
    await sunny_day(nodes)
    await rainy_day(nodes)
    await slashing_day(nodes)
    _seed_pending_submission(nodes[0])

    # Attach a read-only HTTP bridge to each node on its own port, on THIS loop.
    runners = []
    for i, (ipv8, community) in enumerate(zip(instances, nodes)):
        port = HTTP_BASE_PORT + i
        runner = await attach_http_bridge(ipv8, community, port=port)
        runners.append(runner)
        print(f"  node {i} HTTP bridge: http://127.0.0.1:{port}")

    print("\nEndpoints per node: /api/node /api/chain /api/mempool "
          "/api/reputation /api/peers")
    print("Serving on the IPv8 event loop. Press Ctrl-C to stop.")
    try:
        await asyncio.Event().wait()  # run forever, sharing IPv8's loop
    finally:
        for runner in runners:
            await runner.cleanup()
        for ipv8 in instances:
            await ipv8.stop()
        print("Stopped.")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
