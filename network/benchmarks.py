"""Live consensus benchmarks — measured from consensus events, not function calls.

Three benchmarks run against **real IPv8 nodes** and report real latencies:

1. :func:`bench_finality` — *finalization time vs validator-set size*. For each
   ``N`` it launches an isolated cluster of ``N`` validators, proposes a series of
   blocks, and measures ``finalized_at − proposed_at`` for each, then tears the
   cluster down. This is why the harness can vary ``N`` at all: the default running
   set has a fixed size, so each ``N`` gets its own short-lived cluster.
2. :func:`bench_convergence` — *how long after finality the whole network agrees*.
   On one running cluster it measures, per block, ``max(finalized_at over all
   nodes) − finalized_at(proposer)``: the moment the last node observes the same
   finalized tip the proposer already had.
3. :func:`bench_view_change` — *the liveness cost of rotating a stalled proposer*.
   Alternates a happy-path block against one where the scheduled view-0 proposer is
   offline, so the remaining validators must view-change to make progress.

**The measurement rule.** Every number here is a difference between two
*timestamps recorded inside the node at the instant the consensus event occurred*
(:meth:`network.community.AttestationCommunity.mark_event`, called at block
production, block arrival, first observation of quorum, and view-change vote).
Nothing is timed by wrapping a Python call: a call's duration would measure object
construction, not the network and the commit round. The harness only *waits* for
those events (polling a cheap flag) and then subtracts the timestamps the node
already recorded.

Nothing in this module changes consensus. It arranges inputs (who proposes, who is
offline), reads timestamps, and computes order statistics.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import socket
import statistics
import tempfile
import time
from dataclasses import dataclass

from ipv8.configuration import ConfigBuilder
from ipv8.peer import Peer
from ipv8_service import IPv8

from attestation.submission import hash_artifact, make_submission
from blockchain.blockchain import Blockchain, quorum_size
from crypto.keys import generate_keypair, keypair_from_seed
from network.community import AttestationCommunity
from network.demo import DEMO_DOMAIN, RUBRIC, overlays
from reputation.genesis import CONSENSUS_DOMAIN

# Validator-set sizes the finality benchmark sweeps. Four is the BFT minimum
# (n=4, f=1, quorum=3); thirteen is large enough for the O(n²) commit flood to be
# visible without making a browser-triggered run take minutes.
DEFAULT_NS = (4, 7, 10, 13)

# Measured blocks per data point. Enough for a stable median with min/max spread,
# few enough that a full N-sweep stays inside a defensible live-demo wait (the
# commit flood at N=13 alone costs seconds per block).
DEFAULT_REPEATS = 5

# UDP base port the benchmark clusters look for a free window from. Deliberately
# clear of the demo/live range (9090+) so a benchmark can run while the live
# cluster is up.
BENCH_UDP_BASE = 9600

# How long to wait for one block to finalize / converge before giving up on that
# run and reporting it as a timeout (seconds). Sized with headroom over the slowest
# measured case: a 13-validator commit flood on loopback settles in ~10s, so 25
# leaves a run that is merely slow from being mis-reported as a timeout.
FINALITY_TIMEOUT = 25.0

# Poll interval while waiting for a consensus event to be recorded. This is a
# *wait*, not a measurement — the reported latency comes from the timestamps the
# node recorded when the events happened, so this interval bounds our detection
# lag, not the numbers themselves.
POLL = 0.002


# --------------------------------------------------------------- cluster harness


@dataclass
class BenchCluster:
    """One short-lived, isolated cluster of ``n`` genesis validators."""

    instances: list[IPv8]
    nodes: list[AttestationCommunity]
    base_udp_port: int
    key_dir: tempfile.TemporaryDirectory

    @property
    def n(self) -> int:
        return len(self.nodes)


def _bench_keypair(i: int):
    """A reproducible validator keypair for benchmark node ``i``.

    Seeded from a hash of the index so benchmark identities are stable across runs
    and cannot collide with the demo/scenario identities.
    """
    return keypair_from_seed(hashlib.sha256(f"bench-validator-{i}".encode()).digest())


def _udp_port_window(count: int, start: int = BENCH_UDP_BASE) -> int:
    """Find a base port with ``count`` consecutive free UDP ports; return the base.

    Benchmark clusters come and go, and one may run while the live demo cluster is
    up, so the window is probed rather than assumed.
    """
    for base in range(start, start + 400, 25):
        socks = []
        try:
            for offset in range(count):
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.bind(("127.0.0.1", base + offset))
                socks.append(s)
            return base
        except OSError:
            continue
        finally:
            for s in socks:
                s.close()
    raise RuntimeError(f"no free UDP window of {count} ports from {start}")


def introduce(instances: list[IPv8], base_udp_port: int) -> None:
    """Wire every node to every other by (public key, loopback address).

    Identity is the peer's public key; the address is only where to send.
    Idempotent, so it doubles as the "re-introduce" step that heals a node the
    view-change benchmark took offline.
    """
    for i, node in enumerate(instances):
        overlay = node.get_overlay(AttestationCommunity)
        for j, other in enumerate(instances):
            if i == j:
                continue
            other_overlay = other.get_overlay(AttestationCommunity)
            peer = Peer(other_overlay.my_peer.public_key, ("127.0.0.1", base_udp_port + j))
            overlay.network.add_verified_peer(peer)
            overlay.network.discover_services(peer, [AttestationCommunity.community_id])


async def start_cluster(n: int, base_udp_port: int | None = None) -> BenchCluster:
    """Launch ``n`` genesis-validator IPv8 nodes on the running loop and mesh them.

    Every node validates against the SAME genesis anchor (all ``n`` keys carry
    CONSENSUS_DOMAIN weight, so all ``n`` are validators and the quorum is
    ``⌊2n/3⌋+1``). IPv8 key files are written into a temporary directory that is
    removed with the cluster, so a benchmark never leaves ``ec*.pem`` behind.
    """
    if n < 4:
        raise ValueError(f"need at least 4 validators for BFT (got {n})")
    keypairs = [_bench_keypair(i) for i in range(n)]
    genesis = {pub: {CONSENSUS_DOMAIN: 100} for _priv, pub in keypairs}
    balances = {pub: 100 for _priv, pub in keypairs}
    base = base_udp_port or _udp_port_window(n)
    key_dir = tempfile.TemporaryDirectory(prefix="hs-fob-bench-")

    instances: list[IPv8] = []
    for i in range(n):
        chain = Blockchain(genesis=genesis, balances=balances)
        builder = ConfigBuilder().clear_keys().clear_overlays()
        builder.set_port(base + i)
        builder.add_key("my peer", "medium", os.path.join(key_dir.name, f"ec{i}.pem"))
        builder.add_overlay(
            "CompetenceAttestationCommunity",
            "my peer",
            [],
            [],
            {"blockchain": chain, "producer_key": keypairs[i][0]},
            [],
        )
        ipv8 = IPv8(
            builder.finalize(),
            extra_communities={"CompetenceAttestationCommunity": AttestationCommunity},
        )
        await ipv8.start()
        instances.append(ipv8)

    introduce(instances, base)
    await asyncio.sleep(0.4)  # settle peer tables before the first proposal
    return BenchCluster(
        instances=instances,
        nodes=overlays(instances),
        base_udp_port=base,
        key_dir=key_dir,
    )


async def stop_cluster(cluster: BenchCluster) -> None:
    """Shut the cluster's nodes down and delete its temporary key material."""
    for ipv8 in cluster.instances:
        await ipv8.stop()
    cluster.key_dir.cleanup()


def _isolate(nodes: list[AttestationCommunity], down_index: int) -> None:
    """Take one node offline by removing it from the peer mesh (both directions)."""
    down = nodes[down_index]
    down_bin = down.my_peer.public_key.key_to_bin()
    for j, node in enumerate(nodes):
        if j == down_index:
            continue
        for peer in list(node.get_peers()):
            if peer.public_key.key_to_bin() == down_bin:
                node.network.remove_peer(peer)
    for peer in list(down.get_peers()):
        down.network.remove_peer(peer)


# ------------------------------------------------------------------ measurement


def _filler_tx():
    """A freshly-signed submission, so every measured block carries real content."""
    priv, pub = generate_keypair()
    tx = make_submission(
        subject=pub,
        domain=DEMO_DOMAIN,
        rubric_root=RUBRIC.root(),
        title="Benchmark filler submission",
        artifact_hash=hash_artifact(os.urandom(16)),
    )
    tx.sign(priv)
    return tx


def _proposer_node(nodes, height: int, view: int = 0):
    """The node whose validator the schedule assigns to ``(height, view)``."""
    target = nodes[0].blockchain.proposer_for(height, view)
    return next((node for node in nodes if node.validator_pubkey == target), None)


async def _await(predicate, timeout: float) -> bool:
    """Wait until ``predicate()`` is true (or ``timeout``); report whether it became true.

    Only a detection wait — the latencies reported by the benchmarks are computed
    from timestamps the nodes recorded when the events fired, never from how long
    this loop ran.
    """
    deadline = time.perf_counter() + timeout
    while not predicate():
        if time.perf_counter() >= deadline:
            return False
        await asyncio.sleep(POLL)
    return True


def _event(node, block_hash: str, name: str):
    """One recorded consensus-event timestamp for a block on a node, or ``None``."""
    return node.event_times.get(block_hash, {}).get(name)


async def _await_common_height(nodes, height: int, timeout: float = FINALITY_TIMEOUT) -> bool:
    """Wait until every node's chain has reached ``height`` blocks."""
    return await _await(
        lambda: all(len(node.blockchain.blocks) >= height for node in nodes), timeout
    )


async def _propose_and_finalize(nodes, timeout: float = FINALITY_TIMEOUT):
    """Have the scheduled proposer produce one block; wait for it to finalize there.

    Returns ``(proposer, block)`` — or ``(proposer, None)`` if the block never
    reached quorum within ``timeout``. Callers read ``proposer.event_times[hash]``
    for the ``proposed_at`` / ``finalized_at`` readings.
    """
    height = len(nodes[0].blockchain.blocks)
    proposer = _proposer_node(nodes, height)
    proposer.blockchain.add_transaction(_filler_tx())
    block = proposer.mine_and_broadcast_block()
    ok = await _await(
        lambda: _event(proposer, block.hash, "finalized_at") is not None, timeout
    )
    return proposer, (block if ok else None)


def _summary(values: list[float]) -> dict:
    """Order statistics for a list of measurements (empty-safe), rounded for display."""
    if not values:
        return {"runs": 0, "median": None, "min": None, "max": None, "p95": None, "mean": None}
    ordered = sorted(values)
    # Nearest-rank p95: with 5–10 samples this is an honest "worst realistic case"
    # rather than an interpolation between two points we never observed.
    p95_index = max(0, min(len(ordered) - 1, int(round(0.95 * len(ordered))) - 1))
    return {
        "runs": len(ordered),
        "median": round(statistics.median(ordered), 2),
        "min": round(ordered[0], 2),
        "max": round(ordered[-1], 2),
        "p95": round(ordered[p95_index], 2),
        "mean": round(statistics.fmean(ordered), 2),
    }


# ------------------------------------------------------------------ benchmark 1


async def bench_finality(ns=DEFAULT_NS, repeats: int = DEFAULT_REPEATS) -> dict:
    """Finalization time vs validator count: ``finalized_at − proposed_at`` per block.

    For each ``N`` an isolated cluster of ``N`` validators is launched, one warm-up
    block is produced (unmeasured, so peer tables and payload formats are hot),
    then ``repeats`` blocks are proposed and each one's finalization latency is
    taken from the proposer's own event timestamps. The cluster is then stopped and
    the next ``N`` gets a fresh one.
    """
    series = []
    for n in ns:
        cluster = await start_cluster(n)
        try:
            nodes = cluster.nodes
            await _propose_and_finalize(nodes)  # warm-up, not measured
            await _await_common_height(nodes, len(nodes[0].blockchain.blocks))
            samples, runs = [], []
            for run in range(repeats):
                proposer, block = await _propose_and_finalize(nodes)
                if block is None:
                    runs.append({"run": run + 1, "ms": None, "timeout": True})
                    continue
                events = proposer.event_times[block.hash]
                ms = (events["finalized_at"] - events["proposed_at"]) * 1000.0
                samples.append(ms)
                runs.append(
                    {
                        "run": run + 1,
                        "ms": round(ms, 2),
                        "height": block.index,
                        "commits": len(
                            block.commit_signers()
                            & proposer.blockchain.validator_set(block.index)
                        ),
                    }
                )
                # Let every node append before the next height's proposer is picked.
                await _await_common_height(nodes, block.index + 1)
            # ``measurements`` is the raw per-block data; ``_summary`` contributes the
            # order statistics (including its own ``runs`` *count*), so the two never
            # collide on one key.
            series.append(
                {
                    "n": n,
                    "quorum": quorum_size(n),
                    "measurements": runs,
                    **_summary(samples),
                }
            )
        finally:
            await stop_cluster(cluster)
    return {
        "benchmark": "finality",
        "unit": "ms",
        "metric": "finalized_at − proposed_at (proposer's own consensus events)",
        "series": series,
        "params": {"ns": list(ns), "repeats": repeats},
    }


# ------------------------------------------------------------------ benchmark 2


async def bench_convergence(nodes, repeats: int = DEFAULT_REPEATS) -> dict:
    """Convergence latency: how long after finality every node reports the same tip.

    Per run the scheduled proposer produces a block and we wait until *every* node
    has recorded ``finalized_at`` for that block hash. Two latencies are reported,
    both from the nodes' own finality events:

    * ``ms`` — ``max(finalized_at) − finalized_at(proposer)``: the extra time the
      slowest node needs after the *proposer* observed quorum. In this topology the
      proposer is usually the **last** node to observe quorum (it broadcasts the
      block first and collects the returning commits last), so this is often ~0.
    * ``spread_ms`` — ``max(finalized_at) − min(finalized_at)``: the network-wide
      agreement window, from the first node to observe finality to the last. This is
      the honest "how fast does the network agree" number, and it is what the chart
      plots.
    """
    samples, spreads, runs = [], [], []
    for run in range(repeats):
        proposer, block = await _propose_and_finalize(nodes)
        if block is None:
            runs.append({"run": run + 1, "ms": None, "timeout": True})
            continue
        converged = await _await(
            lambda: all(_event(node, block.hash, "finalized_at") is not None for node in nodes),
            FINALITY_TIMEOUT,
        )
        events = proposer.event_times[block.hash]
        finality_ms = (events["finalized_at"] - events["proposed_at"]) * 1000.0
        if not converged:
            runs.append(
                {"run": run + 1, "ms": None, "timeout": True,
                 "finality_ms": round(finality_ms, 2)}
            )
            continue
        finality_times = [_event(node, block.hash, "finalized_at") for node in nodes]
        last, first = max(finality_times), min(finality_times)
        ms = (last - events["finalized_at"]) * 1000.0
        spread_ms = (last - first) * 1000.0
        samples.append(ms)
        spreads.append(spread_ms)
        runs.append(
            {
                "run": run + 1,
                "ms": round(ms, 2),
                "spread_ms": round(spread_ms, 2),
                "finality_ms": round(finality_ms, 2),
                "height": block.index,
            }
        )
        await _await_common_height(nodes, block.index + 1)
    return {
        "benchmark": "convergence",
        "unit": "ms",
        "metric": (
            "spread: max(finalized_at) − min(finalized_at) across all nodes; "
            "ms: max(finalized_at) − finalized_at(proposer)"
        ),
        "nodes": len(nodes),
        "quorum": quorum_size(
            len(nodes[0].blockchain.validator_set(len(nodes[0].blockchain.blocks)))
        ),
        "runs": runs,
        # ``summary`` is the network-wide agreement window (what the chart plots);
        # ``proposer_relative`` keeps the proposer-anchored view alongside it.
        "summary": _summary(spreads),
        "proposer_relative": _summary(samples),
        "params": {"repeats": repeats},
    }


# ------------------------------------------------------------------ benchmark 3


async def _measure_view_change(cluster: BenchCluster) -> dict | None:
    """One view-change round: isolate the view-0 proposer, rotate, finalize, heal.

    Returns the run's measurements, or ``None`` if the rotation did not finalize in
    time. Two latencies are reported:

    * ``ms`` — from the *stall event* (the first live validator's view-change vote,
      timestamped in ``request_view_change``) to the replacement block's
      ``finalized_at``: the liveness cost a client actually waits through; and
    * ``propose_ms`` — the replacement block's own ``finalized_at − proposed_at``,
      comparable one-for-one with the happy path's number.
    """
    nodes = cluster.nodes
    height = len(nodes[0].blockchain.blocks)
    validators = nodes[0].blockchain.validator_set(height)
    down_pub = nodes[0].blockchain.proposer_for(height, 0)
    new_pub = nodes[0].blockchain.proposer_for(height, 1)
    down_index = next(i for i, node in enumerate(nodes) if node.validator_pubkey == down_pub)
    new_index = next(i for i, node in enumerate(nodes) if node.validator_pubkey == new_pub)

    nodes[new_index].blockchain.add_transaction(_filler_tx())
    _isolate(nodes, down_index)

    live = [i for i in range(len(nodes))
            if i != down_index and nodes[i].validator_pubkey in validators]
    for i in live:
        nodes[i].request_view_change(height)
    # The stall event: the earliest moment a live validator acted on the timeout.
    started = min(nodes[i].view_change_times[height] for i in live
                  if height in nodes[i].view_change_times)

    proposer = nodes[new_index]
    produced = await _await(
        lambda: len(proposer.blockchain.blocks) > height
        and _event(proposer, proposer.blockchain.blocks[height].hash, "finalized_at") is not None,
        FINALITY_TIMEOUT,
    )
    result = None
    if produced:
        block = proposer.blockchain.blocks[height]
        events = proposer.event_times[block.hash]
        result = {
            "ms": round((events["finalized_at"] - started) * 1000.0, 2),
            "propose_ms": round((events["finalized_at"] - events["proposed_at"]) * 1000.0, 2),
            "view": block.view,
            "height": block.index,
            "commits": len(block.commit_signers() & validators),
        }

    # Heal: re-introduce the offline node, re-advertise the tip so it fork-syncs,
    # and only continue once every node is back at the same height.
    introduce(cluster.instances, cluster.base_udp_port)
    await asyncio.sleep(0.2)
    proposer.broadcast_block(proposer.blockchain.last_block)
    await _await_common_height(nodes, len(proposer.blockchain.blocks))
    return result


async def bench_view_change(n: int = 7, repeats: int = 5) -> dict:
    """The liveness cost of a stalled proposer: happy path vs forced view change.

    Runs on its own isolated ``n``-validator cluster (the live demo chain is left
    untouched). Each repeat measures one happy-path block — the scheduled view-0
    proposer produces and the block finalizes — and then one rotation: that same
    scheduled proposer is taken offline, the remaining validators vote to advance
    the view, and the view-1 proposer's block finalizes on the remaining quorum.
    """
    cluster = await start_cluster(n)
    try:
        nodes = cluster.nodes
        await _propose_and_finalize(nodes)  # warm-up, not measured
        await _await_common_height(nodes, len(nodes[0].blockchain.blocks))

        normal_samples, normal_runs = [], []
        vc_samples, vc_propose_samples, vc_runs = [], [], []
        for run in range(repeats):
            proposer, block = await _propose_and_finalize(nodes)
            if block is None:
                normal_runs.append({"run": run + 1, "ms": None, "timeout": True})
            else:
                events = proposer.event_times[block.hash]
                ms = (events["finalized_at"] - events["proposed_at"]) * 1000.0
                normal_samples.append(ms)
                normal_runs.append({"run": run + 1, "ms": round(ms, 2), "height": block.index})
                await _await_common_height(nodes, block.index + 1)

            measured = await _measure_view_change(cluster)
            if measured is None:
                vc_runs.append({"run": run + 1, "ms": None, "timeout": True})
            else:
                vc_samples.append(measured["ms"])
                vc_propose_samples.append(measured["propose_ms"])
                vc_runs.append({"run": run + 1, **measured})

        return {
            "benchmark": "view_change",
            "unit": "ms",
            "metric": (
                "normal: finalized_at − proposed_at; "
                "view-change: finalized_at − first view-change vote (stall detected)"
            ),
            "n": n,
            "quorum": quorum_size(n),
            # As in bench_finality: raw per-run data under ``measurements``, order
            # statistics (with their own ``runs`` count) spread in alongside.
            "groups": [
                {"label": "normal", "measurements": normal_runs, **_summary(normal_samples)},
                {"label": "view-change", "measurements": vc_runs, **_summary(vc_samples)},
            ],
            "view_change_propose_only": _summary(vc_propose_samples),
            "params": {"n": n, "repeats": repeats},
        }
    finally:
        await stop_cluster(cluster)


# -------------------------------------------------------------------- registry


# Name -> (human description, explanation shown next to the chart).
BENCHMARKS = {
    "finality": (
        "Finalization time as the validator set grows (4 → 13), each N on its own cluster.",
        "Each N spins up an isolated cluster of N validators, proposes a series of blocks, "
        "and measures finalized_at − proposed_at from the proposer's own consensus events. "
        "A block finalizes only once ⌊2n/3⌋+1 validators have gossiped commit signatures, so "
        "the commit flood grows with N and the median latency rises with it.",
    ),
    "convergence": (
        "How long after finality the whole network reports the same finalized tip.",
        "On the running cluster, each block's convergence window is max(finalized_at) − "
        "min(finalized_at) across every node: from the first node to observe the BFT quorum to "
        "the last, using each node's own finality event. Finality is deterministic, so this is "
        "pure commit-gossip propagation, not re-agreement. The proposer-relative number is "
        "reported too and is near zero — the proposer broadcasts first and collects the "
        "returning commits last, so it is usually the last node to see quorum.",
    ),
    "view_change": (
        "The liveness cost of rotating a stalled proposer, against the happy path.",
        "The happy-path bar is finalized_at − proposed_at for a normal block. The view-change bar "
        "measures from the stall being acted on (the first validator's view-change vote) to the "
        "replacement block's finality: a vote flood to quorum, then a proposal and a commit round "
        "by the rotated leader. Safety is unaffected — only the wait is.",
    ),
}


class BenchmarkRegistry:
    """Binds the benchmarks to the HTTP bridge (``list`` + ``async run``).

    ``net`` is the *running* network (a :class:`network.scenarios.ScenarioNet`) the
    convergence benchmark measures on; the finality and view-change benchmarks
    launch and tear down their own clusters, because they need validator-set sizes
    the running network does not have. A lock serializes runs so two concurrent
    requests never interleave clusters or chain edits.
    """

    def __init__(self, net=None) -> None:
        self.net = net
        self._lock = asyncio.Lock()

    def list(self) -> list[dict]:
        return [
            {"name": name, "description": desc, "explanation": explanation}
            for name, (desc, explanation) in BENCHMARKS.items()
        ]

    async def run(self, name: str, params: dict | None = None) -> dict | None:
        params = params or {}
        if name not in BENCHMARKS:
            return None
        repeats = max(1, min(int(params.get("repeats", DEFAULT_REPEATS)), 20))
        async with self._lock:
            started = time.perf_counter()
            if name == "finality":
                ns = tuple(params.get("ns") or DEFAULT_NS)
                result = await bench_finality(ns=ns, repeats=repeats)
            elif name == "convergence":
                if self.net is None:
                    cluster = await start_cluster(int(params.get("n", 7)))
                    try:
                        result = await bench_convergence(cluster.nodes, repeats=repeats)
                    finally:
                        await stop_cluster(cluster)
                else:
                    result = await bench_convergence(self.net.nodes, repeats=repeats)
            else:
                result = await bench_view_change(
                    n=int(params.get("n", 7)), repeats=repeats
                )
            result["elapsed_s"] = round(time.perf_counter() - started, 2)
            result["description"], result["explanation"] = BENCHMARKS[name]
            return result
