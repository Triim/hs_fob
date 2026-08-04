"""Tests for the consensus-event instrumentation and the benchmark plumbing.

Two halves:

* the **instrumentation**, exercised on IPv8's in-memory mock harness (the same
  ``TestBase`` setup as :mod:`tests.test_community`), so the timestamps are recorded
  by the real handlers on real serialized packets — a block is proposed, gossiped,
  committed, and finalized, and each event's timestamp lands where it should; and
* the **benchmark plumbing** — the order statistics, the registry surface, and the
  HTTP routes — as pure/unit checks.

The benchmarks themselves launch real IPv8 clusters and take tens of seconds, so
they are driven from the UI (or by POSTing the endpoints), not from this suite.
"""

import unittest

from ipv8.peer import Peer
from ipv8.test.base import TestBase

from blockchain.blockchain import Blockchain
from crypto.keys import public_hex
from network.benchmarks import BENCHMARKS, BenchmarkRegistry, _summary
from network.community import AttestationCommunity, AttestationSettings
from network.http_bridge import build_app
from reputation.genesis import CONSENSUS_DOMAIN, GENESIS_AUTHORITY_KEYS


class EventTimestampTests(TestBase):
    """The node records each consensus event at the point where it happens."""

    def setUp(self):
        super().setUp()
        self.overlay_class = AttestationCommunity
        # Two validators (quorum ⌊2·2/3⌋+1 = 2), so a proposed block reaches finality
        # exactly when the peer's commit arrives — a real, networked commit round.
        authority_key = GENESIS_AUTHORITY_KEYS["genesis-authority"][0]
        from crypto.keys import generate_keypair

        self.keys = [authority_key, generate_keypair()[0]]
        genesis = {public_hex(key): {CONSENSUS_DOMAIN: 100} for key in self.keys}
        self.nodes = [
            self.create_node(
                AttestationSettings(
                    blockchain=Blockchain(genesis=genesis), producer_key=key
                )
            )
            for key in self.keys
        ]
        for node in self.nodes:
            for other in self.nodes:
                if other is node:
                    continue
                public_peer = Peer(other.my_peer.public_key, other.my_peer.address)
                node.network.add_verified_peer(public_peer)
                node.network.discover_services(
                    public_peer, [AttestationCommunity.community_id]
                )
        for i in range(len(self.nodes)):
            self.patch_overlays(i)

    def _proposer(self):
        """The node the schedule assigns to the next height (only it may propose)."""
        chain = self.overlay(0).blockchain
        target = chain.proposer_for(len(chain.blocks))
        return next(
            self.overlay(i)
            for i in range(len(self.nodes))
            if self.overlay(i).validator_pubkey == target
        )

    async def test_proposal_and_finality_events_are_timestamped(self):
        """A proposed block gets ``proposed_at``, and ``finalized_at`` when quorum lands."""
        proposer = self._proposer()

        block = proposer.mine_and_broadcast_block()
        await self.deliver_messages()

        events = proposer.event_times[block.hash]
        self.assertIn("proposed_at", events)
        self.assertIn("finalized_at", events)
        # Finality is observed after the proposal, never before it.
        self.assertGreaterEqual(events["finalized_at"], events["proposed_at"])
        self.assertTrue(proposer.blockchain.is_final(block))

    async def test_receiving_node_timestamps_arrival_and_its_own_finality(self):
        """The peer that appends a gossiped block records ``received_at``, then finality."""
        proposer = self._proposer()
        receiver = next(o for o in (self.overlay(0), self.overlay(1)) if o is not proposer)

        block = proposer.mine_and_broadcast_block()
        await self.deliver_messages()

        events = receiver.event_times[block.hash]
        self.assertIn("received_at", events)
        self.assertIn("finalized_at", events)
        self.assertGreaterEqual(events["finalized_at"], events["received_at"])
        # No proposal event on a node that did not propose it.
        self.assertNotIn("proposed_at", events)

    async def test_view_change_vote_timestamps_the_stall(self):
        """``request_view_change`` records when this node acted on a stalled proposer."""
        height = len(self.overlay(0).blockchain.blocks)

        self.overlay(0).request_view_change(height)

        self.assertIn(height, self.overlay(0).view_change_times)

    async def test_mark_event_keeps_the_first_reading(self):
        """A repeated event mark never moves the timestamp (events happen once)."""
        overlay = self.overlay(0)
        first = overlay.mark_event("abc", "finalized_at")
        again = overlay.mark_event("abc", "finalized_at")
        self.assertEqual(first, again)


class SummaryStatsTests(unittest.TestCase):
    def test_order_statistics_are_rounded(self):
        stats = _summary([10.0, 20.0, 30.0, 40.5])
        self.assertEqual(stats["runs"], 4)
        self.assertEqual(stats["median"], 25.0)
        self.assertEqual(stats["min"], 10.0)
        self.assertEqual(stats["max"], 40.5)
        self.assertEqual(stats["mean"], 25.12)  # 25.125, rounded half-to-even

    def test_p95_is_nearest_rank(self):
        # Nearest rank on 10 samples: ceil-ish index 9 -> the largest value.
        self.assertEqual(_summary([float(i) for i in range(1, 11)])["p95"], 10.0)

    def test_empty_is_safe(self):
        stats = _summary([])
        self.assertEqual(stats["runs"], 0)
        self.assertIsNone(stats["median"])
        self.assertIsNone(stats["p95"])


class RegistryTests(unittest.IsolatedAsyncioTestCase):
    def test_lists_all_three_benchmarks_with_explanations(self):
        entries = BenchmarkRegistry().list()
        self.assertEqual(
            [e["name"] for e in entries], ["finality", "convergence", "view_change"]
        )
        for entry in entries:
            self.assertTrue(entry["description"])
            self.assertTrue(entry["explanation"])
        self.assertEqual(set(BENCHMARKS), {"finality", "convergence", "view_change"})

    async def test_unknown_benchmark_returns_none(self):
        self.assertIsNone(await BenchmarkRegistry().run("nope"))


class BenchmarkRouteTests(unittest.TestCase):
    """The benchmark routes are mounted only on a node given a registry (node 0)."""

    def _paths(self, **kwargs):
        community = _StubCommunity()
        app = build_app(None, community, **kwargs)
        return {getattr(route.resource, "canonical", "") for route in app.router.routes()}

    def test_routes_absent_without_a_registry(self):
        paths = self._paths()
        self.assertNotIn("/api/benchmarks", paths)
        self.assertNotIn("/api/benchmark/{name}", paths)

    def test_routes_present_with_a_registry(self):
        paths = self._paths(benchmarks=BenchmarkRegistry())
        self.assertIn("/api/benchmarks", paths)
        self.assertIn("/api/benchmark/{name}", paths)


class _StubCommunity:
    """The minimum surface ``build_app`` touches at construction time."""

    def __init__(self):
        self.blockchain = Blockchain()

    def get_peers(self):
        return []


if __name__ == "__main__":
    unittest.main()
