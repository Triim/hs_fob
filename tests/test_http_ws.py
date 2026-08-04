"""Tests for the WebSocket live-update stream (/ws).

Drives a real community through an aiohttp test client. The watcher's poll
interval is set high so the tests advance state and call ``push_updates``
directly — deterministic, no timing races.
"""

import asyncio

from aiohttp.test_utils import TestClient, TestServer
from ipv8.test.base import TestBase

from attestation.attestation import make_attestation
from blockchain.blockchain import Blockchain
from credentials.presentation import make_presentation
from credentials.vc import issue_reviewer_credential
from crypto.did import public_key_to_did_key
from crypto.keys import generate_keypair
from network.community import AttestationCommunity, AttestationSettings
from network.http_bridge import (
    build_app,
    produce_block,
    push_updates,
    submit_transaction,
)
from network.wire import PRESENTATION_KEY


def attest_body(community, item_index=0):
    """A signed attestation plus the reviewer credential presentation it needs.

    Attesting is gated on eligibility, so the POST body a client sends is the
    transaction *and* a Reviewer VC with a proof of possession over a challenge
    this node issued (see :mod:`credentials.presentation`). The credential rides
    beside the transaction and never enters the chain, which is why the pushed
    mempool/chain payloads below are unchanged in shape.
    """
    private_key, public_key = generate_keypair()
    tx = make_attestation(public_key, "subject", "rubric", item_index, True, 1, "aa")
    tx.sign(private_key)
    credential = issue_reviewer_credential(
        public_key_to_did_key(public_key), [tx.payload["domain"]]
    )
    challenge = community.challenges.issue()["challenge"]
    return {
        **tx.to_dict(),
        PRESENTATION_KEY: make_presentation(private_key, credential, challenge),
    }


async def _recv(ws):
    return await asyncio.wait_for(ws.receive_json(), timeout=2)


class WebSocketTests(TestBase):
    def setUp(self):
        super().setUp()
        self.overlay_class = AttestationCommunity
        self.nodes = [self.create_node(AttestationSettings(blockchain=Blockchain()))]
        self.patch_overlays(0)

    async def _client(self):
        # ws_interval high -> the watcher never auto-fires during the test; we
        # drive push_updates() ourselves for determinism.
        app = build_app(None, self.overlay(0), ws_interval=3600)
        client = TestClient(TestServer(app))
        await client.start_server()
        return app, client

    async def test_connect_pushes_full_snapshot(self):
        app, client = await self._client()
        try:
            ws = await client.ws_connect("/ws")
            events = {}
            for _ in range(5):
                ev = await _recv(ws)
                events[ev["type"]] = ev

            self.assertEqual(
                set(events), {"chain", "mempool", "reputation", "balances", "peers"}
            )
            self.assertEqual(events["chain"]["height"], 1)      # genesis only
            self.assertEqual(events["mempool"]["mempool"], [])  # empty
            # reputation snapshot is the canonical genesis anchor
            reps = {r["pubkey"]["full"] for r in events["reputation"]["reputation"]}
            self.assertIn("genesis-alice", reps)
            await ws.close()
        finally:
            await client.close()

    async def test_mempool_and_chain_deltas_are_pushed(self):
        app, client = await self._client()
        try:
            ws = await client.ws_connect("/ws")
            for _ in range(5):  # drain the initial snapshot
                await _recv(ws)

            # Pool a signed tx -> only a mempool delta.
            submit_transaction(self.overlay(0), attest_body(self.overlay(0)))
            pushed = await push_updates(app)
            self.assertEqual(pushed, ["mempool"])
            ev = await _recv(ws)
            self.assertEqual(ev["type"], "mempool")
            self.assertEqual(len(ev["mempool"]), 1)
            self.assertTrue(ev["mempool"][0]["signature_valid"])

            # Mine -> chain grows, mempool empties, and the attestation's bond is
            # now locked on-chain, so balances change too: three deltas.
            produce_block(self.overlay(0))
            pushed = await push_updates(app)
            self.assertEqual(set(pushed), {"chain", "mempool", "balances"})
            got = {}
            for _ in range(len(pushed)):
                ev = await _recv(ws)
                got[ev["type"]] = ev
            self.assertEqual(got["chain"]["height"], 2)
            self.assertEqual(got["mempool"]["mempool"], [])
            await ws.close()
        finally:
            await client.close()

    async def test_no_change_pushes_nothing(self):
        app, client = await self._client()
        try:
            ws = await client.ws_connect("/ws")
            for _ in range(5):
                await _recv(ws)

            pushed = await push_updates(app)  # nothing changed since connect
            self.assertEqual(pushed, [])
            with self.assertRaises(asyncio.TimeoutError):
                await _recv(ws)  # no message arrives
            await ws.close()
        finally:
            await client.close()

    async def test_second_client_also_gets_snapshot(self):
        app, client = await self._client()
        try:
            ws1 = await client.ws_connect("/ws")
            for _ in range(5):
                await _recv(ws1)
            ws2 = await client.ws_connect("/ws")
            types = {(await _recv(ws2))["type"] for _ in range(5)}
            self.assertEqual(
                types, {"chain", "mempool", "reputation", "balances", "peers"}
            )
            await ws1.close()
            await ws2.close()
        finally:
            await client.close()
