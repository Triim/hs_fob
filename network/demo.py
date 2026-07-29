"""Multi-node attestation demo.

Starts three real IPv8 instances in one process (each with its own EC key file
``ec1.pem`` / ``ec2.pem`` / ``ec3.pem``, as in the IPv8 overlay tutorial), lets
them discover each other over UDP loopback, and runs two scenarios end to end:

* **Sunny day** — three attesters on three different nodes each attest a distinct
  rubric item for one subject. The attestations gossip to every node, one node
  mines them into a block, the aggregator sees the acceptance threshold met and
  issues a certificate, and that certificate is mined into a further block that
  every node converges on.

* **Rainy day** — attesters submit attestations that reference a *tampered*
  rubric root. They still gossip (the transport is deliberately permissive), but
  the aggregation layer — the real trust boundary — counts a vote only when it is
  bound to the *published* rubric, so the forged votes are ignored and **no
  certificate is issued**.

Run it with::

    uv run python -m network.demo

Peers are introduced manually by (public key, loopback address) so the demo is
fully self-contained and needs no internet bootstrap servers. Identity is always
the peer's public key, never its address.
"""

from __future__ import annotations

import asyncio
import os

from ipv8.configuration import ConfigBuilder
from ipv8.peer import Peer
from ipv8_service import IPv8

from attestation.aggregator import certify
from attestation.attestation import make_attestation
from attestation.rubric import Rubric
from blockchain.blockchain import Blockchain
from network.community import AttestationCommunity
from reputation.registry import ReputationRegistry

# Low difficulty keeps the demo's mining near-instant while still doing real PoW.
DEMO_DIFFICULTY = 8
BASE_PORT = 9090
NODE_COUNT = 3

# The rubric every honest node has published and agrees on.
RUBRIC = Rubric(
    [
        "Can derive a Merkle root by hand",
        "Can explain proof-of-work difficulty",
        "Can validate a chain end to end",
    ]
)

# Who the attestations are about (a stand-in hex public key for the student).
SUBJECT = "5375626a6563745075624b6579"  # "SubjectPubKey" in hex, for legibility

# The demo's three attesters each carry weight 1 in the (default) "general"
# domain, so the weighted aggregator behaves as a head count here — preserving
# the original "threshold of 3 distinct attesters" narrative unchanged now that
# certify() decides by reputation weight.
DEMO_DOMAIN = "general"
DEMO_REGISTRY = ReputationRegistry(
    {
        "attester-alice": {DEMO_DOMAIN: 1},
        "attester-bob": {DEMO_DOMAIN: 1},
        "attester-carol": {DEMO_DOMAIN: 1},
    }
)


def _rule(title: str) -> None:
    print("\n" + "=" * 68)
    print(title)
    print("=" * 68)


async def start_nodes() -> list[IPv8]:
    """Launch NODE_COUNT IPv8 instances, each with its own chain and key file."""
    instances: list[IPv8] = []
    for i in range(NODE_COUNT):
        chain = Blockchain(difficulty=DEMO_DIFFICULTY)
        builder = ConfigBuilder().clear_keys().clear_overlays()
        builder.set_port(BASE_PORT + i)
        # Distinct persisted EC key per node, exactly as the overlay tutorial does.
        builder.add_key("my peer", "medium", f"ec{i + 1}.pem")
        # No walkers/bootstrappers: we introduce peers manually below, so the
        # demo is deterministic and offline. The live chain is injected here.
        builder.add_overlay(
            "CompetenceAttestationCommunity",
            "my peer",
            [],
            [],
            {"blockchain": chain},
            [],
        )
        ipv8 = IPv8(
            builder.finalize(),
            extra_communities={
                "CompetenceAttestationCommunity": AttestationCommunity
            },
        )
        await ipv8.start()
        instances.append(ipv8)
    return instances


def introduce(instances: list[IPv8]) -> None:
    """Wire every node to every other by (public key, loopback address).

    Mirrors what IPv8's own test harness does: peers are added directly so
    discovery is instant and needs no bootstrap servers. Crucially, a peer is
    identified by its public key — the address is only where to send packets.
    """
    for i, node in enumerate(instances):
        overlay = node.get_overlay(AttestationCommunity)
        for j, other in enumerate(instances):
            if i == j:
                continue
            other_overlay = other.get_overlay(AttestationCommunity)
            peer = Peer(
                other_overlay.my_peer.public_key, ("127.0.0.1", BASE_PORT + j)
            )
            overlay.network.add_verified_peer(peer)
            overlay.network.discover_services(
                peer, [AttestationCommunity.community_id]
            )


def overlays(instances: list[IPv8]) -> list[AttestationCommunity]:
    return [node.get_overlay(AttestationCommunity) for node in instances]


def show_convergence(nodes: list[AttestationCommunity]) -> bool:
    """Print each node's chain tip and report whether all agree."""
    tips = []
    for i, node in enumerate(nodes):
        chain = node.blockchain
        tip = chain.last_block
        tips.append(tip.hash)
        print(
            f"  node {i}: height={len(chain.blocks)} "
            f"tip={tip.hash[:16]}… valid={chain.is_valid_chain()}"
        )
    converged = len(set(tips)) == 1
    print(f"  --> all nodes converged: {converged}")
    return converged


def chain_has_certificate(chain: Blockchain, subject: str) -> bool:
    """True if a certificate transaction for ``subject`` is committed anywhere."""
    for block in chain.blocks:
        for tx in block.transactions:
            if tx.payload.get("type") == "certificate" and tx.payload.get(
                "subject"
            ) == subject:
                return True
    return False


async def sunny_day(nodes: list[AttestationCommunity]) -> None:
    _rule("SUNNY DAY — honest attestations lead to a certificate")
    rubric_root = RUBRIC.root()
    print(f"Published rubric root: {rubric_root[:16]}…  ({len(RUBRIC.claims)} items)")
    print(f"Subject under review : {SUBJECT}")

    # Each node hosts a distinct attester who signs off one rubric item.
    attesters = ["attester-alice", "attester-bob", "attester-carol"]
    for i, node in enumerate(nodes):
        tx = make_attestation(
            attester=attesters[i],
            subject=SUBJECT,
            rubric_root=rubric_root,
            item_index=i,
            verdict=True,
            stake=1,
        )
        fanout = node.broadcast_attestation(tx)
        # The attester's own node also pools its attestation locally.
        node.blockchain.add_transaction(tx)
        print(f"Step {i + 1}: {attesters[i]} on node {i} attested item {i} "
              f"(verdict=True) -> broadcast to {fanout} peers")
    await asyncio.sleep(0.6)  # let the gossip land

    pooled = [len(n.blockchain.mempool) for n in nodes]
    print(f"Step 4: attestations propagated — mempool sizes per node: {pooled}")

    print("Step 5: node 0 mines the pooled attestations into a block and gossips it")
    nodes[0].mine_and_broadcast_block()
    await asyncio.sleep(0.6)

    print("Step 6: node 0 runs the aggregator against the published rubric root")
    cert = certify(
        nodes[0].blockchain, DEMO_REGISTRY, SUBJECT, rubric_root, DEMO_DOMAIN, threshold=3
    )
    if cert is None:
        print("  UNEXPECTED: threshold not met — no certificate")
        return
    print(f"  threshold met by {cert.payload['granted_by']}")
    print(f"  certificate issued for subject {cert.payload['subject']}")

    print("Step 7: the certificate is mined into a block and gossiped to all nodes")
    nodes[0].blockchain.add_transaction(cert)
    nodes[0].mine_and_broadcast_block()
    await asyncio.sleep(0.6)

    print("Step 8: convergence check")
    show_convergence(nodes)
    for i, node in enumerate(nodes):
        has = chain_has_certificate(node.blockchain, SUBJECT)
        print(f"  node {i} chain contains the certificate: {has}")


async def rainy_day(nodes: list[AttestationCommunity]) -> None:
    _rule("RAINY DAY — forged rubric root yields no certificate")
    real_root = RUBRIC.root()
    tampered_root = "deadbeef" * 8  # a rubric root nobody published
    subject = "426164537562"  # a different subject, to keep state independent
    print(f"Published rubric root: {real_root[:16]}…")
    print(f"Forged rubric root   : {tampered_root[:16]}…  (never published)")

    attesters = ["attester-alice", "attester-bob", "attester-carol"]
    for i, node in enumerate(nodes):
        tx = make_attestation(
            attester=attesters[i],
            subject=subject,
            rubric_root=tampered_root,  # <-- the tamper
            item_index=i,
            verdict=True,
            stake=1,
        )
        node.broadcast_attestation(tx)
        node.blockchain.add_transaction(tx)
        # The receiving side accepts well-formed attestations, but an honest
        # node checks the referenced root against the rubric it published.
        recognised = tx.payload["rubric_root"] == real_root
        print(f"Step {i + 1}: {attesters[i]} attested against a forged root "
              f"-> recognised by honest nodes: {recognised}")
    await asyncio.sleep(0.6)

    print("Step 4: node 0 mines whatever propagated and runs the aggregator")
    nodes[0].mine_and_broadcast_block()
    await asyncio.sleep(0.6)

    # The aggregator only pools votes bound to the *published* root, so the
    # forged votes never count toward this subject's certification.
    cert = certify(
        nodes[0].blockchain, DEMO_REGISTRY, subject, real_root, DEMO_DOMAIN, threshold=3
    )
    print(f"  certify() against the published root -> {cert!r}")
    print(f"  certificate issued: {cert is not None}  (expected: False)")


async def main() -> None:
    _rule("Decentralized competence attestation — multi-node demo")
    print(f"Starting {NODE_COUNT} IPv8 nodes on ports "
          f"{BASE_PORT}–{BASE_PORT + NODE_COUNT - 1} …")
    instances = await start_nodes()
    introduce(instances)
    await asyncio.sleep(0.5)  # settle peer tables

    nodes = overlays(instances)
    peer_counts = [len(n.get_peers()) for n in nodes]
    print(f"Peers discovered per node: {peer_counts}")

    try:
        await sunny_day(nodes)
        await rainy_day(nodes)
    finally:
        _rule("Shutting down nodes")
        for ipv8 in instances:
            await ipv8.stop()
        print("Done.")


if __name__ == "__main__":
    asyncio.run(main())
