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

* **Slashing day** — three attesters attest honestly, enough for a certificate.
  Then an authority commits a *slash* against one of them for a provable
  violation. Reputation is re-derived from the now-longer chain — nothing is
  mutated by hand — so the slashed attester's weight drops to zero, the weighted
  support falls below the threshold, and the certificate no longer issues.

Reputation here is **chain-derived**: each node reads its own
``overlay.reputation`` (a pure function of its chain, seeded from the shared
genesis anchor), rather than any hand-built registry.

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
from crypto.keys import keypair_from_seed
from network.community import AttestationCommunity
from reputation.genesis import CONSENSUS_DOMAIN, GENESIS_AUTHORITY_KEYS
from reputation.slashing import make_slash
from reputation.tally import weighted_support

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

DEMO_DOMAIN = "general"
DEMO_THRESHOLD = 250

# The demo's three attesters, each with a REPRODUCIBLE Ed25519 keypair (fixed
# seed) so their public keys are stable across runs. Attestations are participant
# transactions: each attester signs its own, and its ``sender`` is its public key
# (``name -> (private_key, public_key_hex)``). The authority that issues slashes
# reuses the genesis authority keypair.
_ATTESTER_KEYS = {
    "alice": keypair_from_seed(bytes.fromhex("a1" * 32)),
    "bob": keypair_from_seed(bytes.fromhex("b0" * 32)),
    "carol": keypair_from_seed(bytes.fromhex("ca" * 32)),
}
_AUTHORITY_PRIVATE, _AUTHORITY_PUBKEY = GENESIS_AUTHORITY_KEYS["genesis-authority"]

# The demo's OWN genesis anchor — injected into every node, never merged into the
# canonical GENESIS_REPUTATION. It declares the demo's founding participants:
#   * the real genesis authority key, with consensus weight, so demo nodes can
#     produce (sign) valid PoA blocks; and
#   * the three attesters (keyed by their real public keys), each weight 100 in
#     the "general" domain.
# Certification decides by reputation weight: three honest attesters contribute
# 300 (over the 250 threshold); a single slash (−100) drops the total to 200,
# below it. Reputation is derived from each node's chain seeded by THIS anchor —
# no hand-built registry — read via ``overlay.reputation``.
DEMO_GENESIS = {
    _AUTHORITY_PUBKEY: {CONSENSUS_DOMAIN: 100},
    **{pubkey: {DEMO_DOMAIN: 100} for _priv, pubkey in _ATTESTER_KEYS.values()},
}


def _signed_attestation(keypair, subject, rubric_root, item_index, verdict=True, stake=1):
    """Build an attestation whose sender is the attester's key, then sign it.

    Attestations are participant transactions, so the chain now requires each to
    be signed by its author (``sender`` = the attester's public key).
    """
    private_key, public_key = keypair
    tx = make_attestation(public_key, subject, rubric_root, item_index, verdict, stake)
    tx.sign(private_key)
    return tx


def _rule(title: str) -> None:
    print("\n" + "=" * 68)
    print(title)
    print("=" * 68)


async def start_nodes() -> list[IPv8]:
    """Launch NODE_COUNT IPv8 instances, each with its own chain and key file."""
    instances: list[IPv8] = []
    for i in range(NODE_COUNT):
        # Every node validates against the SAME demo anchor — shared network
        # configuration, exactly like the genesis block. A node given a different
        # anchor would compute different authorities and diverge.
        chain = Blockchain(genesis=DEMO_GENESIS)
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
    attesters = list(_ATTESTER_KEYS.items())
    for i, node in enumerate(nodes):
        name, keypair = attesters[i]
        tx = _signed_attestation(keypair, SUBJECT, rubric_root, i)
        fanout = node.broadcast_attestation(tx)
        # The attester's own node also pools its attestation locally.
        node.blockchain.add_transaction(tx)
        print(f"Step {i + 1}: {name} on node {i} attested item {i} "
              f"(verdict=True) -> broadcast to {fanout} peers")
    await asyncio.sleep(0.6)  # let the gossip land

    pooled = [len(n.blockchain.mempool) for n in nodes]
    print(f"Step 4: attestations propagated — mempool sizes per node: {pooled}")

    print("Step 5: node 0 mines the pooled attestations into a block and gossips it")
    nodes[0].mine_and_broadcast_block()
    await asyncio.sleep(0.6)

    print("Step 6: node 0 runs the aggregator against the published rubric root")
    cert = certify(
        nodes[0].blockchain, nodes[0].reputation, SUBJECT, rubric_root,
        DEMO_DOMAIN, threshold=DEMO_THRESHOLD,
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

    attesters = list(_ATTESTER_KEYS.items())
    for i, node in enumerate(nodes):
        name, keypair = attesters[i]
        # The tamper is in the referenced root; the attestation is still validly
        # signed by its author (an honest node just won't recognise the root).
        tx = _signed_attestation(keypair, subject, tampered_root, i)
        node.broadcast_attestation(tx)
        node.blockchain.add_transaction(tx)
        # The receiving side accepts well-formed attestations, but an honest
        # node checks the referenced root against the rubric it published.
        recognised = tx.payload["rubric_root"] == real_root
        print(f"Step {i + 1}: {name} attested against a forged root "
              f"-> recognised by honest nodes: {recognised}")
    await asyncio.sleep(0.6)

    print("Step 4: node 0 mines whatever propagated and runs the aggregator")
    nodes[0].mine_and_broadcast_block()
    await asyncio.sleep(0.6)

    # The aggregator only pools votes bound to the *published* root, so the
    # forged votes never count toward this subject's certification.
    cert = certify(
        nodes[0].blockchain, nodes[0].reputation, subject, real_root,
        DEMO_DOMAIN, threshold=DEMO_THRESHOLD,
    )
    print(f"  certify() against the published root -> {cert!r}")
    print(f"  certificate issued: {cert is not None}  (expected: False)")


async def slashing_day(nodes: list[AttestationCommunity]) -> None:
    _rule("SLASHING DAY — a slash drops support below the threshold")
    rubric_root = RUBRIC.root()
    subject = "536c617368656453756266"  # yet another subject, independent state
    attesters = list(_ATTESTER_KEYS.items())
    print(f"Published rubric root: {rubric_root[:16]}…")
    print(f"Subject under review : {subject}")

    # 1. All three attest honestly against the published rubric.
    for i, node in enumerate(nodes):
        name, keypair = attesters[i]
        tx = _signed_attestation(keypair, subject, rubric_root, i)
        node.broadcast_attestation(tx)
        node.blockchain.add_transaction(tx)
        print(f"Step {i + 1}: {name} attested item {i} (verdict=True)")
    await asyncio.sleep(0.6)
    nodes[0].mine_and_broadcast_block()
    await asyncio.sleep(0.6)

    # 2. Before any slash, support is 3 × 100 = 300 ≥ 250, so a certificate would issue.
    support_before = weighted_support(
        nodes[0].blockchain, nodes[0].reputation, subject, rubric_root, DEMO_DOMAIN
    )
    cert_before = certify(
        nodes[0].blockchain, nodes[0].reputation, subject, rubric_root,
        DEMO_DOMAIN, threshold=DEMO_THRESHOLD,
    )
    print(f"Step 4: weighted support before slash = {support_before} "
          f"(threshold {DEMO_THRESHOLD}) -> certificate would issue: "
          f"{cert_before is not None}")

    # 3. An authority slashes one attester for a *provable* violation (here, a
    #    stand-in reference). A slash is a participant transaction issued by an
    #    authority, so it is signed by that authority (sender = its public key).
    #    The slash is a chain event; reputation is re-derived from the chain, so
    #    no registry is mutated by hand.
    carol_pubkey = _ATTESTER_KEYS["carol"][1]
    slash = make_slash(
        offender=carol_pubkey,
        domain=DEMO_DOMAIN,
        reason="signed two contradictory verdicts for the same claim",
        reference="<hash-of-offending-attestation>",
        amount=100,
        issuer=_AUTHORITY_PUBKEY,
    )
    slash.sign(_AUTHORITY_PRIVATE)
    nodes[0].blockchain.add_transaction(slash)
    nodes[0].mine_and_broadcast_block()
    await asyncio.sleep(0.6)
    print("Step 5: an authority slashed carol (−100 in 'general'), "
          "mined into a block")

    # 4. Re-derived from the now-longer chain, carol's weight is 0, so support is
    #    2 × 100 = 200 < 250 — the certificate no longer issues.
    support_after = weighted_support(
        nodes[0].blockchain, nodes[0].reputation, subject, rubric_root, DEMO_DOMAIN
    )
    cert_after = certify(
        nodes[0].blockchain, nodes[0].reputation, subject, rubric_root,
        DEMO_DOMAIN, threshold=DEMO_THRESHOLD,
    )
    print(f"Step 6: weighted support after slash = {support_after} "
          f"(threshold {DEMO_THRESHOLD}) -> certificate issued: "
          f"{cert_after is not None}  (expected: False)")


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
        await slashing_day(nodes)
    finally:
        _rule("Shutting down nodes")
        for ipv8 in instances:
            await ipv8.stop()
        print("Done.")


if __name__ == "__main__":
    asyncio.run(main())
