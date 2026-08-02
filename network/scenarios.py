"""On-demand demo scenarios for a live defense.

Where :mod:`network.demo` auto-plays a fixed three-act script once at startup,
this module drives the **same real network** on demand: each scenario is a
coroutine that runs one scripted story against the already-running IPv8 nodes and
returns a structured, step-by-step JSON log the UI can render. Nothing here
changes consensus, attestation, or reputation logic — every decision is still
taken by the core (``certify``, ``weighted_support``, ``is_final``,
``validate_slash``, the collusion cap); the scenarios only *arrange the inputs*
and *read out* what the chain derived.

The network
-----------
:func:`start_network` launches ``n`` IPv8 nodes (``n >= 4`` so BFT tolerates one
fault: ``n=4, f=1, quorum=3``), **all genesis validators**. Node order fixes the
validator identities: nodes 0–2 are the three attesters (alice/bob/carol, who
also carry competence in :data:`DEMO_DOMAIN`), node 3 is the genesis authority,
and nodes 4… are extra consensus-only validators. A separate set of *colluders*
are high-competence attester identities that are **not** validators — they exist
only to drive the collusion scenario. The genesis reputation and balance anchors
are built to match, then shared (identical) across every node, exactly like the
genesis block.

State model
-----------
Scenarios **accumulate** on one shared chain — they do not reset between runs — so
the chain stays inspectable and each run is auditable end to end. To keep repeated
runs independent (a live defense re-runs a scenario freely), every run mints a
**fresh subject** via a per-network nonce, so re-running ``sunny`` certifies a new
subject rather than double-issuing (which consensus would reject). The one
scenario that needs transient isolation is ``view_change``: it takes a validator
offline for the duration by removing it from the peer mesh, then re-introduces it
and lets it fork-sync back — documented, self-healing isolation.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

from ipv8.configuration import ConfigBuilder
from ipv8_service import IPv8

from attestation.aggregator import certify
from attestation.attestation import make_attestation
from attestation.submission import hash_artifact, make_submission
from blockchain.blockchain import Blockchain, quorum_size
from crypto.keys import generate_keypair, keypair_from_seed
from ipv8.peer import Peer

from network.community import AttestationCommunity
from network.demo import (
    DEMO_DOMAIN,
    DEMO_DOMAINS,
    DEMO_EXPERT_WEIGHTS,
    DEMO_STAKE,
    DEMO_THRESHOLD,
    RUBRIC,
    chain_has_certificate,
    mine_scheduled,
    overlays,
)
from reputation.genesis import CONSENSUS_DOMAIN, GENESIS_AUTHORITY_KEYS
from reputation.slashing import approve_slash, make_slash
from reputation.tally import attester_clusters, capped_support, weighted_support

# Default UDP base port for the IPv8 nodes (node ``i`` listens on ``base + i``),
# matching the demo so the two never collide with each other's defaults only when
# run together on the same host (override via CLI if needed).
BASE_UDP_PORT = 9090

# Reproducible seeds so identities are stable across runs (nice for a defense: the
# same short pubkey prefixes appear every time). The three attesters double as the
# first three validators and carry DEMO_DOMAIN competence; the colluders carry
# competence but are NOT validators — they drive the collusion scenario only.
_ATTESTER_SEEDS = {
    "alice": "a1" * 32,
    "bob": "b0" * 32,
    "carol": "ca" * 32,
}
_COLLUDER_SEEDS = {
    "mallory": "11" * 32,
    "trent": "22" * 32,
    "sybil": "33" * 32,
}
# Dedicated equivocators for the slash scenario. A slash permanently zeroes the
# offender's competence in the domain (chain-derived, irreversible), so slashing a
# *shared* attester would break every later ``sunny`` run. These identities exist
# ONLY to be slashed: each has competence but is never a validator and is used by
# no other scenario, so slashing one leaves alice/bob/carol untouched. The scenario
# consumes the next unslashed offender per run, so a handful of clean re-runs are
# available before the pool is exhausted (after which it degrades gracefully — the
# step log simply reports the lower, real support).
_OFFENDER_SEEDS = {
    f"offender{i}": f"{0x40 + i:02x}" * 32 for i in range(6)
}

# How long to let gossip settle after a broadcast before reading the outcome.
# Larger validator sets need longer: a block only finalizes once a *quorum* of
# commits has flooded the mesh, and convergence is driven by that finality, so the
# window grows with the node count. Tuned so n=4 stays snappy (~0.6s) while n=7+
# still reaches quorum and converges before we read the chain.
_SETTLE_BASE = 0.45
_SETTLE_PER_NODE = 0.12


def _settle_for(n: int) -> float:
    """Gossip-settle window scaled to the validator-set size (bigger set → longer)."""
    return _SETTLE_BASE + _SETTLE_PER_NODE * n


@dataclass
class ScenarioNet:
    """The live network a scenario runs against, plus the keys it scripts with.

    Holds the running IPv8 ``instances`` and their ``nodes`` (communities), the
    attester / colluder / validator keypairs by identity, and a monotonic
    ``_nonce`` used to mint a fresh subject per run so repeated scenarios never
    collide on the chain.
    """

    instances: list[IPv8]
    nodes: list[AttestationCommunity]
    base_udp_port: int
    attesters: dict[str, tuple]          # name -> (private_key, public_hex)
    colluders: dict[str, tuple]          # name -> (private_key, public_hex)
    offenders: dict[str, tuple]          # name -> (private_key, public_hex)
    authority: tuple                     # (private_key, public_hex)
    validator_privs: dict[str, object]   # validator pubkey -> private key
    _nonce: int = field(default=0)

    def next_subject(self, tag: str) -> str:
        """A fresh, deterministic hex subject id for this run (keeps runs independent)."""
        self._nonce += 1
        return f"subject-{tag}-{self._nonce}".encode("utf-8").hex()

    def next_offender(self, ref_node) -> tuple[str, tuple]:
        """The next unslashed offender identity (falls back to the first if all spent).

        Picks the first pool member still holding full competence on ``ref_node``'s
        chain, so a re-run slashes a fresh identity and shows the full 300→200 drop.
        Once the pool is exhausted every member is at 0, so the first is reused and
        the scenario degrades gracefully (the log reports the real, lower support).
        """
        for name, keypair in self.offenders.items():
            if ref_node.reputation.weight(keypair[1], DEMO_DOMAIN) >= 100:
                return name, keypair
        return next(iter(self.offenders.items()))


def _validator_keys(n: int, attesters, authority):
    """Node-ordered validator private keys and the pubkey->private map for approvals.

    Node order pins validator identity: [alice, bob, carol, authority, extra…].
    Extra validators (for ``n > 4``) get reproducible consensus-only keypairs.
    Returns ``(node_privs, extra_keypairs, validator_privs_by_pub)``.
    """
    ordered = [
        attesters["alice"],
        attesters["bob"],
        attesters["carol"],
        authority,
    ]
    extra = []
    for i in range(4, n):
        kp = keypair_from_seed(bytes.fromhex(f"{0xE0 + i:02x}" * 32))
        extra.append(kp)
        ordered.append(kp)
    node_privs = [priv for priv, _pub in ordered[:n]]
    validator_privs = {pub: priv for priv, pub in ordered[:n]}
    return node_privs, extra, validator_privs


def _anchors(attesters, colluders, offenders, authority, extra):
    """Build the shared genesis reputation and balance anchors for the network.

    Attesters are validators (CONSENSUS_DOMAIN) *and* competent (DEMO_DOMAIN); the
    authority and extras are consensus-only validators; colluders and offenders are
    competent (DEMO_DOMAIN) but hold no consensus weight, so they can never validate.
    Colluders exist to over-concentrate attester weight (which the cap clamps);
    offenders exist to be slashed without touching the shared attesters.
    """
    genesis: dict[str, dict[str, int]] = {}
    balances: dict[str, int] = {}
    for name, (_priv, pub) in attesters.items():
        # Uneven per-domain competence (see DEMO_EXPERT_WEIGHTS): full weight in
        # DEMO_DOMAIN so the scripted scenarios still certify, diverging elsewhere so
        # the reputation matrix shows weight is domain-scoped, not global.
        genesis[pub] = {CONSENSUS_DOMAIN: 100, **DEMO_EXPERT_WEIGHTS[name]}
        balances[pub] = 100
    _authority_priv, authority_pub = authority
    genesis[authority_pub] = {CONSENSUS_DOMAIN: 100}
    balances[authority_pub] = 100
    for _priv, pub in extra:
        genesis[pub] = {CONSENSUS_DOMAIN: 100}
    for _priv, pub in [*colluders.values(), *offenders.values()]:
        genesis[pub] = {DEMO_DOMAIN: 100}
        balances[pub] = 100
    return genesis, balances


def introduce(instances: list[IPv8], base_udp_port: int) -> None:
    """Wire every node to every other by (public key, loopback address).

    Port-aware counterpart of :func:`network.demo.introduce` (which hardcodes the
    demo's base port): peers are added directly at ``base_udp_port + j`` so a
    network started on a non-default UDP base still delivers packets to the right
    address. Identity is always the peer's public key; the address is only where
    to send. Idempotent, so it doubles as the re-introduce step that heals the
    ``view_change`` scenario's temporarily-isolated node.
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


async def start_network(n: int, base_udp_port: int = BASE_UDP_PORT) -> ScenarioNet:
    """Launch ``n`` genesis-validator IPv8 nodes on one loop and wire them together.

    ``n`` must be ``>= 4`` so the BFT quorum tolerates one faulty/offline validator
    (n=4, f=1, quorum=3). Every node validates against the SAME shared anchors, so
    they agree on validators and balances exactly like the genesis block. Returns a
    :class:`ScenarioNet` bundling the running instances, their communities, and the
    keypairs the scenarios script with.
    """
    if n < 4:
        raise ValueError(f"need at least 4 validators for BFT (got {n})")
    attesters = {
        name: keypair_from_seed(bytes.fromhex(seed))
        for name, seed in _ATTESTER_SEEDS.items()
    }
    colluders = {
        name: keypair_from_seed(bytes.fromhex(seed))
        for name, seed in _COLLUDER_SEEDS.items()
    }
    offenders = {
        name: keypair_from_seed(bytes.fromhex(seed))
        for name, seed in _OFFENDER_SEEDS.items()
    }
    authority = GENESIS_AUTHORITY_KEYS["genesis-authority"]

    node_privs, extra, validator_privs = _validator_keys(n, attesters, authority)
    genesis, balances = _anchors(attesters, colluders, offenders, authority, extra)

    instances: list[IPv8] = []
    for i in range(n):
        chain = Blockchain(genesis=genesis, balances=balances)
        builder = ConfigBuilder().clear_keys().clear_overlays()
        builder.set_port(base_udp_port + i)
        builder.add_key("my peer", "medium", f"ec{i + 1}.pem")
        builder.add_overlay(
            "CompetenceAttestationCommunity",
            "my peer",
            [],
            [],
            {"blockchain": chain, "producer_key": node_privs[i]},
            [],
        )
        ipv8 = IPv8(
            builder.finalize(),
            extra_communities={"CompetenceAttestationCommunity": AttestationCommunity},
        )
        await ipv8.start()
        instances.append(ipv8)

    introduce(instances, base_udp_port)
    await asyncio.sleep(0.5)  # settle peer tables
    nodes = overlays(instances)
    return ScenarioNet(
        instances=instances,
        nodes=nodes,
        base_udp_port=base_udp_port,
        attesters=attesters,
        colluders=colluders,
        offenders=offenders,
        authority=authority,
        validator_privs=validator_privs,
    )


# --------------------------------------------------------------- small helpers


class _StepLog:
    """Accumulates ordered ``{step, detail}`` entries for a scenario's JSON log."""

    def __init__(self) -> None:
        self.steps: list[dict] = []

    def add(self, detail: str) -> None:
        self.steps.append({"step": len(self.steps) + 1, "detail": detail})


def _signed_attestation(keypair, subject, rubric_root, item, submission_tx_hash,
                        verdict=True, stake=DEMO_STAKE):
    """Build one attestation whose sender is the attester's key, then sign it."""
    private_key, public_key = keypair
    tx = make_attestation(
        public_key, subject, rubric_root, item, verdict, stake, submission_tx_hash, DEMO_DOMAIN
    )
    tx.sign(private_key)
    return tx


def _submission_hash(subject, rubric_root):
    """The submission-tx hash every review of one piece of work binds to."""
    submission = make_submission(
        subject=subject,
        domain=DEMO_DOMAIN,
        rubric_root=rubric_root,
        title="Live scenario submission",
        artifact_hash=hash_artifact(b"scenario artifact for " + subject.encode()),
    )
    return submission.hash


def _random_submission(rubric_root):
    """A freshly-signed submission, so a produced block carries visible content."""
    priv, pub = generate_keypair()
    tx = make_submission(
        subject=pub,
        domain=DEMO_DOMAIN,
        rubric_root=rubric_root,
        title="Live scenario filler submission",
        artifact_hash=hash_artifact(b"filler bytes"),
    )
    tx.sign(priv)
    return tx


def _balances_view(ref_node, net: ScenarioNet) -> dict:
    """Chain-derived total/locked/free for every scripted identity, keyed by name."""
    ledger = ref_node.balances
    out = {}
    for name, (_priv, pub) in {**net.attesters, **net.colluders, **net.offenders}.items():
        out[name] = {
            "total": ledger.total(pub),
            "locked": ledger.locked(pub),
            "free": ledger.free(pub),
        }
    return out


def _reputation_view(ref_node, net: ScenarioNet) -> dict:
    """Chain-derived weight per identity across ALL demo domains + consensus.

    Reporting every domain (not just DEMO_DOMAIN) is what makes domain-scoping
    visible in a scenario's result table: alice carries data-science weight but zero
    instructional-design, bob the reverse, so the same identity's influence changes
    with the domain in play.
    """
    reg = ref_node.reputation
    domains = [*DEMO_DOMAINS, CONSENSUS_DOMAIN]
    out = {}
    for name, (_priv, pub) in {**net.attesters, **net.colluders, **net.offenders}.items():
        out[name] = {d: reg.weight(pub, d) for d in domains}
    return out


def _result(name, log, net, *, ref_node=None, certificate_issued=None, extra=None) -> dict:
    """Assemble a scenario's JSON: steps + resulting height/finality/balances/reputation."""
    ref = ref_node or net.nodes[0]
    chain = ref.blockchain
    tip = chain.last_block
    res = {
        "scenario": name,
        "steps": log.steps,
        "chain_height": len(chain.blocks),
        "tip_hash": tip.hash,
        "finalized": chain.is_final(tip),
        "balances": _balances_view(ref, net),
        "reputation": _reputation_view(ref, net),
    }
    if certificate_issued is not None:
        res["certificate_issued"] = certificate_issued
    if extra:
        res.update(extra)
    return res


# ----------------------------------------------------------------- scenarios


async def scenario_sunny(net: ScenarioNet) -> dict:
    """Honest attestations meet the weighted threshold → certificate, finalized by quorum."""
    log = _StepLog()
    nodes = net.nodes
    settle = _settle_for(len(nodes))
    root = RUBRIC.root()
    subject = net.next_subject("sunny")
    sub_hash = _submission_hash(subject, root)
    log.add(f"domain '{DEMO_DOMAIN}': published rubric root {root[:16]}…; "
            f"subject under review {subject[:16]}…")

    for i, (name, keypair) in enumerate(net.attesters.items()):
        tx = _signed_attestation(keypair, subject, root, i, sub_hash, True, DEMO_STAKE)
        nodes[i].broadcast_attestation(tx)
        nodes[i].blockchain.add_transaction(tx)
        log.add(f"{name} (node {i}) attested item {i} verdict=True in '{DEMO_DOMAIN}', "
                f"bonding {DEMO_STAKE}")
    await asyncio.sleep(settle)

    proposer, block = await mine_scheduled(nodes, settle=settle)
    log.add(f"scheduled proposer {proposer.validator_pubkey[:12]}… mined "
            f"attestations into block {block.index}")

    cert = certify(
        nodes[0].blockchain, nodes[0].reputation, subject, root,
        DEMO_DOMAIN, sub_hash, threshold=DEMO_THRESHOLD,
    )
    if cert is None:
        log.add(f"UNEXPECTED: weighted support below threshold {DEMO_THRESHOLD} — no certificate")
        return _result("sunny", log, net, certificate_issued=False)

    support = weighted_support(
        nodes[0].blockchain, nodes[0].reputation, subject, root, DEMO_DOMAIN, sub_hash
    )
    log.add(f"weighted support {support} ≥ threshold {DEMO_THRESHOLD}; certificate "
            f"granted by {len(cert.payload['granted_by'])} attesters")

    node, cert_block = await mine_scheduled(nodes, extra_txs=[cert], settle=settle)
    log.add(f"certificate mined into block {cert_block.index}; "
            f"finalized={node.blockchain.is_final(cert_block)} by quorum commit")

    issued = chain_has_certificate(nodes[0].blockchain, subject)
    return _result("sunny", log, net, certificate_issued=issued,
                   extra={"domain": DEMO_DOMAIN})


async def scenario_rainy(net: ScenarioNet) -> dict:
    """Attestations cite a forged rubric root → the aggregator counts none, no certificate."""
    log = _StepLog()
    nodes = net.nodes
    settle = _settle_for(len(nodes))
    real_root = RUBRIC.root()
    forged_root = "deadbeef" * 8  # a root nobody published
    subject = net.next_subject("rainy")
    sub_hash = _submission_hash(subject, forged_root)
    log.add(f"published rubric root {real_root[:16]}…; forged root {forged_root[:16]}… (never published)")

    for i, (name, keypair) in enumerate(net.attesters.items()):
        tx = _signed_attestation(keypair, subject, forged_root, i, sub_hash, True, DEMO_STAKE)
        nodes[i].broadcast_attestation(tx)
        nodes[i].blockchain.add_transaction(tx)
        log.add(f"{name} attested against the forged root — honest nodes will not recognise it")
    await asyncio.sleep(settle)

    proposer, block = await mine_scheduled(nodes, settle=settle)
    log.add(f"scheduled proposer mined the forged-root attestations into block {block.index}")

    cert = certify(
        nodes[0].blockchain, nodes[0].reputation, subject, real_root,
        DEMO_DOMAIN, sub_hash, threshold=DEMO_THRESHOLD,
    )
    log.add(f"aggregator run against the PUBLISHED root → certificate issued: {cert is not None} "
            f"(expected False: no vote is bound to the real rubric)")
    return _result("rainy", log, net, certificate_issued=cert is not None,
                   extra={"domain": DEMO_DOMAIN})


async def scenario_slash(net: ScenarioNet) -> dict:
    """Equivocation → evidence + validator quorum slash → bond burned, support drops below threshold.

    Two stable honest attesters (alice, bob — stake-free here, so their balances
    don't accumulate across runs) plus one **dedicated offender** attest positively
    (weighted support 300). The offender then equivocates and is slashed with
    evidence + a validator quorum, burning its bond and dropping support to 200 <
    threshold. The offender is a throwaway identity used by no other scenario, so
    the slash never damages alice/bob/carol and ``sunny`` keeps working.
    """
    log = _StepLog()
    nodes = net.nodes
    settle = _settle_for(len(nodes))
    root = RUBRIC.root()
    subject = net.next_subject("slash")
    sub_hash = _submission_hash(subject, root)
    log.add(f"published rubric root {root[:16]}…; subject under review {subject[:16]}…")

    # Two stable honest attesters (stake-free) carry 200 of the support …
    honest_attesters = [("alice", net.attesters["alice"]), ("bob", net.attesters["bob"])]
    for i, (name, keypair) in enumerate(honest_attesters):
        tx = _signed_attestation(keypair, subject, root, i, sub_hash, True, 0)
        node = nodes[i]
        node.broadcast_attestation(tx)
        node.blockchain.add_transaction(tx)
        log.add(f"{name} attested item {i} verdict=True")

    # … and the dedicated offender attests honestly (item 2, bonding a real stake).
    off_name, (off_priv, off_pub) = net.next_offender(nodes[0])
    honest_off = _signed_attestation((off_priv, off_pub), subject, root, 2, sub_hash, True, DEMO_STAKE)
    nodes[0].broadcast_transaction(honest_off)
    nodes[0].blockchain.add_transaction(honest_off)
    log.add(f"{off_name} attested item 2 verdict=True, bonding {DEMO_STAKE}")

    # The offender EQUIVOCATES: opposite verdict on the same claim — the evidence.
    conflict = make_attestation(off_pub, subject, root, 2, False, DEMO_STAKE, sub_hash, DEMO_DOMAIN)
    conflict.sign(off_priv)
    nodes[0].broadcast_transaction(conflict)
    log.add(f"{off_name} EQUIVOCATED — signed verdict=False on the same item 2 (verdict=True already made)")
    await asyncio.sleep(settle)
    await mine_scheduled(nodes, extra_txs=[honest_off, conflict], settle=settle)

    support_before = weighted_support(
        nodes[0].blockchain, nodes[0].reputation, subject, root, DEMO_DOMAIN, sub_hash
    )
    log.add(f"weighted support before slash = {support_before} (threshold {DEMO_THRESHOLD}) — "
            f"a certificate would issue")

    height = len(nodes[0].blockchain.blocks)
    validators = nodes[0].blockchain.validator_set(height)
    evidence = sorted([honest_off.hash, conflict.hash])
    amount = 100
    # Every current validator approves — always a quorum (the offender is not a
    # validator, so the whole set is available).
    approver_privs = [priv for pub, priv in net.validator_privs.items() if pub in validators]
    approvals = dict(
        approve_slash(priv, off_pub, DEMO_DOMAIN, amount, evidence)
        for priv in approver_privs
    )
    slash = make_slash(
        offender=off_pub, domain=DEMO_DOMAIN, evidence=evidence,
        approvals=approvals, amount=amount,
    )
    await mine_scheduled(nodes, extra_txs=[slash], settle=settle)
    log.add(f"quorum-approved slash of {off_name} (−{amount} in '{DEMO_DOMAIN}') mined — "
            f"{len(approvals)} of {len(validators)} validators approved "
            f"(quorum {quorum_size(len(validators))})")

    support_after = weighted_support(
        nodes[0].blockchain, nodes[0].reputation, subject, root, DEMO_DOMAIN, sub_hash
    )
    cert_after = certify(
        nodes[0].blockchain, nodes[0].reputation, subject, root,
        DEMO_DOMAIN, sub_hash, threshold=DEMO_THRESHOLD,
    )
    log.add(f"weighted support after slash = {support_after} (threshold {DEMO_THRESHOLD}) → "
            f"certificate issued: {cert_after is not None} (expected False); {off_name}'s bond burned")
    return _result("slash", log, net, certificate_issued=cert_after is not None,
                   extra={"offender": off_name, "support_before": support_before,
                          "support_after": support_after, "domain": DEMO_DOMAIN})


async def scenario_collusion(net: ScenarioNet) -> dict:
    """A cross-attesting cluster over-concentrates weight; the ALPHA cap clamps it below threshold."""
    log = _StepLog()
    nodes = net.nodes
    settle = _settle_for(len(nodes))
    root = RUBRIC.root()
    colluders = list(net.colluders.items())
    target = net.next_subject("collusion")
    log.add(f"{len(colluders)} colluders each hold {DEMO_DOMAIN} weight 100 "
            f"(raw sum {100 * len(colluders)} ≥ threshold {DEMO_THRESHOLD})")

    pending = []
    # 1. Mutual cross-attestation: every colluder positively attests every other,
    #    forming one collusion cluster (mutual-edge connected component).
    for a_name, a_kp in colluders:
        for b_name, (_b_priv, b_pub) in colluders:
            if a_name == b_name:
                continue
            sh = _submission_hash(b_pub, root)
            tx = _signed_attestation(a_kp, b_pub, root, 0, sh, True, 0)
            nodes[0].blockchain.add_transaction(tx)
            nodes[0].broadcast_transaction(tx)
            pending.append(tx)
    log.add("colluders mutually cross-attested each other → they form one cluster")

    # 2. The whole cluster piles onto one target subject.
    target_hash = _submission_hash(target, root)
    for i, (name, kp) in enumerate(colluders):
        tx = _signed_attestation(kp, target, root, i, target_hash, True, 0)
        nodes[0].blockchain.add_transaction(tx)
        nodes[0].broadcast_transaction(tx)
        pending.append(tx)
    log.add(f"all colluders positively attested target {target[:16]}…")
    await asyncio.sleep(settle)
    await mine_scheduled(nodes, extra_txs=pending, settle=settle)

    from reputation.tally import positive_attesters  # local: keep module surface small
    attesters = positive_attesters(nodes[0].blockchain, target, root, DEMO_DOMAIN, target_hash)
    weights = {a: nodes[0].reputation.weight(a, DEMO_DOMAIN) for a in attesters}
    raw = weighted_support(nodes[0].blockchain, nodes[0].reputation, target, root,
                           DEMO_DOMAIN, target_hash)
    capped = capped_support(nodes[0].blockchain, attesters, weights)
    clusters = attester_clusters(nodes[0].blockchain, attesters)
    log.add(f"raw weighted support {raw}; clusters {[len(c) for c in clusters]}; "
            f"cap clamps the colluding cluster → counted support {capped}")

    cert = certify(
        nodes[0].blockchain, nodes[0].reputation, target, root,
        DEMO_DOMAIN, target_hash, threshold=DEMO_THRESHOLD,
    )
    log.add(f"certificate issued: {cert is not None} (expected False: capped support "
            f"{capped} < threshold {DEMO_THRESHOLD})")
    return _result("collusion", log, net, certificate_issued=cert is not None,
                   extra={"raw_support": raw, "capped_support": capped, "domain": DEMO_DOMAIN})


def _isolate(net: ScenarioNet, down_index: int) -> None:
    """Take one node offline by removing it from the peer mesh (both directions)."""
    down = net.nodes[down_index]
    down_bin = down.my_peer.public_key.key_to_bin()
    for j, node in enumerate(net.nodes):
        if j == down_index:
            continue
        for peer in list(node.get_peers()):
            if peer.public_key.key_to_bin() == down_bin:
                node.network.remove_peer(peer)
    for peer in list(down.get_peers()):
        down.network.remove_peer(peer)


async def scenario_view_change(net: ScenarioNet) -> dict:
    """One validator goes offline; a view-change rotates the proposer and the block still finalizes.

    The validator the schedule assigns to the next height (view 0) is taken offline
    (removed from the mesh, so it neither proposes nor commits). The remaining
    validators vote to rotate to view 1; the view-1 scheduled proposer produces a
    block carrying that quorum of view-change votes as justification, and it reaches
    finality on the remaining quorum alone. The offline node is then re-introduced
    and fork-syncs back, so the network heals.
    """
    log = _StepLog()
    nodes = net.nodes
    n = len(nodes)
    settle = _settle_for(n)
    root = RUBRIC.root()
    height = len(nodes[0].blockchain.blocks)
    validators = nodes[0].blockchain.validator_set(height)

    down_pub = nodes[0].blockchain.proposer_for(height, 0)
    new_pub = nodes[0].blockchain.proposer_for(height, 1)
    down_index = next(i for i, node in enumerate(nodes) if node.validator_pubkey == down_pub)
    new_index = next(i for i, node in enumerate(nodes) if node.validator_pubkey == new_pub)
    log.add(f"at height {height} the view-0 proposer is node {down_index} ({down_pub[:12]}…)")

    # Give the view-1 proposer some content so the produced block is not empty.
    nodes[new_index].blockchain.add_transaction(_random_submission(root))

    _isolate(net, down_index)
    log.add(f"node {down_index} is OFFLINE (removed from the mesh) — it will neither propose nor commit")

    voters = [i for i in range(n) if i != down_index and nodes[i].validator_pubkey in validators]
    for i in voters:
        nodes[i].request_view_change(height)
    log.add(f"{len(voters)} live validators broadcast view-change votes to advance to view 1 "
            f"(quorum {quorum_size(len(validators))})")
    # The view-change round is a vote-flood + a produce-and-commit round, so give it
    # extra time on top of the size-scaled window.
    await asyncio.sleep(settle * 1.6)

    live = nodes[new_index]
    produced = live.blockchain.blocks[height] if len(live.blockchain.blocks) > height else None
    if produced is None:
        log.add("UNEXPECTED: no block was produced after the view change")
    else:
        commits = len(produced.commit_signers() & validators)
        finalized = live.blockchain.is_final(produced)
        log.add(f"node {new_index} ({new_pub[:12]}…) proposed block {height} at view {produced.view}, "
                f"justified by the view-change quorum")
        log.add(f"block {height} finalized={finalized} with {commits}/{len(validators)} validator "
                f"commits (quorum {quorum_size(len(validators))}) — the offline node did not commit")

    extra = {
        "node_down": {"index": down_index, "pubkey": down_pub},
        "new_proposer": {"index": new_index, "pubkey": new_pub},
    }
    if produced is not None:
        extra.update({
            "view": produced.view,
            "commits": len(produced.commit_signers() & validators),
            "quorum": quorum_size(len(validators)),
            "validators": len(validators),
        })

    # Heal: re-introduce the offline node and re-advertise the tip so it fork-syncs.
    introduce(net.instances, net.base_udp_port)
    await asyncio.sleep(settle * 0.7)
    live.broadcast_block(live.blockchain.last_block)
    await asyncio.sleep(settle)
    log.add(f"node {down_index} re-introduced and fork-synced back to height {len(live.blockchain.blocks)}")

    return _result("view_change", log, net, ref_node=live, extra=extra)


# Name -> (human description, coroutine). One registry the HTTP bridge lists and runs.
SCENARIOS = {
    "sunny": (
        "Honest attestations meet the weighted threshold; a certificate is issued and finalized by quorum.",
        scenario_sunny,
    ),
    "rainy": (
        "Attestations cite a forged rubric root, so the aggregator counts none and no certificate issues.",
        scenario_rainy,
    ),
    "slash": (
        "An attester equivocates; an evidence-based, validator-quorum slash burns the bond and support falls below threshold.",
        scenario_slash,
    ),
    "view_change": (
        "The scheduled proposer goes offline; a view-change rotates the proposer and the block still finalizes with the remaining quorum.",
        scenario_view_change,
    ),
    "collusion": (
        "A cross-attesting cluster over-concentrates support; the ALPHA cap clamps it below threshold and rejects certification.",
        scenario_collusion,
    ),
}


class ScenarioRegistry:
    """Binds the scenario coroutines to one live network for the HTTP bridge.

    ``list`` powers ``GET /api/scenarios``; ``run`` powers
    ``POST /api/scenario/{name}``. A lock serializes runs so two concurrent POSTs
    can never interleave their edits to the one shared chain.
    """

    def __init__(self, net: ScenarioNet) -> None:
        self.net = net
        self._lock = asyncio.Lock()

    def list(self) -> list[dict]:
        return [{"name": name, "description": desc} for name, (desc, _fn) in SCENARIOS.items()]

    async def run(self, name: str) -> dict | None:
        entry = SCENARIOS.get(name)
        if entry is None:
            return None
        async with self._lock:
            return await entry[1](self.net)
