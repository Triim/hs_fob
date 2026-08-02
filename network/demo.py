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
  Then one of them (carol) **equivocates** — signs two contradictory verdicts on
  the same claim. A *slash* is committed against her, but not by one authority's
  fiat: it carries those two conflicting attestations as **evidence** and is
  approved by a **quorum of the validators** (the authority, alice, bob). Consensus
  re-verifies the evidence and quorum from the chain prefix before it debits her.
  Reputation is re-derived from the now-longer chain — nothing is mutated by hand —
  so the slashed attester's weight drops to zero (capped at MAX_SLASH), the
  weighted support falls below the threshold, and the certificate no longer issues.

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
from attestation.submission import hash_artifact, make_submission
from blockchain.blockchain import Blockchain
from crypto.keys import keypair_from_seed
from network.community import AttestationCommunity
from reputation.derive import REVIEW_REWARD
from reputation.genesis import CONSENSUS_DOMAIN, GENESIS_AUTHORITY_KEYS
from reputation.slashing import approve_slash, make_slash
from reputation.tally import weighted_support

BASE_PORT = 9090
# Four nodes, one per validator in DEMO_GENESIS: the three attesters plus the
# genesis authority. Running *every* validator as a node is what keeps the live
# happy path at view 0 — the deterministic proposer schedule
# (:func:`blockchain.blockchain.scheduled_proposer`) rotates the leader across the
# whole validator set, so if any scheduled proposer had no node the chain would
# have to view-change to make progress. With all four present, the scheduled
# proposer for every height is a live node and no rotation is needed.
NODE_COUNT = 4

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

# The demo spans THREE competence domains, not one, to make the central point that
# reputation is domain-scoped rather than global: an expert credentialed in one
# domain carries no weight in another. ``DEMO_DOMAIN`` is the primary domain the
# scripted scenarios certify in (kept first); the full set is surfaced to the UI via
# ``GET /api/domains`` so selectors are populated from the backend, not hardcoded.
DEMO_DOMAINS = ["computer-science", "data-science", "instructional-design"]
DEMO_DOMAIN = DEMO_DOMAINS[0]
DEMO_THRESHOLD = 250

# Per-expert competence across the three demo domains — deliberately UNEVEN so the
# reputation matrix shows domain-scoped weight rather than one global number. Every
# attester keeps full weight in DEMO_DOMAIN (computer-science) so the scripted
# scenarios, which certify in that domain, still reach the 250 threshold (3×100=300);
# the other two domains diverge sharply:
#   * alice — strong in data-science, ZERO in instructional-design;
#   * bob   — the mirror image: strong in instructional-design, ZERO in data-science;
#   * carol — cross-domain, partial weight in both.
# So attesting in a domain where you hold zero weight visibly contributes nothing.
DEMO_EXPERT_WEIGHTS = {
    "alice": {"computer-science": 100, "data-science": 100},
    "bob": {"computer-science": 100, "instructional-design": 100},
    "carol": {"computer-science": 100, "data-science": 50, "instructional-design": 50},
}

# Every attestation in the demo bonds this many tokens. Chosen legible against the
# endowment below (100) and REVIEW_REWARD (5), so the console can show a bond of
# 10 leave free balance, come back on a certificate (+5 reward), or be burned on a
# slash.
DEMO_STAKE = 10

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
# canonical GENESIS_REPUTATION. It declares the demo's founding participants and
# is where the THREE ROLES are visibly separate:
#   * the real genesis authority key, with CONSENSUS_DOMAIN weight, so it is a
#     founding validator; and
#   * the three attesters (keyed by their real public keys), each carrying BOTH
#     CONSENSUS_DOMAIN weight (they are the founding validators the nodes run as —
#     their consensus authority) AND DEMO_DOMAIN weight 100 (their competence /
#     attester credibility, used in weighted support).
# Keeping the two weights on separate domains is the point: consensus authority
# (produce/commit) is the CONSENSUS_DOMAIN weight; competence is the DEMO_DOMAIN
# weight. A certificate would raise competence without ever touching consensus
# authority — only genesis or an approved promotion grants that.
# Certification decides by DEMO_DOMAIN weight: three honest attesters contribute
# 300 (over the 250 threshold); a single slash (−100) drops the total to 200,
# below it. Reputation is derived from each node's chain seeded by THIS anchor —
# no hand-built registry — read via ``overlay.reputation``.
DEMO_GENESIS = {
    _AUTHORITY_PUBKEY: {CONSENSUS_DOMAIN: 100},
    **{
        pubkey: {CONSENSUS_DOMAIN: 100, **DEMO_EXPERT_WEIGHTS[name]}
        for name, (_priv, pubkey) in _ATTESTER_KEYS.items()
    },
}

# The demo's OWN token-endowment anchor — the economic counterpart of DEMO_GENESIS,
# injected into every node the same way. It declares each attester's *starting
# token balance* (their bonding capacity), kept small (100) so the console shows a
# real, finite balance a 10-token bond visibly moves — locked on attestation,
# released + rewarded on a certificate, burned on a slash. The authority is endowed
# too for completeness (it produces blocks, it does not attest). This is the
# concrete "genesis endows initial balances"; balances are then a pure function of
# each node's chain (read via ``overlay.balances``), never a hand-built ledger.
DEMO_BALANCES = {
    _AUTHORITY_PUBKEY: 100,
    **{pubkey: 100 for _priv, pubkey in _ATTESTER_KEYS.values()},
}


def _submission_hash(subject, rubric_root, domain=DEMO_DOMAIN):
    """The ``submission_tx_hash`` every review of one piece of work binds to.

    Builds the submission transaction the reviews cover and returns its content
    hash. The submission itself need not be mined for the binding to be meaningful
    — the hash is a stable identity that every honest node derives identically — so
    the demo just computes it and threads it through the attestations and the
    certificate that decide *that* submission.
    """
    submission = make_submission(
        subject=subject,
        domain=domain,
        rubric_root=rubric_root,
        title="Demo submission",
        artifact_hash=hash_artifact(b"demo artifact bytes for " + subject.encode()),
    )
    return submission.hash


def _signed_attestation(
    keypair, subject, rubric_root, item_index, submission_tx_hash, verdict=True, stake=DEMO_STAKE
):
    """Build an attestation whose sender is the attester's key, then sign it.

    Attestations are participant transactions, so the chain now requires each to
    be signed by its author (``sender`` = the attester's public key). Each review
    also binds to the exact submission it covers via ``submission_tx_hash``.
    """
    private_key, public_key = keypair
    tx = make_attestation(
        public_key, subject, rubric_root, item_index, verdict, stake, submission_tx_hash
    )
    tx.sign(private_key)
    return tx


def _rule(title: str) -> None:
    print("\n" + "=" * 68)
    print(title)
    print("=" * 68)


async def start_nodes() -> list[IPv8]:
    """Launch NODE_COUNT IPv8 instances, each with its own chain and key file."""
    # Each node gets a DISTINCT validator key: the three attesters (real
    # reproducible keypairs, each an authority in DEMO_GENESIS) plus the genesis
    # authority as the fourth. This is what lets the live network reach quorum AND
    # keep the proposer schedule on live nodes: the validator set is {genesis
    # authority} ∪ {alice, bob, carol} (N=4, quorum floor(2·4/3)+1 = 3), and every
    # one of those four now runs as a node, so whichever validator the schedule
    # assigns to a height is present to propose — the live happy path never needs a
    # view-change. Their commit votes accumulate toward finality (up to 4/4).
    node_validator_privs = [
        *(priv for priv, _pub in _ATTESTER_KEYS.values()),
        _AUTHORITY_PRIVATE,
    ]
    instances: list[IPv8] = []
    for i in range(NODE_COUNT):
        # Every node validates against the SAME demo anchor — shared network
        # configuration, exactly like the genesis block. A node given a different
        # anchor would compute different authorities and diverge.
        chain = Blockchain(genesis=DEMO_GENESIS, balances=DEMO_BALANCES)
        builder = ConfigBuilder().clear_keys().clear_overlays()
        builder.set_port(BASE_PORT + i)
        # Distinct persisted EC key per node, exactly as the overlay tutorial does.
        builder.add_key("my peer", "medium", f"ec{i + 1}.pem")
        # No walkers/bootstrappers: we introduce peers manually below, so the
        # demo is deterministic and offline. The live chain and this node's
        # validator/producer key are injected here.
        builder.add_overlay(
            "CompetenceAttestationCommunity",
            "my peer",
            [],
            [],
            {"blockchain": chain, "producer_key": node_validator_privs[i]},
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


def scheduled_proposer_node(nodes: list[AttestationCommunity]) -> AttestationCommunity:
    """The node whose validator the schedule assigns to propose the next block.

    Once the scheduled-proposer rule is enforced, only that node can produce a
    valid block for the current height at view 0, so the demo routes each block to
    it rather than always mining on node 0 (see
    :func:`blockchain.blockchain.scheduled_proposer`). The schedule is chain-derived
    and identical on every node, so reading it off node 0 is authoritative.
    """
    height = len(nodes[0].blockchain.blocks)
    proposer = nodes[0].blockchain.proposer_for(height)
    return next(node for node in nodes if node.validator_pubkey == proposer)


async def mine_scheduled(
    nodes: list[AttestationCommunity], extra_txs=(), settle: float = 0.6
):
    """Have the scheduled proposer mine the next block (view 0) and gossip it.

    Any ``extra_txs`` that only one node holds (a certificate or slash, which are
    not gossiped as participant transactions) are pooled onto that proposer first —
    guarded against re-pooling anything it already has — so the block it produces
    carries them. Returns ``(proposer_node, block)``.
    """
    node = scheduled_proposer_node(nodes)
    for tx in extra_txs:
        if not node._already_seen(tx):
            node.blockchain.add_transaction(tx)
    block = node.mine_and_broadcast_block()
    await asyncio.sleep(settle)
    return node, block


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


def show_balances(node: AttestationCommunity, label: str) -> None:
    """Print each attester's token balance (total / locked / free) on ``node``.

    Balances are read from ``node.balances`` — a pure function of the node's chain,
    never a hand-built ledger — so this is exactly what consensus derives. It makes
    the stake-bond lifecycle visible: a bond locked on attestation, released +
    rewarded on a certificate, or burned on a slash.
    """
    ledger = node.balances
    print(f"  {label}")
    for name, (_priv, pubkey) in _ATTESTER_KEYS.items():
        print(
            f"    {name:>6}: total={ledger.total(pubkey):>4}  "
            f"locked={ledger.locked(pubkey):>4}  free={ledger.free(pubkey):>4}"
        )


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
    submission_tx_hash = _submission_hash(SUBJECT, rubric_root)
    print(f"Published rubric root: {rubric_root[:16]}…  ({len(RUBRIC.claims)} items)")
    print(f"Subject under review : {SUBJECT}")
    print(f"Submission under review: {submission_tx_hash[:16]}…")

    # The first three nodes host a distinct attester who signs off one rubric item;
    # the fourth node (the genesis authority) only produces/commits, it does not attest.
    attesters = list(_ATTESTER_KEYS.items())
    for i, (name, keypair) in enumerate(attesters):
        node = nodes[i]
        tx = _signed_attestation(keypair, SUBJECT, rubric_root, i, submission_tx_hash)
        fanout = node.broadcast_attestation(tx)
        # The attester's own node also pools its attestation locally.
        node.blockchain.add_transaction(tx)
        print(f"Step {i + 1}: {name} on node {i} attested item {i} "
              f"(verdict=True) -> broadcast to {fanout} peers")
    await asyncio.sleep(0.6)  # let the gossip land

    pooled = [len(n.blockchain.mempool) for n in nodes]
    print(f"Step 4: attestations propagated — mempool sizes per node: {pooled}")

    proposer, _ = await mine_scheduled(nodes)
    print(f"Step 5: the scheduled proposer ({proposer.validator_pubkey[:12]}…) "
          "mined the pooled attestations into a block and gossiped it")
    show_balances(nodes[0], f"balances after mining (each bonded {DEMO_STAKE} to attest):")

    print("Step 6: node 0 runs the aggregator against the published rubric root")
    cert = certify(
        nodes[0].blockchain, nodes[0].reputation, SUBJECT, rubric_root,
        DEMO_DOMAIN, submission_tx_hash, threshold=DEMO_THRESHOLD,
    )
    if cert is None:
        print("  UNEXPECTED: threshold not met — no certificate")
        return
    print(f"  threshold met by {cert.payload['granted_by']}")
    print(f"  certificate issued for subject {cert.payload['subject']}")

    print("Step 7: the certificate is mined into a block and gossiped to all nodes")
    await mine_scheduled(nodes, extra_txs=[cert])

    show_balances(
        nodes[0],
        f"balances after certificate (bonds released + {REVIEW_REWARD} reward each):",
    )

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
    submission_tx_hash = _submission_hash(subject, tampered_root)
    print(f"Published rubric root: {real_root[:16]}…")
    print(f"Forged rubric root   : {tampered_root[:16]}…  (never published)")

    attesters = list(_ATTESTER_KEYS.items())
    for i, (name, keypair) in enumerate(attesters):
        node = nodes[i]
        # The tamper is in the referenced root; the attestation is still validly
        # signed by its author (an honest node just won't recognise the root).
        tx = _signed_attestation(keypair, subject, tampered_root, i, submission_tx_hash)
        node.broadcast_attestation(tx)
        node.blockchain.add_transaction(tx)
        # The receiving side accepts well-formed attestations, but an honest
        # node checks the referenced root against the rubric it published.
        recognised = tx.payload["rubric_root"] == real_root
        print(f"Step {i + 1}: {name} attested against a forged root "
              f"-> recognised by honest nodes: {recognised}")
    await asyncio.sleep(0.6)

    print("Step 4: the scheduled proposer mines whatever propagated, then the aggregator runs")
    await mine_scheduled(nodes)

    # The aggregator only pools votes bound to the *published* root, so the
    # forged votes never count toward this subject's certification.
    cert = certify(
        nodes[0].blockchain, nodes[0].reputation, subject, real_root,
        DEMO_DOMAIN, submission_tx_hash, threshold=DEMO_THRESHOLD,
    )
    print(f"  certify() against the published root -> {cert!r}")
    print(f"  certificate issued: {cert is not None}  (expected: False)")


async def slashing_day(nodes: list[AttestationCommunity]) -> None:
    _rule("SLASHING DAY — evidence-based, quorum-approved slashing")
    rubric_root = RUBRIC.root()
    subject = "536c617368656453756266"  # yet another subject, independent state
    submission_tx_hash = _submission_hash(subject, rubric_root)
    attesters = list(_ATTESTER_KEYS.items())
    print(f"Published rubric root: {rubric_root[:16]}…")
    print(f"Subject under review : {subject}")

    # 1. All three attest honestly against the published rubric. We keep carol's
    #    honest attestation object — it is one half of the evidence below.
    honest: dict[str, object] = {}
    for i, (name, keypair) in enumerate(attesters):
        node = nodes[i]
        tx = _signed_attestation(keypair, subject, rubric_root, i, submission_tx_hash)
        honest[name] = tx
        node.broadcast_attestation(tx)
        node.blockchain.add_transaction(tx)
        print(f"Step {i + 1}: {name} attested item {i} (verdict=True)")

    # 1b. carol then EQUIVOCATES: she signs the *opposite* verdict on the SAME
    #     claim (same subject/rubric/item). Two contradictory signed verdicts are
    #     the objectively provable fault a slash punishes — this is the evidence.
    carol_priv, carol_pubkey = _ATTESTER_KEYS["carol"]
    carol_item = 2  # the item carol honestly attested (loop index 2)
    carol_conflict = make_attestation(
        carol_pubkey, subject, rubric_root, carol_item, False, DEMO_STAKE,
        submission_tx_hash, DEMO_DOMAIN,
    )
    carol_conflict.sign(carol_priv)
    nodes[2].broadcast_attestation(carol_conflict)
    print("Step 4: carol EQUIVOCATED — signed verdict=False on the same item 2 "
          "(verdict=True already on chain)")
    await asyncio.sleep(0.6)
    # The scheduled proposer mines the honest attestations + carol's conflict. The
    # conflict was gossiped to everyone, so it is passed as a safety extra_tx too
    # (mine_scheduled skips it if the proposer already pooled it).
    await mine_scheduled(nodes, extra_txs=[carol_conflict])

    # 2. Before any slash, support is 3 × 100 = 300 ≥ 250, so a certificate would issue.
    support_before = weighted_support(
        nodes[0].blockchain, nodes[0].reputation, subject, rubric_root, DEMO_DOMAIN,
        submission_tx_hash,
    )
    cert_before = certify(
        nodes[0].blockchain, nodes[0].reputation, subject, rubric_root,
        DEMO_DOMAIN, submission_tx_hash, threshold=DEMO_THRESHOLD,
    )
    print(f"Step 5: weighted support before slash = {support_before} "
          f"(threshold {DEMO_THRESHOLD}) -> certificate would issue: "
          f"{cert_before is not None}")
    show_balances(nodes[0], "balances before slash (carol's two bonds still locked):")

    # 3. A slash is now a *protocol-validated* transaction, not one authority's
    #    fiat. It references the two conflicting attestations as EVIDENCE, and a
    #    QUORUM of the current validators must sign it. The validator set here is
    #    {genesis-authority, alice, bob, carol} (N=4, quorum=3); three validators
    #    (the authority, alice, bob — everyone but the offender) approve. Consensus
    #    re-verifies the evidence and the quorum from the chain prefix before it
    #    debits anyone — no registry is mutated by hand.
    evidence = sorted([honest["carol"].hash, carol_conflict.hash])
    amount = 100
    approver_keys = {
        "genesis-authority": _AUTHORITY_PRIVATE,
        "alice": _ATTESTER_KEYS["alice"][0],
        "bob": _ATTESTER_KEYS["bob"][0],
    }
    approvals = dict(
        approve_slash(priv, carol_pubkey, DEMO_DOMAIN, amount, evidence)
        for priv in approver_keys.values()
    )
    slash = make_slash(
        offender=carol_pubkey,
        domain=DEMO_DOMAIN,
        evidence=evidence,
        approvals=approvals,
        amount=amount,
    )
    await mine_scheduled(nodes, extra_txs=[slash])
    print(f"Step 6: quorum-approved slash of carol (−{amount} in 'general') — "
          f"evidence={[h[:10] + '…' for h in evidence]}, "
          f"approvers={sorted(approver_keys)} — mined into a block")

    # 4. Re-derived from the now-longer chain, carol's weight is 0, so support is
    #    2 × 100 = 200 < 250 — the certificate no longer issues.
    support_after = weighted_support(
        nodes[0].blockchain, nodes[0].reputation, subject, rubric_root, DEMO_DOMAIN,
        submission_tx_hash,
    )
    cert_after = certify(
        nodes[0].blockchain, nodes[0].reputation, subject, rubric_root,
        DEMO_DOMAIN, submission_tx_hash, threshold=DEMO_THRESHOLD,
    )
    print(f"Step 7: weighted support after slash = {support_after} "
          f"(threshold {DEMO_THRESHOLD}) -> certificate issued: "
          f"{cert_after is not None}  (expected: False)")
    show_balances(
        nodes[0],
        f"balances after slash (carol's {2 * DEMO_STAKE} in bonds BURNED, not just reputation):",
    )


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
