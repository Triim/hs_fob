# GradED — Decentralized Competence Attestation (CS414)

A minimal, readable blockchain implemented **from scratch in pure Python**,
extended with a competence-attestation application layer, a peer-to-peer
networking layer (IPv8), and a browser console. Peers agree on an ordered chain;
everything else — reputation, token balances, the validator set, certificate
status — is **derived state**, a pure function of that agreed chain, so every
node computes it identically with no extra consensus.

The chain core stays fully generic: attestations, submissions, certificates,
promotions, and slashes all ride inside an ordinary `Transaction` payload, so
`Block`, `MerkleTree`, and `Blockchain` are never modified by the application.

## What the system does

- **Own blockchain, no proof-of-work.** A `Block` header commits to a Merkle root
  over its transactions; the chain is an ordered, hash-linked, tamper-evident
  list anchored at a fixed genesis block. There is no mining search — block
  production is a signature.
- **Signed transactions.** Participant-authored transactions (`attestation`,
  `submission`) must each carry a valid author signature: the `sender` is the
  author's Ed25519 public key and the signature must verify, or the whole chain
  is invalid. Protocol-validated transactions (`certificate`, `promotion`,
  `slash`, and anything in genesis) are not individually authored — their
  integrity comes from the block producer's signature plus deterministic
  re-derivability from chain state (see `blockchain/tx_signing.py`).
- **PoA-proposed + BFT-quorum finality.** Blocks are *proposed* under
  **Proof-of-Authority**: a block is valid only if its `producer_signature`
  verifies and that producer is the scheduled authority under the reputation
  derived from the chain **prefix before that block** (which breaks the
  circularity). A block becomes **final** only once a **BFT quorum** of
  validators — `floor(2n/3) + 1` — have gossiped commit signatures for it.
  Finalized blocks are irreversible: fork choice prefers the chain with more
  finalized blocks rather than merely the longest chain, and two conflicting
  quorums must overlap in an honest validator, so two conflicting blocks can
  never both finalize (`blockchain/blockchain.py`, `network/community.py`).
- **View-change for liveness.** The proposer for each height is fixed by a
  deterministic schedule (`sorted validators`, indexed by `(height + view) %
  n`). If the scheduled proposer stalls, validators sign and gossip
  **view-change votes**; once a quorum justifies the next view, the block records
  its `view > 0` and `is_valid_chain` accepts it only when that view is both the
  scheduled one and quorum-justified. A stalled or offline proposer is thus
  rotated out automatically without breaking safety
  (`blockchain/blockchain.py`, `network/community.py`).
- **Endogenous validator promotion.** Consensus authority is the genesis
  validator set **plus** anyone added by an on-chain `promotion`. A promotion is
  valid only when the candidate already holds competence weight ≥ threshold in
  some domain **and** a quorum of current validators signed off, subject to
  rate/fraction caps so a fresh cohort can't be minted fast enough to seize a
  majority. Competence never auto-grants authority — promotion is a deliberate,
  quorum-gated conversion (`blockchain/promotion.py`).
- **Chain-derived reputation.** Replaying the chain from `GENESIS_REPUTATION`
  credits each certificate's subject and debits proven, quorum-approved slashes,
  yielding a per-(pubkey, domain) weight table. Attester credibility, competence
  reputation, and consensus authority are kept as three distinct roles
  (`reputation/derive.py`, `reputation/tally.py`).
- **Chain-derived token balances.** A separate `BalanceLedger` tracks each
  participant's `total` / `locked` / `free` tokens. An attestation locks a real
  token **bond**; a review that holds up releases the bond plus a reward; a slash
  **burns** it. Stake is skin-in-the-game, never a vote — it never buys influence
  (`reputation/balances.py`).
- **Evidence + quorum slashing.** A `slash` is valid only if it references two of
  the offender's own signed, genuinely conflicting attestations (opposite
  verdicts on the same claim) that exist in the chain prefix, **and** carries a
  quorum of validator approvals. Consensus re-verifies the evidence and quorum
  deterministically before any weight is debited; a valid slash **burns both**
  the offender's staked bond and their competence reputation, with the reputation
  debit capped at `MAX_SLASH` (`reputation/slashing.py`).
- **Submissions bound to a specific work.** A `submission` is a specialist's
  signed declaration of a piece of work for review; only the artifact's SHA-256
  hash and light metadata go on-chain — the file bytes never do. Every review
  carries a `submission_tx_hash` that binds it to **one specific submission**, and
  a certificate references the same submission, so attestations and certificates
  can never be replayed against a different piece of work
  (`attestation/submission.py`, `attestation/attestation.py`).
- **Abstain as a first-class verdict.** A review may pass, fail, or **abstain**
  (`verdict = None`). An abstain is weight-neutral (it counts toward neither
  support nor opposition), bonds nothing (its stake is forced to `0`), and can
  never be part of the conflicting evidence a slash needs — abstaining is honest,
  not an offence (`attestation/attestation.py`).
- **Certificate lifecycle.** Certificates are **protocol-issued** by the
  aggregator once weighted support over *distinct* attesters clears the
  threshold, then **re-derived and verified from the chain prefix** on replay:
  a certificate that is unearned (support below threshold) or a duplicate re-issue
  is rejected, so `is_valid_chain` fails on a chain that contains one. A live,
  chain-derived status tracks each issued certificate: it becomes
  **contested** when one of its contributing attesters is later slashed for the
  very submission it certifies (`attestation/aggregator.py`).
- **Collusion cluster cap on certification.** Support is counted through a cap
  (`reputation.tally.capped_support`): no single cross-attesting *cluster* —
  identified as a mutual-cross-attestation component, derivable from the chain —
  may contribute more than a fraction `ALPHA` of the counted total. A cartel that
  attests for each other therefore cannot manufacture a certificate. The same cap
  is applied identically by `certify` and by `is_valid_chain`
  (`attestation/aggregator.py`, `reputation/tally.py`).
- **HTTP bridge + WebSocket.** Each live node exposes its real objects over HTTP:
  read GETs (`/api/node`, `/api/chain`, `/api/mempool`, `/api/reputation`,
  `/api/balances`, `/api/peers`), writes (`POST /api/tx`, `POST /api/mine`), and a
  `/ws` WebSocket that pushes live state. Writes follow the real trust model: the
  **client** signs, the node only validates and relays — it never holds a
  participant's private key (`network/http_bridge.py`).
- **Vanilla-JS frontend.** A dependency-free, tabbed browser console (`frontend/`)
  that generates keypairs and signs transactions locally with a vendored, offline
  Ed25519 library (no CDN at runtime), then talks to a node over HTTP/WebSocket.

## Layout

- `blockchain/` — generic core (standard library only):
  - `transaction.py` — content-addressed `Transaction` (generic dict payload).
  - `merkle.py` — `MerkleTree` with inclusion proofs and `verify`.
  - `block.py` — `Block` (header hash over the Merkle root) + producer signature,
    commit signatures, and view-change signing bytes.
  - `blockchain.py` — `Blockchain`: genesis, mempool, PoA validity, BFT finality,
    the deterministic proposer schedule / view-change, and finality-based fork
    choice.
  - `tx_signing.py` — which transaction types require an author signature.
  - `promotion.py` — the `promotion` transaction (endogenous validator growth).
  - `__main__.py` — single-process end-to-end core demo.
- `attestation/` — application layer, built on `Transaction.payload`:
  - `attestation.py` — `make_attestation` / `is_attestation` (pass/fail/abstain,
    submission-bound).
  - `submission.py` — `make_submission` / `hash_artifact` (hash-only on-chain).
  - `rubric.py` — `Rubric`: ordered claims committed under a Merkle root.
  - `aggregator.py` — `certify`: capped weighted support over distinct attesters,
    certificate issuance, prefix re-derivation, and contested-status derivation.
- `reputation/` — derived state (standard library only):
  - `genesis.py` — `GENESIS_REPUTATION` / balances: the axiomatic trust anchor.
  - `derive.py` — reputation and balances as pure functions of the chain.
  - `tally.py` — weighted attester support and the collusion cluster cap.
  - `registry.py` / `balances.py` — the weight and token tables (mutated only
    during derivation).
  - `slashing.py` — evidence-based, quorum-approved slash validation.
- `network/` — networking + UI-facing layers:
  - `wire.py` — JSON serialization bridge over `to_dict` (the core/network seam).
  - `community.py` — `AttestationCommunity` (IPv8): gossips transactions, blocks,
    the commit round that drives BFT finality, and view-change votes.
  - `http_bridge.py` — read/write HTTP + `/ws` WebSocket over the live node.
  - `demo.py` — multi-node scripted demo (sunny / rainy / slashing scenarios).
  - `scenarios.py` — on-demand scenario registry driven by the live nodes.
  - `run_nodes.py` — live HTTP-pollable nodes for the browser console.
- `frontend/` — vanilla-JS console (`index.html`, `app.js`, `style.css`, vendored
  `noble-ed25519.js`).
- `tests/` — unit and integration tests (stdlib `unittest`).

## Requirements

Python 3.12+ and [`uv`](https://docs.astral.sh/uv/). The networking layer uses
`pyipv8`; run everything through `uv`, which manages the interpreter and virtual
environment:

```bash
uv sync            # creates .venv and installs dependencies from pyproject/uv.lock
```

The `blockchain/`, `attestation/`, and `reputation/` layers are standard-library
only; only the `network/` layer needs `pyipv8`.

## Run with Docker

The fastest way to see the whole demo — no local Python or `uv` needed, just
Docker with Compose:

```bash
docker compose up
```

That builds one image and starts two services:

- **nodes** — the 7-validator live cluster (quorum 5), publishing each node's
  HTTP bridge on the host at `http://127.0.0.1:8080` … `http://127.0.0.1:8086`.
- **frontend** — a static server for `frontend/` at **http://127.0.0.1:8090**.

**Open the browser console at http://127.0.0.1:8090.** The console selector
defaults to node 0 (`http://127.0.0.1:8080`), where the scenario triggers live;
pick any node `i` (`http://127.0.0.1:808i`) to watch the same chain from another
validator. Generate a keypair, submit and attest work, or fire a scenario, and
watch the chain, reputation, and balances update live over the WebSocket.

**Reach a node's API directly**, e.g.:

```bash
curl http://127.0.0.1:8080/api/node       # node identity + consensus params
curl http://127.0.0.1:8080/api/chain      # the current chain
curl http://127.0.0.1:8080/api/scenarios  # scenario triggers (node 0)
```

The browser talks to the bridges directly on `127.0.0.1:8080-8086`, so both
services simply publish their ports — no inter-container networking is involved.
IPv8 EC keypairs are generated fresh **inside** the container on first run (never
copied from the host, never committed). Stop with `Ctrl-C`, or tear down with
`docker compose down`.

## Running the tests

```bash
uv run python -m unittest discover -s tests -v
```

The IPv8 integration tests use IPv8's in-memory `MockIPv8` / `TestBase` harness —
real serialized packets between simulated nodes, no network required.

## Running the core demo

```bash
uv run python -m blockchain
```

Builds a chain, adds generic-payload transactions, produces signed blocks, and
reports whether the chain validates.

## Running the multi-node attestation demo

```bash
uv run python -m network.demo
```

Starts real IPv8 nodes in one process (each with its own EC key file, generated
locally and gitignored), introduces them over UDP loopback, and runs scripted
scenarios with step-by-step output: a **sunny day** (honest attestations reach a
certificate), a **rainy day** (forged rubric root → no certificate), and a
**slashing day** (an equivocating attester is slashed on evidence + quorum, and
their certificate no longer issues).

## Running the live nodes + browser console

1. Start the live, HTTP-pollable nodes. They start **idle** (genesis only) and
   expose on-demand scenario triggers on node 0 that drive the live network:

   ```bash
   uv run python -m network.run_nodes                 # 4 validators, HTTP on 8080…8083
   ```

   Pass `--nodes` to run a larger validator set (the BFT minimum is 4 so the
   quorum can tolerate one faulty node), and `--http-port` / `--udp-port` to move
   the base ports:

   ```bash
   uv run python -m network.run_nodes --nodes 7                 # 7 validators (quorum 5)
   uv run python -m network.run_nodes --http-port 9000 --udp-port 9500
   ```

   Node `i` serves its read/write HTTP bridge on `http_base + i` and listens on
   `udp_base + i`. The HTTP base port also honours `$HS_FOB_HTTP_PORT`:

   ```bash
   HS_FOB_HTTP_PORT=9000 uv run python -m network.run_nodes
   ```

   Node 0 exposes the scenario endpoints — `GET /api/scenarios` and `POST
   /api/scenario/{sunny,rainy,slash,view_change,collusion}` — each of which runs
   one scripted story against the live network and returns a step-by-step JSON
   log for the UI.

2. Open the console. CORS is permissive, so the simplest path is to open the file
   directly:

   ```bash
   open frontend/index.html        # macOS; or just open the file in a browser
   ```

   or serve it statically if your browser restricts `file://` fetches:

   ```bash
   uv run python -m http.server -d frontend 5173    # then visit http://127.0.0.1:5173
   ```

   Generate a keypair, submit work, attest, produce blocks, trigger scenarios, and
   watch the chain, reputation, and balances update live over the WebSocket. Keys
   are generated and transactions are signed **in the browser** — the node only
   validates and relays.

## Known limitations

- **Synchronous commit collection.** Finality collects commit signatures over the
  gossip layer in a single round; it does not implement the full PBFT lock/
  view-change rules or explicit network-partition handling. View-change rotates a
  stalled proposer, but partition recovery under adversarial timing is out of
  scope.
- **Genesis validator set is an axiom.** The founding validators (and genesis
  reputation and balances) are declared constants, not themselves established
  on-chain — the unavoidable external trust anchor. Everything after genesis is
  chain-derived.
- **Sybil resistance needs external proof-of-personhood.** Nothing in the
  protocol stops one human from creating many participant identities; keeping
  participation one-person-one-identity requires an external proof-of-personhood
  layer that is assumed, not implemented.
- **No on-chain oracle for attestation quality.** The protocol can prove and slash
  an *objective* violation (equivocation — two conflicting signed verdicts), but
  it cannot judge whether a single, non-contradictory review is *qualitatively*
  honest or competent. That subjective oracle is assumed, not implemented.
- **Demonstrative token layer.** The stake bond and review reward illustrate
  skin-in-the-game; the numbers are not a calibrated economy and are not tuned
  against real incentive analysis.
- **Cluster cap is a simplified proxy.** The collusion cap is a chain-derivable
  approximation (mutual cross-attestation) embedded in consensus; a fuller
  solution is controlled reviewer assignment plus audit, which is out of scope
  here.
- **In-memory state.** Chain, mempool, and derived tables live in process memory;
  there is no crash-safe persistence, so state does not survive a restart.
- **Institutional legitimacy is out of scope.** Whether any institution *accepts*
  a chain-issued certificate is a social and political problem, not one this
  system tries to solve.

## Notes on identity and safety

Peers are identified by public key, never by network address, and peer
introduction is manual, so the demos are fully self-contained and need no
internet bootstrap servers. The browser console stores private keys only in the
browser's `localStorage` and is a **demo identity — do not use real credentials**.
Generated `*.pem` keys, runtime `sqlite/` / `state/` directories, and local
editor settings are gitignored.
