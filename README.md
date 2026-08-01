# GradED — Decentralized Competence Attestation (CS414)

A minimal, readable blockchain implemented **from scratch in pure Python**,
extended with a competence-attestation application layer, a peer-to-peer
networking layer (IPv8), and a browser console. Peers agree on an ordered chain;
everything else — reputation, token balances, the validator set — is **derived
state**, a pure function of that agreed chain, so every node computes it
identically with no extra consensus.

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
  verifies and that producer is an authority under the reputation derived from
  the chain **prefix before that block** (which breaks the circularity). A block
  becomes **final** only once a **BFT quorum of validators** have gossiped commit
  signatures for it; fork choice prefers the chain with more finalized blocks
  rather than merely the longest chain (`blockchain/blockchain.py`,
  `network/community.py`).
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
  deterministically before any weight is debited; the debit is capped at
  `MAX_SLASH` (`reputation/slashing.py`).
- **Submissions.** A `submission` is a specialist's signed declaration of a piece
  of work for review. Only the artifact's SHA-256 hash and light metadata go
  on-chain — the file bytes never do (`attestation/submission.py`).
- **HTTP bridge + WebSocket.** Each live node exposes its real objects over HTTP:
  read GETs (`/api/node`, `/api/chain`, `/api/mempool`, `/api/reputation`,
  `/api/balances`, `/api/peers`), writes (`POST /api/tx`, `POST /api/mine`), and a
  `/ws` WebSocket that pushes live state. Writes follow the real trust model: the
  **client** signs, the node only validates and relays — it never holds a
  participant's private key (`network/http_bridge.py`).
- **Vanilla-JS frontend.** A dependency-free browser console (`frontend/`) that
  generates keypairs and signs transactions locally with a vendored, offline
  Ed25519 library (no CDN at runtime), then talks to a node over HTTP/WebSocket.

## Layout

- `blockchain/` — generic core (standard library only):
  - `transaction.py` — content-addressed `Transaction` (generic dict payload).
  - `merkle.py` — `MerkleTree` with inclusion proofs and `verify`.
  - `block.py` — `Block` (header hash over the Merkle root) + producer signature.
  - `blockchain.py` — `Blockchain`: genesis, mempool, PoA validity, BFT finality,
    finality-based fork choice.
  - `tx_signing.py` — which transaction types require an author signature.
  - `promotion.py` — the `promotion` transaction (endogenous validator growth).
  - `__main__.py` — single-process end-to-end core demo.
- `attestation/` — application layer, built on `Transaction.payload`:
  - `attestation.py` — `make_attestation` / `is_attestation` (pass/fail/abstain).
  - `submission.py` — `make_submission` / `hash_artifact` (hash-only on-chain).
  - `rubric.py` — `Rubric`: ordered claims committed under a Merkle root.
  - `aggregator.py` — `certify`: weighted support over distinct attesters,
    issuing a certificate at threshold.
- `reputation/` — derived state (standard library only):
  - `genesis.py` — `GENESIS_REPUTATION` / balances: the axiomatic trust anchor.
  - `derive.py` — reputation and balances as pure functions of the chain.
  - `tally.py` — weighted attester support.
  - `registry.py` / `balances.py` — the weight and token tables (mutated only
    during derivation).
  - `slashing.py` — evidence-based, quorum-approved slash validation.
- `network/` — networking + UI-facing layers:
  - `wire.py` — JSON serialization bridge over `to_dict` (the core/network seam).
  - `community.py` — `AttestationCommunity` (IPv8): gossips transactions, blocks,
    and the commit round that drives BFT finality.
  - `http_bridge.py` — read/write HTTP + `/ws` WebSocket over the live node.
  - `demo.py` — three-node demo (sunny / rainy / slashing scenarios).
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

Starts three real IPv8 nodes in one process (each with its own EC key file
`ec1.pem` / `ec2.pem` / `ec3.pem`, generated locally and gitignored), introduces
them over UDP loopback, and runs three scenarios with step-by-step output: a
**sunny day** (honest attestations reach a certificate), a **rainy day** (forged
rubric root → no certificate), and a **slashing day** (an equivocating attester is
slashed on evidence + quorum, and their certificate no longer issues).

## Running the live nodes + browser console

1. Start the live, HTTP-pollable nodes (they seed real chain state from the demo
   scenarios, then keep serving):

   ```bash
   uv run python -m network.run_nodes
   ```

   Each node's read/write HTTP bridge listens on a base port + node index —
   `8080`, `8081`, `8082` by default. To dodge a port already in use, pass a base
   port as the first argument or via `HS_FOB_HTTP_PORT`:

   ```bash
   uv run python -m network.run_nodes 9000          # → 9000, 9001, 9002
   HS_FOB_HTTP_PORT=9000 uv run python -m network.run_nodes
   ```

   (The bundled frontend's node picker targets the default `8080–8082`.)

2. Open the console. CORS is permissive, so the simplest path is to open the file
   directly:

   ```bash
   open frontend/index.html        # macOS; or just open the file in a browser
   ```

   or serve it statically if your browser restricts `file://` fetches:

   ```bash
   uv run python -m http.server -d frontend 5173    # then visit http://127.0.0.1:5173
   ```

   Generate a keypair, submit work, attest, produce blocks, and watch the chain,
   reputation, and balances update live over the WebSocket. Keys are generated and
   transactions are signed **in the browser** — the node only validates and relays.

## Known limitations

- **Synchronous commit, no view-change.** Finality uses a single-round commit over
  the gossip layer; there is no leader rotation or view-change protocol, so a
  stalled or faulty proposer is not automatically replaced.
- **Genesis validator set is an axiom.** The founding validators (and genesis
  reputation) are declared constants, not themselves established on-chain — the
  unavoidable external trust anchor. Everything after genesis is chain-derived.
- **Honest-attestation oracle is out of scope.** The protocol can prove
  *equivocation* (two conflicting signed verdicts) and slash it, but it cannot
  judge whether a single, non-contradictory review is *qualitatively* honest or
  competent. That qualitative oracle is assumed, not implemented.
- **Paid-review tradeoff.** Rewarding reviewers for reviews that hold up creates
  an incentive to attest for the reward; the stake bond and slashing bound abuse
  but do not eliminate the tension between paying for review and keeping it
  disinterested.

## Notes on identity and safety

Peers are identified by public key, never by network address, and peer
introduction is manual, so the demos are fully self-contained and need no
internet bootstrap servers. The browser console stores private keys only in the
browser's `localStorage` and is a **demo identity — do not use real credentials**.
Generated `*.pem` keys, runtime `sqlite/` / `state/` directories, and local
editor settings are gitignored.
