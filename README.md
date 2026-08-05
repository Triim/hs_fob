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

## Problem, motivation, and users

Course attendance and a final grade say little about the exact work a person can
reproduce. A portfolio can show an artifact, but not necessarily who reviewed it,
which rubric claims they checked, how credible those reviewers were in that
domain, or whether the evidence was later contested. GradED addresses that narrower
problem: it creates a shared, auditable history behind a **specific competence
claim**, without claiming to replace universities or manufacture institutional
recognition.

The system has four participant roles:

- **Learner** — submits a work artifact by hash, receives a protocol certificate
  when the evidence threshold is met, and exports it as a portable Competence VC.
- **Reviewer** — obtains a domain-scoped Reviewer VC, proves possession of its
  subject key, and signs rubric-item attestations while bonding stake.
- **Verifier** — an employer, educator, or other relying party that checks the
  exported credential's issuer proof locally and resolves its current chain-backed
  status.
- **Validator / accrediting authority** — proposes and commits blocks, validates
  protocol rules, and collectively controls promotions, view changes, and objective
  slashing decisions.

## Why a blockchain instead of a database?

GradED uses a blockchain for one specific reason: several independent validators
must share an append-only evidence history without giving any one participant
unilateral control over certificates, reputation, or status. Signed transactions
preserve authorship; the Merkle-committed, hash-linked chain preserves ordering and
tamper evidence; and a BFT quorum makes a block irreversible only after multiple
validators have committed to the same header. Every node can then independently
replay that history into the same reputation, balances, validator set, and
certificate status.

A blockchain is **not inherently required** for competence records. If one trusted
institution owns the whole workflow and every relying party accepts its authority,
a conventional database plus signed exports is simpler, faster, and easier to
operate. GradED's design is justified only for the multi-authority case where the
audit trail and current status must not depend on one database administrator.

## User flow

1. A learner creates a browser identity and submits a work hash, domain, title,
   and rubric root in a signed transaction.
2. A reviewer obtains a domain-scoped Reviewer VC and proves possession of the
   private key behind its `did:key`.
3. The reviewer signs pass, fail, or abstain attestations bound to the exact
   submission transaction and rubric item.
4. Validators propose, validate, commit-sign, and finalize blocks containing that
   evidence.
5. Every node deterministically computes weighted support. Once all required
   rubric items and the threshold are satisfied, the protocol issues a certificate.
6. The learner exports that certificate as a portable Competence VC.
7. A verifier checks the VC signature locally and asks a node only for trusted
   issuer, chain linkage, and the live `valid` / `contested` / `revoked` status.

## System architecture

```mermaid
flowchart LR
    U[Browser clients<br/>learner · reviewer · verifier]
    K[Local identity<br/>Ed25519 + did:key]
    H[HTTP + WebSocket bridge]
    N[IPv8 validator cluster<br/>PoA proposal · BFT commits · view change]
    C[Generic blockchain<br/>transactions · Merkle root · signed blocks]
    D[Deterministic replay<br/>reputation · balances · certificates · status]
    V[Portable credentials<br/>Reviewer VC · Competence VC]

    U --> K
    K -->|signed requests| H
    H -->|validate + gossip| N
    N -->|finalized blocks| C
    C --> D
    D --> H
    H -->|live state| U
    D -->|export / resolve status| V
    V -->|portable JSON| U
```

The browser owns participant keys and performs transaction and proof-of-possession
signing locally. Each node exposes an HTTP/WebSocket bridge over the same live
objects it gossips through IPv8; the bridge is not a second source of truth. Nodes
exchange transactions, blocks, commit signatures, and view-change votes. Consensus
orders evidence in the generic chain, while application state is recomputed from
that chain rather than stored in a separate authoritative database. Credentials
remain off-chain and refer back to chain-derived evidence and status.

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
- **Reviewer Verifiable Credentials — the right to attest.** A node admits an
  attestation only when it arrives with a **Reviewer VC** (W3C VC 2.0 shape,
  signed by a trusted issuer with a Data Integrity `eddsa-jcs-2022` proof over
  JCS-canonicalized JSON) whose subject `did:key` **is the attesting key**, plus a
  **proof of possession**: a signature over a fresh, single-use challenge the node
  issued. A copied credential is therefore worthless — using it requires the
  private key it names, which never leaves the holder's browser. Eligibility is
  all the credential grants: an accepted attestation's **weight is still
  chain-derived reputation**, its **accountability is still stake**, and reviewer
  eligibility is **not** validator authority. The credential JSON lives entirely
  **off-chain** — it rides beside the transaction in the request/gossip envelope,
  so no transaction or consensus format changed and no personal data is ever
  written to the chain (`credentials/`, `network/community.py`).
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
  `/api/balances`, `/api/peers`, `/api/submissions`, `/api/domains`), credential
  export/status/verification routes, writes (`POST /api/tx`, `POST /api/mine`),
  and a `/ws` WebSocket that pushes live state. Transaction writes follow the real
  trust model: the **client** signs, the node only validates and relays — it never
  holds a participant's private key (`network/http_bridge.py`).
- **Vanilla-JS frontend.** A dependency-free, tabbed browser console (`frontend/`)
  that generates keypairs and signs transactions locally with a vendored, offline
  Ed25519 library (no CDN at runtime), then talks to a node over HTTP/WebSocket.
- **Portable competence credentials.** Any protocol-issued certificate can be
  exported, without another on-chain write, as a deterministic signed
  `GradEDCompetenceCredential`. The learner is named by the `did:key` derived from
  their existing Ed25519 public key; blockchain evidence links the JSON document
  back to the exact submission, rubric and certificate block. A verifier checks
  the issuer proof locally and asks a node for chain linkage plus the certificate's
  live `valid` / `contested` / `revoked` status. The signed document stays portable
  while its signed `credentialStatus` URL keeps its standing current
  (`credentials/competence.py`, `frontend/`).

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
- `credentials/` — portable, entirely off-chain credentials:
  - `jcs.py` — RFC 8785 JSON canonicalization (the bytes a credential signs).
  - `vc.py` — the GradED Authority, Reviewer VC issuance and verification.
  - `presentation.py` — proof of possession, its challenge store, and the
    presentation a holder sends with an attestation.
  - `competence.py` — deterministic Competence VC export, chain linkage and live
    certificate status verification.
- `network/` — networking + UI-facing layers:
  - `wire.py` — JSON serialization bridge over `to_dict` (the core/network seam).
  - `community.py` — `AttestationCommunity` (IPv8): gossips transactions, blocks,
    the commit round that drives BFT finality, and view-change votes.
  - `http_bridge.py` — read/write HTTP + `/ws` WebSocket over the live node.
  - `demo.py` — multi-node scripted demo (sunny / rainy / slashing scenarios).
  - `scenarios.py` — on-demand scenario registry driven by the live nodes.
  - `benchmarks.py` — live consensus benchmarks (finality vs N, convergence,
    view-change cost) measured from the nodes' own consensus-event timestamps,
    with a harness that launches and tears down an N-validator cluster.
  - `run_nodes.py` — live HTTP-pollable nodes for the browser console.
- `frontend/` — vanilla-JS console (`index.html`, `app.js`, `style.css`, vendored
  `noble-ed25519.js`), plus `assets/` — the presentation tabs, the Benchmarking
  tab (`bench.js`) and its vendored, offline canvas charting (`chart.js`).
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

The suite is organized by failure boundary rather than as one opaque end-to-end
test:

- **Pure protocol tests** cover transaction and block validity, Merkle proofs,
  rubric coverage, weighted aggregation, balances, reputation replay, promotion,
  slashing, and certificate lifecycle rules.
- **Network contract tests** exercise real serialized IPv8 messages, consensus
  handlers, HTTP reads and writes, WebSocket updates, and benchmark routing.
- **Cross-runtime tests** ask Node.js to verify Python-produced DIDs, canonical
  credential bytes, and Ed25519 signatures (and vice versa), catching browser /
  backend interoperability errors that Python-only tests cannot see.
- **Live benchmark runs** are deliberately separate from the fast suite. They
  start real temporary clusters and measure wall-clock network events, so treating
  them as deterministic unit tests would make routine validation slow and flaky.

Validation snapshot for the current presentation branch (5 August 2026):

```text
Docker/Python suite: 423 passed, 14 subtests passed, 13 skipped (Node.js absent)
Host interoperability suite: 13 passed with Node.js available
Combined: 436 unique test methods passed in their required runtimes
```

The 13 Docker skips are exactly the Python↔browser interoperability modules. The
runtime image intentionally contains Python but not Node.js, so those same 13 tests
are run on the host instead:

```bash
uv run python -m unittest \
  tests.test_did_js tests.test_credentials_js tests.test_competence_vc_js -v
```

## Benchmarking and evaluation

The **Benchmarking** tab runs three controlled experiments. It intentionally does
not compare GradED's local prototype throughput with published TPS figures from
unrelated production chains: hardware, geography, payload size, validator count,
and even the definition of finality would differ. Instead, each experiment keeps
the implementation and machine fixed and changes one condition:

| Question | Controlled baseline | Changed condition | Reported metric |
|---|---|---|---|
| What does a larger committee cost? | `N=4` validators | `N=7`, `10`, `13` | proposer `finalized_at − proposed_at`, plus relative multiplier vs `N=4` |
| How quickly does finality reach every node? | proposer block finality | first-to-last finality event | network agreement window |
| What does leader failure cost? | happy path, view 0 | scheduled proposer offline | stall response → replacement finality, plus multiplier vs happy path |

All charts retain the raw per-run samples and report median, minimum, maximum, and
p95. Measurements come from consensus-event timestamps recorded inside nodes, not
from the duration of Python object construction. Run them from the browser or call:

```bash
curl -X POST http://127.0.0.1:8080/api/benchmark/convergence \
  -H 'Content-Type: application/json' -d '{"repeats": 5}'

curl -X POST http://127.0.0.1:8080/api/benchmark/view_change \
  -H 'Content-Type: application/json' -d '{"repeats": 4}'
```

Results should be interpreted as a reproducible comparison on the machine that ran
them, not as a production capacity claim. The expected qualitative result is that
larger all-to-all commit committees increase finality cost, convergence adds a
small propagation window, and a justified view change costs an extra vote round.

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

   Node 0 also exposes the **consensus benchmarks** — `GET /api/benchmarks` and
   `POST /api/benchmark/{finality,convergence,view_change}` — each returning the
   raw per-run measurements plus summary statistics (median / min / max / p95):

   * `finality` — finalization time vs validator count. Because `N` varies, this
     one **launches an isolated cluster of `N` real validators per `N`**
     (4 → 7 → 10 → 13), proposes a series of blocks on it, and shuts it down
     before the next `N`; the clusters take their own temporary IPv8 key material
     and a free UDP port window, so they can run while the demo network is up.
   * `convergence` — measured on this running cluster.
   * `view_change` — happy path vs a rotated stalled proposer, on its own cluster.

   Every latency is a difference between **consensus-event timestamps recorded
   inside the nodes** at the moment the event occurred — a block proposed, a BFT
   quorum first observed, a view-change vote cast (`network/community.py`'s
   `event_times` / `view_change_times`) — never the wall-clock duration of a
   Python call, which would measure object construction rather than consensus.

2. Open the console. CORS is permissive, so the simplest path is to open the file
   directly:

   ```bash
   open frontend/index.html        # macOS; or just open the file in a browser
   ```

   or serve it statically if your browser restricts `file://` fetches:

   ```bash
   uv run python -m http.server -d frontend 5173    # then visit http://127.0.0.1:5173
   ```

   Generate a keypair, request a **Reviewer credential** for the domain you want
   to review in (the *Reviewer credential* card — attesting is refused without
   one), submit work, attest, produce blocks, trigger scenarios, and watch the
   chain, reputation, and balances update live over the WebSocket. Keys are
   generated and transactions are signed **in the browser** — the node only
   validates and relays. The reviewer credential is stored in the browser and its
   proof of possession is signed there too; the node holds no private key of yours
   and stores no credential.

   The credential routes are `GET /api/credentials/issuer` (the issuer this node
   trusts), `POST /api/credentials/reviewer/issue` (`{subject | subject_did,
   domains}` → a signed Reviewer VC), and `POST /api/credentials/challenge` (a
   fresh single-use proof-of-possession challenge). An attestation is then POSTed
   to `/api/tx` with a `credential_presentation` sibling field carrying
   `{credential, challenge, challenge_signature}`.

   Once a protocol certificate appears, its submission card offers **export VC**.
   The downloaded JSON comes from `GET
   /api/credentials/competence/{certificate_id}`, resolves live standing through
   `GET /api/credentials/{credential_id}/status`, and can be pasted or uploaded in
   the **Verify** tab. That tab verifies the Ed25519 proof in the browser and uses
   `POST /api/credentials/verify` for the chain-backed checks.

## Design decisions and trade-offs

- **Application-specific Python chain instead of Ethereum contracts.** This gives
  the project direct control over blocks, validation, finality, fork choice, and
  networking—the course's core learning goals—but sacrifices Ethereum tooling and
  ecosystem interoperability.
- **PoA proposal plus BFT-quorum finality instead of Proof of Work.** Validators
  are known authorities, so an energy-based anonymous leader race solves the wrong
  problem. The split makes authorship, agreement, and liveness explicit: PoA picks
  the proposer, commits finalize, and view-change votes rotate a stalled leader.
- **Generic chain plus deterministic derived state.** Keeping domain transactions
  inside a generic payload avoids coupling the blockchain core to GradED. Replay is
  easier to audit and replicate, at the cost of recomputation as history grows.
- **Off-chain credentials with on-chain evidence pointers.** Reviewer and
  Competence VCs remain portable and keep personal data out of consensus. The
  trade-off is that reviewer admission is a mempool/gossip policy rather than a
  historical block-validity rule.
- **Domain reputation separated from eligibility, stake, and validator power.**
  This prevents one credential or token balance from silently becoming universal
  authority, but introduces more concepts that the UI and documentation must make
  explicit.
- **Objective slashing only.** The protocol can prove equivocation from two signed
  contradictory statements; it deliberately refuses to punish subjective
  disagreement because no trustworthy quality oracle exists on-chain.

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
- **Reviewer eligibility is admission policy, not consensus.** Every node
  re-verifies a Reviewer VC and its proof of possession before pooling or
  relaying an attestation, but the credential is off-chain, so a *block* cannot be
  re-checked against it after the fact: a node that chose to ignore the gate could
  still mine an uncredentialed attestation, and honest peers would accept the
  block (its transactions are still validly signed and economically funded).
  Putting eligibility into consensus would mean putting credential state on-chain,
  which this step deliberately does not do. Revocation is likewise expiry-only —
  a status-list credential is the obvious extension.
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

Each identity also has a **`did:key`** rendering (`crypto/did.py`, mirrored for
the browser in `frontend/did.js`): the same Ed25519 public key encoded as
`did:key:z…` per the W3C did:key method (`ed25519-pub` multicodec, base58btc
multibase). It is a naming layer, not new cryptography — a DID is derived from a
public key on demand, shown in the UI, and never stored. On-chain identity is
unchanged: a transaction's `sender` is still the hex public key, and signatures
are still verified against it. Because the key *is* the identifier, a `did:key`
resolves back to the verification key with no registry and no network lookup.

Reviewer credentials build directly on that DID: a Reviewer VC names its holder
by `did:key`, and attesting requires signing a node-issued challenge with the key
behind it, so **eligibility cannot be stolen along with the credential file**.
The demo's issue endpoint is deliberately open (anyone can obtain a demo reviewer
credential); a deployment would gate issuance behind the accrediting body's own
admissions process, which changes who may *become* eligible but not the
protocol-relevant property that only a certified, key-possessing reviewer can
attest.

## Future work

- Persist blocks and derived state with crash-safe recovery and replay checkpoints.
- Replace demo-open Reviewer VC issuance with an institutional admission workflow
  and interoperable revocation/status-list credentials.
- Evaluate consensus across separate hosts under controlled latency, packet loss,
  partitions, and Byzantine timing rather than loopback-only clusters.
- Formalize the safety and liveness model or replace the course-project mechanism
  with a production-reviewed BFT implementation.
- Add controlled reviewer assignment, audits, and richer collusion analysis instead
  of relying only on mutual-cross-attestation components.
- Define privacy-preserving artifact storage and selective disclosure for credential
  claims; the current protocol commits hashes but does not distribute artifacts.
- Calibrate stake, reward, promotion, and reputation parameters through simulation
  and real user studies rather than treating them as demonstrative constants.
- Package the verifier as a standalone relying-party application that can resolve
  multiple trusted GradED networks.

## References and implementation influences

- Castro, M. and Liskov, B. **Practical Byzantine Fault Tolerance** — the source of
  the supermajority/intersection reasoning that motivates GradED's BFT-style commit
  quorum. GradED does not claim to implement complete PBFT.
- [W3C Verifiable Credentials Data Model 2.0](https://www.w3.org/TR/vc-data-model-2.0/)
  — the document shape used by Reviewer and Competence credentials.
- [W3C Controlled Identifiers: `did:key`](https://w3c-ccg.github.io/did-key-spec/)
  — self-resolving Ed25519 public-key identifiers.
- [RFC 8785 — JSON Canonicalization Scheme](https://www.rfc-editor.org/rfc/rfc8785)
  — deterministic credential signing bytes.
- [py-ipv8](https://github.com/Tribler/py-ipv8) — the peer-to-peer overlay and
  messaging substrate; GradED defines its own messages and protocol rules on top.
- Merkle, R. C. **A Digital Signature Based on a Conventional Encryption
  Function** — the hash-tree construction used to commit block headers to their
  transaction set.

## Contributors

- **Ilia Mogilev** — project concept, protocol design, implementation, tests,
  documentation, benchmarking, and presentation.

This repository was developed as the final project for **CS414 Fundamentals of
Blockchain**.
