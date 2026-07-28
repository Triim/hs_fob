# hs_fob — Decentralized Competence Attestation (CS414)

A minimal, readable blockchain implemented from scratch in pure Python, extended
with a competence-attestation **application layer** and a peer-to-peer
**networking layer** (IPv8). The core stays fully generic: attestations and
certificates ride inside an ordinary `Transaction` payload, so `Block`,
`MerkleTree`, and `Blockchain` are never modified by the application.

## Layout

- `blockchain/` — generic core (standard library only):
  - `transaction.py` — content-addressed `Transaction` (generic dict payload).
  - `merkle.py` — `MerkleTree` with inclusion proofs and `verify`.
  - `block.py` — `Block` (header hash over the Merkle root) + `mine`.
  - `proof_of_work.py` — leading-zero-bit difficulty helpers.
  - `blockchain.py` — `Blockchain` (genesis, mempool, validation).
  - `__main__.py` — single-process end-to-end demo.
- `attestation/` — application layer, built on `Transaction.payload`:
  - `attestation.py` — `make_attestation` / `is_attestation` (an attestation
    *is* a transaction, not a new block type).
  - `rubric.py` — `Rubric`: ordered claims committed under a Merkle root, reusing
    the core `MerkleTree` and `verify`.
  - `aggregator.py` — `certify`: pools distinct positive attesters for a
    `(subject, rubric_root)` pair and issues a certificate at threshold.
- `network/` — networking layer:
  - `wire.py` — JSON serialization bridge over the existing `to_dict`
    (the seam between core and network; self-checking on decode).
  - `community.py` — `AttestationCommunity` (IPv8): gossips attestations and
    mined blocks.
  - `demo.py` — multi-node demo (3 IPv8 nodes, sunny + rainy scenarios).
- `tests/` — unit and integration tests (stdlib `unittest`).

## Requirements

Python 3.12+ and [`uv`](https://docs.astral.sh/uv/). The networking layer uses
`pyipv8`, which requires Python ≥ 3.10 — so run everything through `uv`, which
manages the interpreter and virtual environment for you:

```bash
uv sync            # creates .venv and installs pyipv8 from pyproject/uv.lock
```

The `blockchain/` and `attestation/` layers are standard-library only; only the
`network/` layer needs `pyipv8`.

## Running the tests

The full suite (core, attestation, wire, and IPv8 integration tests) runs under
`uv`:

```bash
uv run python -m unittest discover -s tests -v
```

The IPv8 integration tests (`tests/test_community.py`) use IPv8's in-memory
`MockIPv8` / `TestBase` harness — real serialized packets between simulated
nodes, no network required.

## Running the core demo

```bash
uv run python -m blockchain
```

Builds a chain, adds a few generic-payload transactions, mines 3 blocks, and
reports whether the chain validates.

## Running the multi-node attestation demo

```bash
uv run python -m network.demo
```

Starts **three real IPv8 nodes** in one process (each with its own EC key file
`ec1.pem` / `ec2.pem` / `ec3.pem`, generated locally and gitignored), introduces
them over UDP loopback, and runs two scenarios with step-by-step output:

- **Sunny day** — three attesters on three nodes each attest a distinct rubric
  item for one subject. The attestations gossip to every node, one node mines
  them into a block, the aggregator issues a certificate at threshold, and that
  certificate is mined into a further block that **all nodes converge on**.
- **Rainy day** — attesters reference a *forged* rubric root. The transport is
  permissive, but the aggregation layer counts only votes bound to the published
  rubric, so the forged votes are ignored and **no certificate is issued**.

Peers are identified by public key (never by network address), and peer
introduction is manual, so the demo is fully self-contained and needs no
internet bootstrap servers. Generated `*.pem` keys and the IPv8 `sqlite/`
working directory are gitignored.
