# hs_fob — A From-Scratch Blockchain (CS414)

A minimal, readable blockchain implemented from scratch in pure-Python (standard
library only) as the technical foundation for a decentralized
competence-attestation protocol built in later coursework.

## Layout

- `blockchain/` — core package:
  - `transaction.py` — content-addressed `Transaction` (generic dict payload).
  - `merkle.py` — `MerkleTree` with inclusion proofs and `verify`.
  - `block.py` — `Block` (header hash over the Merkle root) + `mine`.
  - `proof_of_work.py` — leading-zero-bit difficulty helpers.
  - `blockchain.py` — `Blockchain` (genesis, mempool, validation).
  - `__main__.py` — end-to-end demo.
- `tests/` — unit tests (stdlib `unittest`).
- `main.py` — separate py-ipv8 networking exercise (not part of the core yet).

## Requirements

Python 3.12+. The core depends only on the standard library.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt   # no third-party deps yet
```

## Running the tests

```bash
python -m unittest discover -s tests -v
```

## Running the demo

```bash
python -m blockchain
```

Builds a chain, adds a few generic-payload transactions, mines 3 blocks, prints
each block (index, truncated hashes, nonce, tx count), and reports whether the
chain validates. Example tail:

```
Chain length: 4 blocks (incl. genesis)
Chain valid?  True
```
