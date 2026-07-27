# hs_fob — A From-Scratch Blockchain (CS414)

A minimal, readable blockchain implemented from scratch in pure-Python (standard
library only) as the technical foundation for a decentralized
competence-attestation protocol built in later coursework.

## Layout

- `blockchain/` — core package (transactions, Merkle tree, blocks, proof-of-work, chain).
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

_Added in a later step._

```bash
python -m blockchain
```
