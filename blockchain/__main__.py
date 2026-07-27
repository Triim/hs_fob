"""End-to-end demo: build a chain, mine a few blocks, print it, validate it.

Run with:

    python -m blockchain

This exercises the whole core — Transaction, MerkleTree, Block, proof-of-work,
and Blockchain — with generic payloads (no application schema), showing that the
foundation is ready for a domain layer to be built on top of it later.
"""

from __future__ import annotations

from blockchain.blockchain import Blockchain
from blockchain.transaction import Transaction


def short(value: str, length: int = 12) -> str:
    """Truncate a long hex hash for readable printing."""
    return f"{value[:length]}…"


def print_block(block) -> None:
    """Print one block's key fields on a single readable line."""
    print(
        f"  #{block.index}  "
        f"hash={short(block.hash)}  "
        f"prev={short(block.previous_hash)}  "
        f"merkle={short(block.merkle_root)}  "
        f"nonce={block.nonce:<7}  "
        f"txs={len(block.transactions)}"
    )


def main() -> None:
    # A low difficulty keeps the demo fast while still doing real work.
    difficulty = 16
    chain = Blockchain(difficulty=difficulty)
    print(f"Created chain (difficulty={difficulty} leading zero bits)")
    print("Genesis:")
    print_block(chain.blocks[0])

    # Three blocks of generic transactions. Payloads are arbitrary dicts — an
    # attestation record could sit here later with no change to the core.
    batches = [
        [
            Transaction(sender="alice", payload={"type": "transfer", "to": "bob", "amount": 10}),
            Transaction(sender="bob", payload={"type": "note", "text": "hello chain"}),
        ],
        [
            Transaction(sender="carol", payload={"type": "transfer", "to": "dave", "amount": 3}),
        ],
        [
            Transaction(sender="dave", payload={"type": "transfer", "to": "alice", "amount": 1}),
            Transaction(sender="alice", payload={"type": "vote", "choice": "yes"}),
            Transaction(sender="carol", payload={"type": "note", "text": "third block"}),
        ],
    ]

    print("\nMining 3 blocks:")
    for batch in batches:
        for tx in batch:
            chain.add_transaction(tx)
        block = chain.add_block()
        print_block(block)

    print(f"\nChain length: {len(chain.blocks)} blocks (incl. genesis)")
    print(f"Chain valid?  {chain.is_valid_chain()}")


if __name__ == "__main__":
    main()
