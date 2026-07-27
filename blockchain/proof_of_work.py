"""Proof-of-work helpers.

Proof-of-work makes producing a valid block *deliberately expensive*: the miner
must search for a nonce whose block hash begins with a required number of zero
bits. Verifying that a hash meets the target is instant, but finding one takes,
on average, ``2 ** difficulty`` hash attempts. That asymmetry is what secures
the chain against cheap rewriting.

"Difficulty" here is the number of **leading zero bits** required in the hash
(bits, not hex digits — so difficulty can be tuned one bit at a time). Both
functions operate on a hex digest string and know nothing about blocks, which
keeps them pure and easy to test.
"""

from __future__ import annotations


def count_leading_zero_bits(hash_hex: str) -> int:
    """Return how many leading zero bits a hex digest has.

    Interprets the hex string as a big integer: fewer significant bits means
    more leading zeros. The all-zero hash is treated as fully zero-prefixed.
    """
    value = int(hash_hex, 16)
    total_bits = len(hash_hex) * 4  # 4 bits per hex character
    if value == 0:
        return total_bits
    return total_bits - value.bit_length()


def hash_meets_target(hash_hex: str, difficulty: int) -> bool:
    """True if ``hash_hex`` has at least ``difficulty`` leading zero bits."""
    return count_leading_zero_bits(hash_hex) >= difficulty
