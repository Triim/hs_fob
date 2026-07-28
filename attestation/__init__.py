"""Competence-attestation application layer (CS414).

This package sits *on top of* the generic ``blockchain`` core. An attestation
is not a new block or chain type — it is an ordinary
:class:`~blockchain.transaction.Transaction` whose ``payload`` carries a
structured attestation record. Keeping it at the payload level means the core
(Block, MerkleTree, Blockchain) stays domain-agnostic and unchanged.
"""
