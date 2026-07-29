"""Domain-scoped reputation (CS414 — Fundamentals of Blockchain).

Reputation is a per-domain weight vector held by each participant, tracked in a
single registry over the single chain — ``domain`` is a data dimension, never a
separate chain. This package holds the axiomatic genesis weights, the registry
that answers "what is X's weight in domain D", and a weighted tally over the
chain. It is pure logic: it does not touch blocks, consensus, or the network.
"""
