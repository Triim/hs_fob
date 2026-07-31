"""The Blockchain — an ordered, tamper-evident list of produced blocks.

The chain starts from a fixed **genesis block** (a trusted anchor every node
builds identically) and grows as authorities produce new blocks from pending
transactions.

Consensus: Proof-of-Authority
-----------------------------
Validity is decided by **Proof-of-Authority**, not proof-of-work. A non-genesis
block is valid only if its ``producer_signature`` verifies against its
``producer`` *and* that producer is an authority under the reputation derived
from the chain **prefix before this block** (blocks ``0 .. N-1`` when validating
block N). Checking against the prefix — never including block N itself — is what
breaks the circularity: a block's validity depends on state that is already
agreed *before* it, so a block can never bootstrap its own producer's authority
(see :func:`reputation.derive.derive_registry`). There is no proof-of-work: block
production is a signature, not a mining search.

How tampering is caught
-----------------------
Each block exposes ``hash`` and ``merkle_root`` as *computed* properties, so a
block can never disagree with itself. Detection comes from chain-level invariants
that ``is_valid_chain`` enforces:

1. **Link integrity** — every block stores its predecessor's hash in
   ``previous_hash``. Tampering with a *past* transaction changes that block's
   hash, but the following block still carries the old value, so the link breaks.
2. **Producer signature** — every non-genesis block's header is signed by its
   producer. Tampering with the *last* block's transaction changes its Merkle
   root and therefore its header, so the producer's signature no longer verifies.
3. **Authority by prefix** — the producer must hold authority weight under the
   reputation implied by all earlier blocks.

Together these cover tampering anywhere in the chain.
"""

from __future__ import annotations

from types import SimpleNamespace

from blockchain.block import Block
from blockchain.merkle import MerkleTree
from blockchain.transaction import Transaction
from blockchain.tx_signing import requires_signature
from reputation.derive import derive_registry

# Fixed genesis parameters — identical on every node so chains share one root.
GENESIS_PREVIOUS_HASH = "0" * 64
GENESIS_TIMESTAMP = 0.0

# Minimum reputation weight (in any single domain) a block producer must hold to
# be an authority. A documented constant so the security/liveness trade-off is
# tunable and explicit. Genesis authorities carry 100 consensus weight, well
# above this floor.
AUTHORITY_THRESHOLD = 50


def quorum_size(n: int) -> int:
    """BFT quorum for a validator set of size ``n``: ``floor(2n/3) + 1``.

    This is the classic Byzantine-fault-tolerant supermajority: with ``n = 3f + 1``
    validators it tolerates up to ``f`` faulty ones, because any two quorums of
    this size must overlap in at least one honest validator, so two conflicting
    blocks can never both be finalized. Worked values: ``n=1 -> 1``, ``n=3 -> 3``,
    ``n=4 -> 3`` (tolerates 1 fault), ``n=7 -> 5`` (tolerates 2).
    """
    return (2 * n) // 3 + 1


class Blockchain:
    """An append-only chain of produced blocks with a pending-transaction pool."""

    def __init__(self, genesis: dict[str, dict[str, int]] | None = None) -> None:
        """Create a chain with only the genesis block.

        Args:
            genesis: The reputation trust anchor this chain validates against.
                ``None`` (the default) uses the canonical
                :data:`~reputation.genesis.GENESIS_REPUTATION`. This anchor is
                **shared network configuration**, exactly like the genesis block:
                every honest node must use the same one, because PoA validity
                (``is_valid_chain``) is judged against reputation derived from it.
                A node configured with a *different* anchor will compute different
                authorities and diverge — that is correct behaviour, not a bug.
        """
        self.genesis = genesis
        self.blocks: list[Block] = [self._create_genesis_block()]
        self.mempool: list[Transaction] = []

    @staticmethod
    def _create_genesis_block() -> Block:
        """Build the fixed genesis block.

        Uses hardcoded values (no transactions, fixed timestamp, no producer) so
        the genesis block — and therefore its hash — is identical on every node.
        The genesis block is a trusted anchor and is not produced by an authority.
        """
        return Block(
            index=0,
            previous_hash=GENESIS_PREVIOUS_HASH,
            transactions=[],
            timestamp=GENESIS_TIMESTAMP,
        )

    @property
    def last_block(self) -> Block:
        """The most recent block in the chain."""
        return self.blocks[-1]

    def validator_set(self, upto_index: int) -> set[str]:
        """The validator set governing block ``upto_index``.

        Validators are exactly the **authorities** (weight ``>= AUTHORITY_THRESHOLD``
        in any domain) implied by the chain **prefix** — blocks ``0 .. upto_index-1``
        — derived from this chain's configured anchor. Keying finality on the same
        prefix that decides producer authority keeps consensus non-circular: a
        block's finality is judged against a validator set fixed *before* it, so a
        block can never enlarge the quorum that finalizes it.
        """
        registry = derive_registry(self, upto_index=upto_index, genesis=self.genesis)
        return registry.authorities(AUTHORITY_THRESHOLD)

    def is_final(self, block: Block) -> bool:
        """Whether ``block`` is finalized: a quorum of its validator set committed it.

        The genesis block is final by definition (a trusted anchor). For any later
        block, the validator set is derived from the prefix before it; the block is
        final iff at least ``quorum_size(N)`` of those ``N`` validators appear among
        its **valid** commit signers (:meth:`Block.commit_signers` already drops
        forged/malformed signatures, and intersecting with the validator set drops
        commits from non-validators). An empty validator set is never a quorum, so
        such a block is not final.
        """
        if block.index == 0:
            return True
        validators = self.validator_set(block.index)
        if not validators:
            return False
        committed = block.commit_signers() & validators
        return len(committed) >= quorum_size(len(validators))

    def add_transaction(self, transaction: Transaction) -> None:
        """Add a transaction to the pending pool (mempool).

        Pooled transactions are not part of the chain until a block that
        includes them is mined via :meth:`add_block`.
        """
        self.mempool.append(transaction)

    def add_block(self, producer_key=None) -> Block:
        """Pack all pending transactions into a new block and append it.

        Links the new block to the current tip. Under Proof-of-Authority there is
        no mining loop: if a ``producer_key`` is given the block is signed by that
        authority (the live validity rule); if omitted the block is left
        unproduced (useful for unit tests that only need blocks to *exist* for
        scanning, and never validate the chain). Clears the mempool and returns
        the new block.

        Args:
            producer_key: Optional Ed25519 private key of the producing authority.
                When provided, the block's ``producer`` and ``producer_signature``
                are set so it passes :meth:`is_valid_chain`.
        """
        block = Block(
            index=len(self.blocks),
            previous_hash=self.last_block.hash,
            transactions=list(self.mempool),  # snapshot so later edits can't sneak in
        )
        if producer_key is not None:
            block.sign_as_producer(producer_key)
        self.blocks.append(block)
        self.mempool.clear()
        return block

    # ---------------------------------------------------------- fork choice

    def _finalized_blocks(self) -> dict[int, str]:
        """``index -> hash`` for every block THIS chain has finalized.

        These are the node's irreversible commitments: once a block here is
        finalized (a quorum of its validator set committed it), fork choice will
        never adopt a chain that drops or rewrites it. Genesis is always included
        (final by definition).
        """
        return {b.index: b.hash for b in self.blocks if self.is_final(b)}

    def _finalized_height(self) -> int:
        """Highest block index this chain has finalized (0 if only genesis is)."""
        return max(
            (b.index for b in self.blocks if self.is_final(b)), default=0
        )

    def _tip_commit_weight(self) -> int:
        """Number of *valid validator* commit signatures on this chain's tip.

        The equivocation tiebreaker's first key: between two same-height,
        equally-final forks, the one whose tip has gathered more genuine validator
        commits is closer to finality and is preferred.
        """
        tip = self.last_block
        if tip.index == 0:
            return 0
        return len(tip.commit_signers() & self.validator_set(tip.index))

    def _fork_choice_rank(self) -> tuple[int, int, int]:
        """The comparable strength of this chain, higher is better.

        ``(finalized_height, length, tip_commit_weight)`` — compared
        lexicographically, then broken by *lower* tip hash (handled by the caller).
        This encodes the fork-choice rule: **finality first** (a chain that has
        finalized more history wins), then length (finality does not freeze
        non-final growth, so a longer non-conflicting chain is still adopted), then
        how close the tip is to its own quorum.
        """
        return (self._finalized_height(), len(self.blocks), self._tip_commit_weight())

    def _reverts_our_finality(self, candidate: "Blockchain") -> bool:
        """Whether ``candidate`` drops or rewrites a block WE have finalized.

        A finalized block can never be reverted: if any ``(index, hash)`` this node
        has finalized is missing from ``candidate`` (shorter than that index, or a
        different block there), the candidate is trying to rewrite settled history
        and must be refused **even if it is longer**. This is the core BFT safety
        property.
        """
        for index, finalized_hash in self._finalized_blocks().items():
            if index >= len(candidate.blocks):
                return True
            if candidate.blocks[index].hash != finalized_hash:
                return True
        return False

    def replace_chain(self, candidate_blocks: list[Block]) -> bool:
        """Adopt ``candidate_blocks`` if finality-based fork choice prefers it.

        This is the **BFT fork-choice rule** — finality, not length, decides. A
        candidate is adopted only when all of the following hold:

        1. It validates end to end as a chain under THIS node's anchor
           (:meth:`is_valid_chain`: same genesis, intact links, every producer
           signature valid and an authority by the prefix, and no faked finality).
        2. It does not revert any block this node has already finalized
           (:meth:`_reverts_our_finality`) — a finalized block is irreversible even
           against a strictly longer fork.
        3. It out-ranks the current chain under
           :meth:`_fork_choice_rank`: higher **finalized height** first; then, when
           finality is equal, the longer chain; then the **deterministic
           equivocation tiebreak** — more valid validator commit signatures on the
           tip, and finally the lexicographically **lower tip hash**. The hash tie
           is what makes two honest nodes resolve the *same* way when they see two
           blocks at the same height, so they never churn.

        On acceptance the blocks are swapped in and the mempool is recomputed: any
        pending transaction the adopted chain already commits is dropped, so it is
        not mined twice.

        Returns:
            ``True`` if the candidate was adopted, ``False`` if it was refused.
        """
        # (1) Validate the candidate in isolation under our shared configuration.
        candidate = Blockchain(genesis=self.genesis)
        candidate.blocks = list(candidate_blocks)
        if not candidate.is_valid_chain():
            return False

        # (2) Safety: never revert our own finalized history, length notwithstanding.
        if self._reverts_our_finality(candidate):
            return False

        # (3) Preference: strictly out-rank us, or tie on rank but win the lower-hash
        # tiebreak. Equal rank *and* equal (or higher) tip hash keeps our chain, so a
        # node never churns between equally-good forks.
        candidate_rank = candidate._fork_choice_rank()
        our_rank = self._fork_choice_rank()
        if candidate_rank < our_rank:
            return False
        if candidate_rank == our_rank:
            if candidate.last_block.hash >= self.last_block.hash:
                return False

        self.blocks = list(candidate_blocks)
        committed = {tx.hash for block in self.blocks for tx in block.transactions}
        self.mempool = [tx for tx in self.mempool if tx.hash not in committed]
        return True

    def is_valid_chain(self) -> bool:
        """Validate the whole chain under Proof-of-Authority.

        Checks, for the genesis block, that it matches the canonical genesis, and
        for every later block: correct index, an intact ``previous_hash`` link, a
        Merkle root that matches its transactions, a valid ``producer_signature``,
        a ``producer`` who is an authority under reputation derived from the chain
        **prefix before that block**, and that every **participant-submitted**
        transaction carries a valid author signature. Returns ``True`` only if
        every check passes.

        Transaction signatures follow :func:`blockchain.tx_signing.requires_signature`:
        participant transactions (attestation / submission / slash) must be signed
        by their author — ``verify_signature()`` verifies against the ``sender``
        public key, so passing it also proves ``sender`` *is* the signer. Protocol-
        generated transactions (certificates) and genesis transactions are exempt
        from the *signature* requirement, but a certificate is not trusted blindly:
        it is a **deterministic protocol event**, so it is re-derived from the
        prefix and rejected unless its genuine weighted support meets
        :data:`~attestation.aggregator.CERTIFICATE_THRESHOLD` and its ``granted_by``
        names exactly the real positive attesters (see
        :func:`~attestation.aggregator.validate_certificate`). A certificate whose
        identity already appears earlier in the chain is rejected too, so a subject
        cannot be credited twice for the same certified claim.

        Transaction validation is **fail-closed**: every transaction must be a
        recognised kind that passes its own rule — a signed participant tx or a
        re-derivable certificate. Any transaction that is neither (an unknown
        payload ``type``, or a non-dict payload) invalidates the chain rather than
        being waved through, so a new or malformed type cannot slip into consensus
        unchecked.

        **Finality integrity** (BFT): a block may carry any number of commit
        signatures — none on a not-yet-final tip, up to a quorum on a finalized
        block — but every signature present must be a genuine commit by a validator
        in that block's prefix-derived set. A chain cannot *assert* finality it did
        not earn by pasting forged or non-validator commit signatures; doing so
        makes the whole chain invalid. Real finality (:meth:`is_final`) counts the
        very same signatures, so it only ever reflects a true quorum.
        """
        # Imported lazily: the aggregator imports this module, so importing it at
        # module load would be circular. Certificate validation is consensus, but
        # its re-derivation logic lives with certify() to stay the single source.
        from attestation.aggregator import (
            CERTIFICATE_TYPE,
            certificate_id,
            validate_certificate,
        )

        if self.blocks[0].hash != self._create_genesis_block().hash:
            return False

        # Certificate identities committed so far, to forbid double-issuance.
        seen_certificate_ids: set[str] = set()

        for i in range(1, len(self.blocks)):
            block = self.blocks[i]
            previous = self.blocks[i - 1]

            if block.index != i:
                return False
            # Link integrity: catches tampering with any earlier block.
            if block.previous_hash != previous.hash:
                return False
            # Merkle root commits to the block's transactions.
            if block.merkle_root != MerkleTree(block.transactions).root:
                return False
            # PoA (1): the header must be signed by its producer. Tampering the
            # last block changes its header, so this catches it (replaces PoW).
            if not block.verify_producer_signature():
                return False
            # PoA (2): the producer must be an authority under reputation derived
            # from the PREFIX (blocks 0..i-1), never from this block itself — the
            # prefix rule that breaks the validity/authority circularity. Derived
            # from THIS chain's configured anchor (shared network config).
            prefix_registry = derive_registry(
                self, upto_index=block.index, genesis=self.genesis
            )
            if not prefix_registry.is_authority(block.producer, AUTHORITY_THRESHOLD):
                return False

            # Finality integrity: a block may legitimately carry *any* number of
            # commit signatures (0 on a not-yet-final tip, up to a full quorum on a
            # finalized block), but every signature it *does* carry must be a
            # genuine commit by a validator in this block's prefix-derived set. A
            # chain therefore cannot fake finality by pasting forged or
            # non-validator commit signatures: such signatures make the whole chain
            # invalid, so :meth:`is_final` (which counts these same signatures) only
            # ever reflects real quorum. The validator set is the prefix authorities
            # — the exact set finality is judged against (PART 1).
            validators = prefix_registry.authorities(AUTHORITY_THRESHOLD)
            claimed_signers = set(block.commit_signatures)
            # commit_signers() returns only the cryptographically valid ones, so a
            # claimed signer missing from it carried a forged/malformed signature.
            if claimed_signers - block.commit_signers():
                return False
            # Every genuine commit must come from an actual validator, else the
            # block is padding its finality with outsiders' votes.
            if claimed_signers - validators:
                return False

            # The prefix view (blocks 0..i-1) and its reputation, reused to
            # re-derive any certificate this block carries.
            prefix_chain = SimpleNamespace(blocks=self.blocks[:i])

            # Transactions are validated **fail-closed**: every transaction must
            # be a recognised kind that passes its own rule, or the chain is
            # rejected. There is no "accept anything else" branch, so an unknown
            # payload type cannot ride into consensus unchecked.
            #   - certificate: re-derived from the prefix (a deterministic protocol
            #     event, not authority fiat) and forbidden from double-issuing.
            #   - participant tx (attestation/submission/slash): must carry a valid
            #     author signature. verify_signature() checks against the tx's own
            #     ``sender``, so a valid result also ties sender to signer.
            #   - anything else (unknown type / non-dict payload): rejected outright.
            for tx in block.transactions:
                payload = tx.payload
                if isinstance(payload, dict) and payload.get("type") == CERTIFICATE_TYPE:
                    cid = certificate_id(payload)
                    # No double-issue: the same certified claim, once committed,
                    # cannot be re-credited by a later (or same-block) copy.
                    if cid in seen_certificate_ids:
                        return False
                    if not validate_certificate(payload, prefix_chain, prefix_registry):
                        return False
                    seen_certificate_ids.add(cid)
                    continue
                if requires_signature(tx):
                    if not (tx.is_signed() and tx.verify_signature()):
                        return False
                    continue
                # Not a certificate and not a known signed participant type:
                # fail closed rather than trusting an unrecognised transaction.
                return False

        return True
