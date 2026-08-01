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
from blockchain.promotion import is_promotion, promotion_signing_bytes
from blockchain.transaction import Transaction
from blockchain.tx_signing import requires_signature
from crypto.keys import verify as _verify
from attestation.attestation import is_attestation
from reputation.derive import derive_balances, derive_registry
from reputation.genesis import CONSENSUS_DOMAIN
from reputation.slashing import is_slash, validate_slash

# Fixed genesis parameters — identical on every node so chains share one root.
GENESIS_PREVIOUS_HASH = "0" * 64
GENESIS_TIMESTAMP = 0.0

# Minimum weight in the infrastructural CONSENSUS_DOMAIN a block producer must
# hold to be a *genesis* validator (consensus authority). A documented constant so
# the security/liveness trade-off is tunable and explicit. Genesis authorities
# carry 100 consensus weight, well above this floor.
AUTHORITY_THRESHOLD = 50

# --- Endogenous validator promotion -----------------------------------------
# Consensus authority is NOT automatic from competence. Beyond the genesis
# validators, the ONLY way to join the validator set is a promotion transaction
# (see :mod:`blockchain.promotion`) that clears all three gates below.

# Competence weight (in the promotion's claimed domain) a candidate must already
# hold to be *eligible* for promotion. Merit is necessary but never sufficient —
# a quorum of validators must still approve (that gate lives in the promotion tx).
PROMOTION_THRESHOLD = 100

# Rate limit: at most this many promotions may take effect within any trailing
# window of PROMOTION_WINDOW blocks. Caps how fast the set can churn.
MAX_NEW_VALIDATORS_PER_WINDOW = 2

# The trailing window, in blocks, the two rate/fraction caps are measured over.
PROMOTION_WINDOW = 5


def scheduled_proposer(validators: set[str], height: int, view: int) -> str | None:
    """The validator whose turn it is to propose block ``height`` in ``view``.

    **Proposer schedule (deterministic, round-robin over views and heights):**
    sort the validator set by pubkey (a total, machine-independent order) and pick
    index ``(height + view) mod N``. So the normal proposer for a height is
    ``sorted[height mod N]`` (view 0); if that proposer stalls and the set rotates
    to view 1, the *next* validator ``sorted[(height + 1) mod N]`` takes over, and
    so on. Sorting by pubkey makes the schedule identical on every honest node with
    no coordination, and folding in both ``height`` and ``view`` means the leader
    both rotates across heights (so no single validator is always the proposer) and
    advances on a view-change (so a stalled proposer can be skipped).

    Returns ``None`` for an empty set (no one can propose), which callers treat as
    "no valid proposer", so a block with an empty prefix validator set is rejected.
    """
    if not validators:
        return None
    ordered = sorted(validators)
    return ordered[(height + view) % len(ordered)]


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

    def __init__(
        self,
        genesis: dict[str, dict[str, int]] | None = None,
        balances: dict[str, int] | None = None,
    ) -> None:
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
            balances: The initial-token-balance anchor (``pubkey -> tokens``) the
                chain seeds its economic ledger from. ``None`` uses the canonical
                :data:`~reputation.genesis.GENESIS_BALANCES`. Also shared network
                configuration: the free-balance rule an attestation must clear
                (see :meth:`is_valid_chain`) is judged against balances derived
                from this anchor, so honest nodes must all use the same one.
        """
        self.genesis = genesis
        self.balance_genesis = balances
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
        """The validator set (consensus authorities) governing block ``upto_index``.

        The validator set is derived from the chain **prefix** — blocks
        ``0 .. upto_index-1`` — as the union of two sources, kept deliberately
        distinct from competence reputation:

        1. **Genesis validators** — pubkeys the anchor grants weight
           ``>= AUTHORITY_THRESHOLD`` in the infrastructural
           :data:`~reputation.genesis.CONSENSUS_DOMAIN`. This is the external
           bootstrap axiom: the founding validator set is *declared*, not earned.
        2. **Promoted validators** — candidates that a valid promotion transaction
           in the prefix has converted into consensus authorities (competence
           threshold + a quorum of then-current validators approving + rate/
           fraction caps; see :meth:`_replay_promotions`).

        Crucially, earning *competence* in a subject domain (via certificates) does
        **not** enlarge this set — only genesis or an approved promotion does. So
        the right to produce/commit blocks (consensus authority) stays separate
        from subject skill (competence) and from vote weight (attester credibility).

        Keying finality on the same prefix that decides producer authority keeps
        consensus non-circular: a block's finality is judged against a validator
        set fixed *before* it, so a block can never enlarge the quorum that
        finalizes it — nor promote its own producer.
        """
        registry = derive_registry(self, upto_index=upto_index, genesis=self.genesis)
        return self._consensus_authorities(registry) | self._replay_promotions(upto_index)

    def proposer_for(self, height: int, view: int = 0) -> str | None:
        """Pubkey of the validator scheduled to propose block ``height`` in ``view``.

        Convenience over :func:`scheduled_proposer` that resolves the validator set
        from this chain's prefix (blocks ``0 .. height-1``), so producers, the demo,
        and the live commit round all agree on whose turn it is without duplicating
        the schedule. ``None`` when the prefix has no validators.
        """
        return scheduled_proposer(self.validator_set(height), height, view)

    @staticmethod
    def _consensus_authorities(registry) -> set[str]:
        """Genesis-style validators implied by ``registry``: consensus-domain authorities.

        Consensus authority is read off one specific domain — CONSENSUS_DOMAIN —
        never "any domain", so competence in a subject domain is never mistaken for
        the right to produce blocks.
        """
        return registry.authorities_in_domain(CONSENSUS_DOMAIN, AUTHORITY_THRESHOLD)

    def _promotion_ok(
        self, payload, validators_before: set[str], prefix_registry, fresh_in_window: int
    ) -> bool:
        """Whether one promotion is well-formed, earned, approved, and within caps.

        ``validators_before`` is the validator set in force *before* this promotion
        (its prefix plus any earlier promotions already applied). Returns ``True``
        only if every gate passes, so a promotion is treated fail-closed: consensus
        rejects any promotion transaction present that this does not accept.

        Gates:
          (a) **competence** — the candidate already holds ``>= PROMOTION_THRESHOLD``
              weight in the claimed domain (merit is necessary);
          (b) **quorum approval** — at least ``quorum_size(N)`` of the ``N`` current
              validators have a *valid* approver signature over the ``(candidate,
              domain)`` statement (peer approval is also necessary; competence alone
              never promotes);
          (c) **rate cap** — at most ``MAX_NEW_VALIDATORS_PER_WINDOW`` promotions may
              take effect within the trailing ``PROMOTION_WINDOW`` blocks; and
          (d) **fraction cap** — the fresh cohort promoted within that window may not
              exceed 1/3 of the resulting set, so newly-minted validators can never
              reach a BFT-blocking (let alone majority) share at once.
        """
        if not is_promotion(payload):
            return False
        candidate = payload["candidate"]
        domain = payload["domain"]
        approvals = payload["approvals"]

        # An existing validator cannot be "promoted" again — nothing to grant.
        if candidate in validators_before:
            return False

        # (a) competence: necessary, never sufficient.
        if prefix_registry.weight(candidate, domain) < PROMOTION_THRESHOLD:
            return False

        # (b) quorum approval by *current* validators, with genuine signatures.
        message = promotion_signing_bytes(candidate, domain)
        approvers = {
            approver
            for approver, signature in approvals.items()
            if approver in validators_before
            and isinstance(signature, str)
            and _verify(approver, message, signature)
        }
        if len(approvers) < quorum_size(len(validators_before)):
            return False

        # (c) + (d) rate and fraction caps on the fresh cohort.
        fresh_after = fresh_in_window + 1
        if fresh_after > MAX_NEW_VALIDATORS_PER_WINDOW:
            return False
        total_after = len(validators_before) + 1
        if 3 * fresh_after > total_after:  # fresh cohort must stay <= 1/3 of the set
            return False

        return True

    def _replay_promotions(self, upto_index: int) -> set[str]:
        """Candidates promoted by valid promotions in blocks ``0 .. upto_index-1``.

        Replays the prefix block by block, applying each promotion that clears
        :meth:`_promotion_ok` against the validator set (and window counts) as they
        stood at that point. A promotion at block ``j`` is judged against the
        reputation and validators derived from blocks ``0 .. j-1`` — the prefix rule
        — so it can never rely on state it or its own block introduce. Promotions
        that fail the gates are simply not applied (consensus rejects such chains
        outright in :meth:`is_valid_chain`; here we stay best-effort so the set is
        still well-defined for any caller).
        """
        promoted: set[str] = set()
        effect_indices: list[int] = []
        for j in range(1, upto_index):
            prefix_registry = derive_registry(self, upto_index=j, genesis=self.genesis)
            current = self._consensus_authorities(prefix_registry) | promoted
            for tx in self.blocks[j].transactions:
                if not is_promotion(tx):
                    continue
                fresh = sum(1 for idx in effect_indices if idx > j - PROMOTION_WINDOW)
                if self._promotion_ok(tx.payload, current, prefix_registry, fresh):
                    candidate = tx.payload["candidate"]
                    promoted.add(candidate)
                    effect_indices.append(j)
                    current = current | {candidate}
        return promoted

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

    def add_block(
        self, producer_key=None, view: int = 0, view_change_messages=None
    ) -> Block:
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
                are set so it passes :meth:`is_valid_chain` — but only if that
                producer is the one the schedule assigns to ``(index, view)``.
            view: The consensus view to stamp on the block (0 for the normal,
                first-attempt proposer). A ``view > 0`` records that earlier
                proposers for this height stalled and must be justified by a quorum
                of ``view_change_messages`` for :meth:`is_valid_chain` to accept it.
            view_change_messages: Optional ``pubkey -> signature`` map justifying a
                ``view > 0`` (each a validator's :func:`~blockchain.block.view_change_signing_bytes`
                vote for this ``(index, view)``). Ignored/empty for view 0.
        """
        block = Block(
            index=len(self.blocks),
            previous_hash=self.last_block.hash,
            transactions=list(self.mempool),  # snapshot so later edits can't sneak in
            view=view,
            view_change_messages=dict(view_change_messages or {}),
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
        # (1) Validate the candidate in isolation under our shared configuration
        # (both the reputation anchor and the balance/endowment anchor).
        candidate = Blockchain(genesis=self.genesis, balances=self.balance_genesis)
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
        participant transactions (attestation / submission) must be signed
        by their author — ``verify_signature()`` verifies against the ``sender``
        public key, so passing it also proves ``sender`` *is* the signer. Protocol-
        validated transactions (certificates, promotions, and now **slashes** —
        the latter carrying evidence + a validator quorum, see
        :func:`reputation.slashing.validate_slash`) and genesis transactions are exempt
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

        **Stake bonds** (economic layer): an attestation additionally binds a real
        token stake. It is valid only if the reviewer's **free** balance —
        balances derived from the prefix (:func:`reputation.derive.derive_balances`)
        minus any bond they already posted earlier in the same block — covers the
        stake. A reviewer therefore cannot bond tokens they do not hold, and the
        bond is later released + rewarded (on a contributing certificate) or burned
        (on a valid slash) purely by derivation. Like reputation, balances are a
        pure function of the chain, so every honest node enforces this identically.

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
        # Validators promoted by earlier blocks, and the block index each promotion
        # took effect at — carried forward so a block's validator set includes the
        # cohort promoted before it, and the rate/fraction caps see the trailing
        # window. A block never counts promotions in itself (prefix rule).
        promoted: set[str] = set()
        effect_indices: list[int] = []

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
            # PoA (2): the producer must be a **validator** under the set derived
            # from the PREFIX (blocks 0..i-1), never from this block itself — the
            # prefix rule that breaks the validity/authority circularity. The
            # validator set is the genesis consensus authorities (from THIS chain's
            # anchor) plus everyone promoted by an earlier block; competence in a
            # subject domain grants no production right on its own.
            prefix_registry = derive_registry(
                self, upto_index=block.index, genesis=self.genesis
            )
            consensus_authorities = self._consensus_authorities(prefix_registry)
            validators = consensus_authorities | promoted

            # PoA (2a) — SCHEDULED PROPOSER (liveness via rotation). The producer must
            # be exactly the validator the deterministic schedule assigns to this
            # block's ``(index, view)`` (:func:`scheduled_proposer`): sorted-by-pubkey
            # round robin ``sorted[(index + view) mod N]``. This subsumes the old
            # "producer is a validator" rule (the scheduled proposer is always in the
            # set) and additionally pins *which* validator's turn it is, so a block
            # cannot be produced out of turn. ``view`` must be a real non-negative int.
            if isinstance(block.view, bool) or not isinstance(block.view, int):
                return False
            if block.view < 0:
                return False
            if block.producer != scheduled_proposer(validators, block.index, block.view):
                return False

            # PoA (2b) — VIEW-CHANGE JUSTIFICATION. View 0 is the normal path and needs
            # no justification. A block claiming ``view > 0`` asserts that the earlier
            # proposer(s) for this height stalled and the set rotated the leader; that
            # advance is only legitimate if a **quorum of this block's validators**
            # signed a view-change vote for exactly this ``(index, view)``. We count
            # only genuine signatures (``view_change_signers`` re-verifies each) that
            # come from actual validators, so a producer cannot forge or pad its way
            # into an out-of-turn slot — it must show the network agreed to rotate to
            # it. Real fork choice never needs to trust the view otherwise.
            if block.view > 0:
                justifiers = block.view_change_signers() & validators
                if len(justifiers) < quorum_size(len(validators)):
                    return False

            # Finality integrity: a block may legitimately carry *any* number of
            # commit signatures (0 on a not-yet-final tip, up to a full quorum on a
            # finalized block), but every signature it *does* carry must be a
            # genuine commit by a validator in this block's prefix-derived set. A
            # chain therefore cannot fake finality by pasting forged or
            # non-validator commit signatures: such signatures make the whole chain
            # invalid, so :meth:`is_final` (which counts these same signatures) only
            # ever reflects real quorum. The validator set (``validators`` above) is
            # the prefix consensus authorities plus promoted validators — the exact
            # set finality is judged against.
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

            # Balances as they stood BEFORE this block (the prefix rule again), so
            # an attestation's bond is judged against tokens the reviewer already
            # held — a block can never fund its own bonds. ``block_locked`` then
            # accumulates bonds posted earlier *within this same block*, so two
            # attestations in one block cannot both spend the same free balance.
            prefix_balances = derive_balances(
                self,
                upto_index=block.index,
                endowments=self.balance_genesis,
                genesis=self.genesis,
            )
            block_locked: dict[str, int] = {}

            # Transactions are validated **fail-closed**: every transaction must
            # be a recognised kind that passes its own rule, or the chain is
            # rejected. There is no "accept anything else" branch, so an unknown
            # payload type cannot ride into consensus unchecked.
            #   - certificate: re-derived from the prefix (a deterministic protocol
            #     event, not authority fiat) and forbidden from double-issuing.
            #   - promotion: a protocol-validated grant of consensus authority,
            #     re-checked against the prefix (competence + a quorum of current
            #     validators' signatures + rate/fraction caps); a present promotion
            #     that fails any gate invalidates the chain.
            #   - slash: a protocol-validated debit of reputation, re-checked
            #     against the prefix (the offender's two conflicting attestations
            #     present + a quorum of current validators' signatures); a present
            #     slash that fails any gate invalidates the chain.
            #   - participant tx (attestation/submission): must carry a valid
            #     author signature. verify_signature() checks against the tx's own
            #     ``sender``, so a valid result also ties sender to signer.
            #   - anything else (unknown type / non-dict payload): rejected outright.
            #
            # ``block_validators`` starts as this block's set and grows as in-block
            # promotions take effect, so a second promotion in one block is judged
            # against the first; ``promoted``/``effect_indices`` carry forward.
            block_validators = set(validators)
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
                if is_promotion(payload):
                    fresh = sum(1 for idx in effect_indices if idx > i - PROMOTION_WINDOW)
                    if not self._promotion_ok(
                        payload, block_validators, prefix_registry, fresh
                    ):
                        return False
                    candidate = payload["candidate"]
                    promoted.add(candidate)
                    effect_indices.append(i)
                    block_validators.add(candidate)
                    continue
                if is_slash(payload):
                    # A slash is a protocol-validated grant of *dis*-authority,
                    # re-checked against the prefix exactly as reputation derivation
                    # will apply it: the offender's two conflicting attestations must
                    # be present in blocks 0..i-1, and a quorum of the prefix's
                    # consensus authorities must have signed it. A present slash that
                    # fails any gate invalidates the chain (fail-closed), so a
                    # fabricated or unapproved slash can never ride into consensus.
                    if not validate_slash(payload, prefix_chain, consensus_authorities):
                        return False
                    continue
                if is_attestation(tx):
                    # A participant tx: it must carry a valid author signature
                    # (verify_signature checks against ``sender``, tying sender to
                    # signer) AND the reviewer must be able to cover the stake it
                    # bonds. Free balance is the prefix balance minus bonds already
                    # posted earlier in this block, so a self-funded or double-spent
                    # bond can never ride into consensus.
                    if not (tx.is_signed() and tx.verify_signature()):
                        return False
                    reviewer = tx.sender
                    stake = tx.payload["stake"]
                    already = block_locked.get(reviewer, 0)
                    if prefix_balances.free(reviewer) - already < stake:
                        return False
                    block_locked[reviewer] = already + stake
                    continue
                if requires_signature(tx):
                    if not (tx.is_signed() and tx.verify_signature()):
                        return False
                    continue
                # Not a certificate, promotion, or known signed participant type:
                # fail closed rather than trusting an unrecognised transaction.
                return False

        return True
