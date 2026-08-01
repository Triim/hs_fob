"""IPv8 transport for attestations and blocks.

This is the peer-to-peer layer. It does **no** blockchain logic of its own: it
moves bytes between peers and hands them to the core, using
:mod:`network.wire` as the only encode/decode path. The design keeps two rules
front and centre:

- **JSON-as-string is the bridge.** IPv8's ``DataClassPayload`` serializes
  primitives only, not arbitrary dicts. So every message carries a single ``str``
  field holding the wire JSON produced by :mod:`network.wire`; the structured
  object is reconstructed on the far side by ``wire_to_tx`` / ``wire_to_block``.
- **Identity is the public key, never the address.** Peers are recognised by
  ``peer.public_key`` / ``peer.mid``; IP/port can change at any time and must
  not be used as identity. (This is stated explicitly in the IPv8 docs.)

Message types:

- ``TransactionMessage`` (msg id 1) — one participant transaction (attestation,
  submission, or slash), carried as its wire JSON string.
- ``BlockMessage`` (msg id 2) — one whole produced block.
- ``ChainRequestMessage`` (msg id 3) — "send me your whole chain", emitted when a
  received block does not extend our tip (a fork).
- ``ChainResponseMessage`` (msg id 4) — one whole chain, for fork choice.
- ``CommitMessage`` (msg id 5) — one validator's commit vote for a block
  (``{block_hash, signer, signature}``), the round that drives BFT finality.
- ``ViewChangeMessage`` (msg id 6) — one validator's view-change vote
  (``{height, view, signer, signature}``), the round that rotates a stalled
  proposer so liveness does not depend on any single leader.

The commit round (BFT finality over the gossip layer):

1. A proposer produces a block and gossips it (``BlockMessage``), casting its own
   commit vote first so the block travels with one commit already attached.
2. A node that receives a block it considers valid — and is itself a current
   validator (a prefix-derived authority) — signs the block's header with its
   validator key and broadcasts a ``CommitMessage``.
3. Every node collects commit votes onto its copy of the block; a vote counts only
   if it is a genuine signature by a validator, and a signer already present is a
   duplicate that is neither re-counted nor re-broadcast (so the flood terminates).
4. Once a block holds ≥ quorum valid validator commits it is *final*
   (:meth:`Blockchain.is_final`) — and finality is deterministic, so all honest
   nodes converge on the same finalized block.

The view-change round (BFT liveness over the gossip layer):

1. The proposer for a height/view is fixed by a deterministic schedule
   (:func:`blockchain.blockchain.scheduled_proposer`): sorted-by-pubkey round robin
   ``sorted[(height + view) mod N]``, so view 0's leader is ``sorted[height mod N]``.
2. If that proposer stalls (produces no block within a timeout), each waiting
   validator calls :meth:`AttestationCommunity.request_view_change`, signing and
   gossiping a view-change vote to advance to the next view at that height.
3. Once a node collects ``>= quorum`` votes for one ``(height, view)``, the view
   advances; the validator the schedule assigns to that view proposes a block
   **stamped with the view and carrying those quorum votes as justification**.
4. Consensus (:meth:`Blockchain.is_valid_chain`) accepts a ``view > 0`` block only
   if its producer is the correctly-scheduled proposer for ``(height, view)`` *and*
   a quorum of validators signed the view-change to it — so a stalled proposer can
   be rotated past without ever letting a block be produced out of turn.

Safety (no finalized block is ever reverted) holds regardless of view changes: a
view only decides *who may propose next*, never which finalized history stands.

Fork sync is deliberately naïve for the MVP: on any divergence a node asks the
sender for its *entire* chain and runs :meth:`Blockchain.replace_chain`, which
decides by **BFT finality** (a finalized block is never reverted; higher
finalized height wins; length only breaks a finality tie). A production system
would exchange headers and sync only the missing suffix; that optimization is
out of scope here.

Reputation is **node-owned but chain-derived**: the community exposes
``reputation`` as :func:`reputation.derive.derive_registry` over its own chain, so
it is never an independently mutated object injected from outside — it is always
exactly what the current chain implies.
"""

from __future__ import annotations

from dataclasses import dataclass

from ipv8.community import Community, CommunitySettings
from ipv8.lazy_community import lazy_wrapper
from ipv8.messaging.payload_dataclass import DataClassPayload
from ipv8.peer import Peer

from attestation.attestation import is_attestation
from attestation.submission import is_submission
from blockchain.block import view_change_signing_bytes
from blockchain.blockchain import Blockchain, quorum_size, scheduled_proposer
from reputation.derive import derive_balances, derive_registry
from reputation.genesis import GENESIS_AUTHORITY_KEYS
from crypto.keys import public_hex, sign, verify
from network.wire import (
    block_to_wire,
    chain_to_wire,
    commit_to_wire,
    tx_to_wire,
    view_change_to_wire,
    wire_to_block,
    wire_to_chain,
    wire_to_commit,
    wire_to_tx,
    wire_to_view_change,
)


@dataclass
class TransactionMessage(DataClassPayload[1]):
    """A single participant transaction, carried as its wire JSON string.

    Historically attestation-only (hence msg id 1); it now carries any participant
    transaction — attestation or submission — so submitted transactions of
    every kind propagate over the same envelope. (Slashes and promotions are
    protocol-validated and ride in mined blocks, not this participant envelope.)
    """

    wire: str


@dataclass
class BlockMessage(DataClassPayload[2]):
    """A whole mined block, carried as its wire JSON string."""

    wire: str


@dataclass
class ChainRequestMessage(DataClassPayload[3]):
    """A request for the sender's whole chain, sent on fork divergence.

    Carries no data of its own — the ``marker`` field exists only because a
    payload needs at least one field; receiving it is the whole signal.
    """

    marker: str


@dataclass
class ChainResponseMessage(DataClassPayload[4]):
    """A whole chain (list of blocks), carried as its wire JSON string."""

    wire: str


@dataclass
class CommitMessage(DataClassPayload[5]):
    """One validator's commit vote for a block, carried as its wire JSON string.

    The wire JSON (see :func:`network.wire.commit_to_wire`) holds
    ``{block_hash, signer, signature}``: which block is being finalized (by hash),
    who is voting (their pubkey), and their Ed25519 signature over that block's
    header. Like every other message it uses a single ``wire: str`` field, so the
    dataclass matches exactly what is sent — no ``marker``-style field mismatch.
    """

    wire: str


@dataclass
class ViewChangeMessage(DataClassPayload[6]):
    """One validator's view-change vote, carried as its wire JSON string.

    The wire JSON (see :func:`network.wire.view_change_to_wire`) holds
    ``{height, view, signer, signature}``: the height whose proposer is being
    rotated, the view to advance to, who is voting, and their signature over
    :func:`blockchain.block.view_change_signing_bytes`. A quorum of these for one
    ``(height, view)`` is what lets the next scheduled proposer produce a valid
    ``view > 0`` block when the earlier proposer stalled — the liveness escape hatch.
    """

    wire: str


# Finalize the IPv8 serialization format of every message *at import time*.
#
# ``DataClassPayload`` builds its ``format_list``/``names`` lazily, on the first
# time a message of that type is *constructed* (IPv8 does this inside
# ``__new__``). That is a footgun for a receive-only node: a process that only
# ever *receives* a given message — never sends one — leaves that class with an
# empty format, so IPv8 unpacks zero fields and ``from_unpack_list`` raises
# ``TypeError: __init__() missing 1 required positional argument`` (e.g. the
# ``marker`` of a ChainRequestMessage a node answers but never sends). It is
# masked in a single process (all nodes share one class object, so whoever sends
# first compiles it for everyone) but bites the moment nodes run in separate
# processes — the real deployment topology, and what fork-sync exercises.
#
# Constructing one throwaway instance of each type here triggers that same
# compilation once, deterministically, before any packet arrives — so both the
# ``add_message_handler`` registrations and the ``@lazy_wrapper`` decoders below
# bind to a class whose format is already populated. This touches only the IPv8
# payload (de)serialization; the wire JSON and signing are untouched.
for _payload_cls in (
    TransactionMessage,
    BlockMessage,
    ChainRequestMessage,
    ChainResponseMessage,
    CommitMessage,
    ViewChangeMessage,
):
    _payload_cls("")  # compile format_list/names; the instance is discarded
del _payload_cls


class AttestationSettings(CommunitySettings):
    """Community settings extended with the local chain the node operates on.

    IPv8 constructs a community from a settings object, so this is the idiomatic
    place to inject the node's :class:`Blockchain`. ``CommunitySettings`` is a
    ``SimpleNamespace`` (not a dataclass), so ``blockchain`` is a plain class
    attribute default that an instance overrides via
    ``AttestationSettings(blockchain=chain)``.
    """

    blockchain: Blockchain | None = None
    # Ed25519 private key this node produces (signs) blocks with. Defaults to the
    # shared genesis authority so a node can produce valid PoA blocks out of the
    # box; a deployment gives each authority its own key.
    producer_key: object | None = None
    # Reputation trust anchor this node validates against. Used only when no
    # blockchain is injected (then a fresh chain is built with it); an injected
    # blockchain already carries its own anchor. ``None`` means the canonical
    # GENESIS_REPUTATION. This is SHARED network configuration — every honest
    # node must use the same anchor or it will diverge (see Blockchain).
    genesis: dict | None = None
    # Initial-token-balance anchor, used only when no blockchain is injected
    # (an injected chain already carries its own). ``None`` means the canonical
    # GENESIS_BALANCES. Also shared network configuration (see Blockchain).
    balances: dict | None = None


class AttestationCommunity(Community):
    """Gossips attestations and blocks over IPv8, backed by a local chain."""

    # Fixed 20-byte overlay identifier so every node joins the same network.
    community_id = b"AttestCompetence2024"
    # IPv8 builds settings via this class, so declaring it here lets the demo
    # inject a per-node Blockchain through the overlay's ``initialize`` dict.
    settings_class = AttestationSettings

    def __init__(self, settings: AttestationSettings) -> None:
        super().__init__(settings)
        # Each node owns its own chain; the community only feeds it. Read via
        # getattr so a plain CommunitySettings (no blockchain attribute) still
        # yields a fresh chain instead of raising. When we build the chain
        # ourselves, seed it with the node's configured anchor; an injected chain
        # already carries its own. Either way the anchor lives in one place —
        # ``self.blockchain.genesis`` — so consensus and reputation read the same.
        self.blockchain: Blockchain = getattr(settings, "blockchain", None) or Blockchain(
            genesis=getattr(settings, "genesis", None),
            balances=getattr(settings, "balances", None),
        )
        # The key this node signs blocks with. Falls back to the shared genesis
        # authority so blocks produced here pass Proof-of-Authority validation.
        self.producer_key = (
            getattr(settings, "producer_key", None)
            or GENESIS_AUTHORITY_KEYS["genesis-authority"][0]
        )
        # This node's validator identity: the public key it commits (and produces)
        # with. Consensus is keyed on this pubkey, never on the network address.
        self.validator_pubkey = public_hex(self.producer_key)
        # Block hashes we have already announced as finalized, so the "reached
        # quorum" log fires exactly once per block, not on every extra commit.
        self._finalized_announced: set[str] = set()

        # View-change bookkeeping (BFT liveness on a stalled proposer):
        #   _view_change_votes: (height, view) -> {signer_pubkey -> signature}
        #     collected view-change votes, so a quorum for one (height, view) can be
        #     detected and then carried onto the block that advances to it.
        #   _view_advanced: heights whose view we have already acted on by producing
        #     (or seeing produced), so a node proposes at an advanced view at most once.
        self._view_change_votes: dict[tuple[int, int], dict[str, str]] = {}
        self._view_advanced: set[int] = set()

        # Map each message type to its handler. The wire string is decoded and
        # validated inside the handler, never here.
        self.add_message_handler(TransactionMessage, self.on_transaction)
        self.add_message_handler(BlockMessage, self.on_block)
        self.add_message_handler(ChainRequestMessage, self.on_chain_request)
        self.add_message_handler(ChainResponseMessage, self.on_chain_response)
        self.add_message_handler(CommitMessage, self.on_commit)
        self.add_message_handler(ViewChangeMessage, self.on_view_change)

    @property
    def reputation(self):
        """The reputation registry implied by this node's current chain.

        Chain-derived on demand (never a stored, separately-mutated object), so
        it always agrees with the chain the node has converged on. This is what
        certification and any authority question consult. It derives from the
        node's own anchor (``self.blockchain.genesis``), the same one PoA
        validation uses — one anchor per node.
        """
        return derive_registry(self.blockchain, genesis=self.blockchain.genesis)

    @property
    def balances(self):
        """The token balance ledger implied by this node's current chain.

        Chain-derived on demand (never a stored, separately-mutated object), so it
        always agrees with the chain the node has converged on — the economic
        counterpart of :attr:`reputation`. It seeds from the node's own endowment
        anchor (``self.blockchain.balance_genesis``), the same one the free-balance
        rule in ``is_valid_chain`` uses.
        """
        return derive_balances(
            self.blockchain,
            endowments=self.blockchain.balance_genesis,
            genesis=self.blockchain.genesis,
        )

    def accepts_transaction(self, tx) -> bool:
        """Whether ``tx`` is a well-formed participant transaction with a valid signature.

        Mirrors the chain's own rule (see
        :func:`blockchain.tx_signing.requires_signature` and
        :meth:`~blockchain.blockchain.Blockchain.is_valid_chain`): only
        attestation / submission are accepted, and only when signed by
        their author (``verify_signature`` checks the signature against the tx's
        ``sender``). This is the single gate for both gossip receipt and HTTP
        submission, so a node never pools — and therefore never mines — a
        transaction that could not be valid on-chain. Slashes (and promotions)
        are protocol-validated, not participant-signed, so they are not admitted
        here; they enter the chain in mined blocks and are checked by
        ``is_valid_chain``.

        For an **attestation** the gate also mirrors the chain's economic rule: the
        reviewer must have enough **free** balance (given this node's current chain)
        to cover the stake it bonds, so a node never pools — and never mines — a
        bond the reviewer cannot fund. (Reserving balance across *multiple* pending
        bonds is not tracked here; ``is_valid_chain`` is the backstop that rejects
        an over-bonded block — an MVP simplification.)
        """
        if is_attestation(tx):
            if not (tx.is_signed() and tx.verify_signature()):
                return False
            return self.balances.free(tx.sender) >= tx.payload["stake"]
        if is_submission(tx):
            return tx.is_signed() and tx.verify_signature()
        return False

    # ------------------------------------------------------------------ send

    def broadcast_transaction(self, tx) -> int:
        """Send a participant transaction to every currently-known peer.

        Works for any participant transaction (attestation, submission).
        Returns the number of peers it was sent to, so callers/tests can see the
        fan-out. Encoding goes through the wire bridge so the bytes on the network
        match exactly what the core hashed and the author signed.
        """
        wire = tx_to_wire(tx)
        peers = self.get_peers()
        for peer in peers:
            self.ez_send(peer, TransactionMessage(wire))
        return len(peers)

    def broadcast_attestation(self, tx) -> int:
        """Back-compat alias for :meth:`broadcast_transaction`."""
        return self.broadcast_transaction(tx)

    def mine_and_broadcast_block(self, view: int = 0, view_change_messages=None):
        """Mine the local mempool into a block, commit it, and gossip it to peers.

        Returns the produced block. Uses the chain's own ``add_block``, signing it
        with this node's producer key so it satisfies Proof-of-Authority. The
        proposer is itself a validator, so it casts its own commit vote **before**
        broadcasting — the block then travels with that first commit attached, and
        every peer runs the same validation and its own commit round on receipt.

        The caller is expected to be the validator the schedule assigns to
        ``(next height, view)`` — for the normal path that is view 0, and this
        method is invoked directly. A ``view > 0`` block additionally carries
        ``view_change_messages`` (a quorum of validator view-change votes) as the
        justification the schedule demands; that path is driven by the view-change
        round below, not called directly.
        """
        block = self.blockchain.add_block(
            producer_key=self.producer_key,
            view=view,
            view_change_messages=view_change_messages,
        )
        self._commit_if_validator(block)  # proposer's own commit rides with the block
        self.broadcast_block(block)
        return block

    def broadcast_block(self, block) -> int:
        """Gossip an already-produced ``block`` to every known peer.

        Returns the peer count for tests/telemetry. Kept separate from producing
        so a node can re-advertise its tip (e.g. to help a lagging peer diverge
        and then sync) without producing a new block.
        """
        wire = block_to_wire(block)
        peers = self.get_peers()
        for peer in peers:
            self.ez_send(peer, BlockMessage(wire))
        return len(peers)

    # --------------------------------------------------------------- receive

    @lazy_wrapper(TransactionMessage)
    def on_transaction(self, peer: Peer, payload: TransactionMessage) -> None:
        """Handle an incoming participant transaction: validate, then pool if new."""
        sender_id = peer.mid.hex()  # identity by public key material, not address
        try:
            tx = wire_to_tx(payload.wire)
        except ValueError:
            self.logger.warning("dropping malformed transaction from %s", sender_id)
            return

        if not self.accepts_transaction(tx):
            self.logger.warning(
                "dropping non-participant or unsigned tx from %s", sender_id
            )
            return

        if self._already_seen(tx):
            return  # idempotent: gossip can deliver the same tx many times

        self.blockchain.add_transaction(tx)
        self.logger.info(
            "pooled %s %s from %s",
            tx.payload.get("type", "tx") if isinstance(tx.payload, dict) else "tx",
            tx.hash[:12],
            sender_id,
        )

    @lazy_wrapper(BlockMessage)
    def on_block(self, peer: Peer, payload: BlockMessage) -> None:
        """Handle an incoming block: verify it extends the chain, then append."""
        sender_id = peer.mid.hex()
        try:
            block = wire_to_block(payload.wire)  # also re-checks merkle_root/hash
        except ValueError:
            self.logger.warning("dropping malformed block from %s", sender_id)
            return

        if self._try_append_block(block):
            self.logger.info(
                "appended block %d (%s) from %s",
                block.index,
                block.hash[:12],
                sender_id,
            )
            # A view-changed block filling this height means the rotation is settled:
            # record it so we never also try to propose our own block for this height.
            if block.view > 0:
                self._view_advanced.add(block.index)
            # The block arrived valid and extends our tip: if we are a validator
            # for it, cast our own commit vote and gossip it. The block may already
            # carry the proposer's (and others') commits from the wire, so this may
            # be the vote that reaches quorum — check finality afterwards.
            self._commit_if_validator(block)
            self._note_if_finalized(block)
        else:
            # The block does not extend our tip: we may be on a shorter or
            # forked chain. Ask this peer for its whole chain and let fork choice
            # decide (naïve MVP sync — a whole chain, not just the missing suffix).
            self.logger.info(
                "block %d from %s does not extend our tip; requesting full chain",
                block.index,
                sender_id,
            )
            self.ez_send(peer, ChainRequestMessage("sync"))

    @lazy_wrapper(ChainRequestMessage)
    def on_chain_request(self, peer: Peer, payload: ChainRequestMessage) -> None:
        """Answer a fork-sync request by sending our whole chain to the peer."""
        self.ez_send(peer, ChainResponseMessage(chain_to_wire(self.blockchain.blocks)))

    @lazy_wrapper(ChainResponseMessage)
    def on_chain_response(self, peer: Peer, payload: ChainResponseMessage) -> None:
        """Adopt the peer's chain if finality-based fork choice prefers it.

        Fork choice is BFT finality, not length: a finalized block is never
        reverted, higher finalized height wins, and only when finality ties does
        length (then the commit-count / lower-hash tiebreak) decide (see
        :meth:`Blockchain.replace_chain`).
        """
        sender_id = peer.mid.hex()
        try:
            candidate = wire_to_chain(payload.wire)
        except ValueError:
            self.logger.warning("dropping malformed chain from %s", sender_id)
            return

        if self.blockchain.replace_chain(candidate):
            self.logger.info(
                "adopted preferred chain (height %d) from %s",
                len(self.blockchain.blocks),
                sender_id,
            )
        else:
            self.logger.info(
                "kept our chain; candidate from %s was not preferred", sender_id
            )

    @lazy_wrapper(CommitMessage)
    def on_commit(self, peer: Peer, payload: CommitMessage) -> None:
        """Handle a validator's commit vote: verify, attach, and relay if new.

        A commit is accepted only when it is a genuine Ed25519 signature over the
        referenced block's header by a **current validator** for that block (both
        checks in :meth:`_apply_commit`). To keep commits flooding through a
        partial mesh without a broadcast storm, we relay a commit to our peers
        **only the first time we see it** — a duplicate (a signer already on the
        block) is dropped and not re-sent, so the gossip terminates.
        """
        sender_id = peer.mid.hex()  # identity by public key material, not address
        try:
            commit = wire_to_commit(payload.wire)
        except ValueError:
            self.logger.warning("dropping malformed commit from %s", sender_id)
            return

        if self._apply_commit(commit["block_hash"], commit["signer"], commit["signature"]):
            # Newly attached: gossip it onward so the rest of the mesh converges.
            self._broadcast_commit(
                commit["block_hash"], commit["signer"], commit["signature"]
            )

    @lazy_wrapper(ViewChangeMessage)
    def on_view_change(self, peer: Peer, payload: ViewChangeMessage) -> None:
        """Handle a validator's view-change vote: verify, collect, relay, maybe advance.

        A vote counts only when it is a genuine signature over
        :func:`~blockchain.block.view_change_signing_bytes` by a **current validator**
        for that height (both checks in :meth:`_apply_view_change`). As with commits,
        we relay a newly-seen vote once so it floods the mesh without a storm, then
        check whether the votes for this ``(height, view)`` now form a quorum — in
        which case, if we are the scheduled proposer for that view, we propose.
        """
        sender_id = peer.mid.hex()  # identity by public key material, not address
        try:
            vc = wire_to_view_change(payload.wire)
        except ValueError:
            self.logger.warning("dropping malformed view-change from %s", sender_id)
            return

        if self._apply_view_change(vc["height"], vc["view"], vc["signer"], vc["signature"]):
            self._broadcast_view_change(
                vc["height"], vc["view"], vc["signer"], vc["signature"]
            )
            self._maybe_advance_view(vc["height"], vc["view"])

    # ------------------------------------------------------- view-change round

    def request_view_change(self, height: int | None = None):
        """Vote to rotate the proposer for ``height`` — the "my proposer timed out" signal.

        In a live deployment a validator calls this when the scheduled proposer for
        the height it is waiting on has not delivered a block within a timeout; here
        it is invoked explicitly (by the demo/tests) to simulate that stall. The
        node signs a view-change vote for the *next* view at ``height`` (default: the
        height it is currently trying to extend), records and broadcasts it, and — if
        its own vote already completes a quorum — advances. Only current validators
        can vote; a non-validator call is a no-op.
        """
        if height is None:
            height = len(self.blockchain.blocks)
        if self.validator_pubkey not in self.blockchain.validator_set(height):
            return  # not a validator for this height — nothing to vote with
        target_view = self._next_view(height)
        signature = sign(self.producer_key, view_change_signing_bytes(height, target_view))
        if self._apply_view_change(height, target_view, self.validator_pubkey, signature):
            self._broadcast_view_change(height, target_view, self.validator_pubkey, signature)
            self._maybe_advance_view(height, target_view)

    def _next_view(self, height: int) -> int:
        """The next view to try at ``height``: one past the highest we've voted for.

        Keeps successive :meth:`request_view_change` calls monotonic — each stall
        escalates to the next view rather than re-voting the same one — so a chain of
        stalled proposers is rotated past one at a time.
        """
        voted = [view for (h, view) in self._view_change_votes if h == height]
        return (max(voted) + 1) if voted else 1

    def _apply_view_change(self, height: int, view: int, signer: str, signature: str) -> bool:
        """Verify and record one view-change vote; return ``True`` iff newly recorded.

        A vote counts only when it is (1) a genuine signature over the
        ``(height, view)`` view-change statement and (2) cast by a validator in that
        height's prefix-derived set. Forged or non-validator votes are ignored, and a
        signer already recorded for this ``(height, view)`` is a duplicate that
        neither re-records nor re-broadcasts (so it cannot fuel a gossip loop).
        """
        if view <= 0:
            return False
        if not verify(signer, view_change_signing_bytes(height, view), signature):
            self.logger.warning("dropping view-change with bad signature at h=%d", height)
            return False
        if signer not in self.blockchain.validator_set(height):
            self.logger.warning("dropping view-change from non-validator %s", signer[:12])
            return False
        votes = self._view_change_votes.setdefault((height, view), {})
        if signer in votes:
            return False  # duplicate: already counted, don't re-broadcast
        votes[signer] = signature
        return True

    def _broadcast_view_change(self, height: int, view: int, signer: str, signature: str) -> int:
        """Gossip one view-change vote to every known peer; return the peer count."""
        wire = view_change_to_wire(height, view, signer, signature)
        peers = self.get_peers()
        for peer in peers:
            self.ez_send(peer, ViewChangeMessage(wire))
        return len(peers)

    def _maybe_advance_view(self, height: int, view: int) -> None:
        """If a quorum has voted to advance to ``(height, view)``, let its proposer act.

        The advance is legitimate only once ``quorum_size(N)`` validators have voted
        for this exact ``(height, view)`` — the same bar :meth:`Blockchain.is_valid_chain`
        enforces on the resulting block. When it is reached, and only if *this* node
        is the validator the schedule assigns to ``(height, view)`` and the height is
        still unfilled, this node produces a ``view``-stamped block carrying the
        quorum of votes as its justification. Every other validator simply records
        the advance and waits for that block, so exactly one block is produced.
        """
        if height in self._view_advanced:
            return  # already produced (or saw produced) an advanced-view block here
        if len(self.blockchain.blocks) != height:
            return  # height already filled; nothing to propose
        validators = self.blockchain.validator_set(height)
        votes = self._view_change_votes.get((height, view), {})
        if len(votes) < quorum_size(len(validators)):
            return  # not yet a quorum of view-change votes
        if self.validator_pubkey != scheduled_proposer(validators, height, view):
            return  # not our turn under the advanced view — just wait for the block
        self._view_advanced.add(height)
        block = self.mine_and_broadcast_block(view=view, view_change_messages=dict(votes))
        self.logger.info(
            "VIEW-CHANGE: proposed block %d in view %d after proposer stall", height, view
        )
        return block

    # ---------------------------------------------------------------- helpers

    def _already_seen(self, tx) -> bool:
        """True if ``tx`` is already pooled or already committed to the chain."""
        if any(pending.hash == tx.hash for pending in self.blockchain.mempool):
            return True
        for block in self.blockchain.blocks:
            if any(committed.hash == tx.hash for committed in block.transactions):
                return True
        return False

    def _try_append_block(self, block) -> bool:
        """Append ``block`` only if the result is still a valid chain.

        Reuses the core's own ``is_valid_chain`` as the single source of truth
        for validity (link integrity, index, Merkle root, proof-of-work). We
        tentatively append and roll back on rejection, so no partial state leaks
        and the transport never reimplements consensus rules.
        """
        self.blockchain.blocks.append(block)
        if self.blockchain.is_valid_chain():
            # Drop any pooled transactions this block just committed.
            committed = {tx.hash for tx in block.transactions}
            self.blockchain.mempool = [
                tx for tx in self.blockchain.mempool if tx.hash not in committed
            ]
            return True
        self.blockchain.blocks.pop()
        return False

    # ----------------------------------------------------------- commit round

    def _find_block_by_hash(self, block_hash: str):
        """The block in our chain with this hash, or ``None`` if we don't have it.

        Commits reference a block by hash (a stable id, since commit signatures
        live outside the hash). We can only attach a commit to a block we actually
        hold; a commit for an unknown block is dropped (the block gossip and our
        own commit round re-converge once we receive it).
        """
        for block in self.blockchain.blocks:
            if block.hash == block_hash:
                return block
        return None

    def _commit_if_validator(self, block) -> None:
        """Cast and broadcast this node's commit vote for ``block``, if eligible.

        We vote only when we are a **current validator** for the block (our pubkey
        is in the prefix-derived validator set) and have not already committed it.
        Ed25519 is deterministic, so re-committing would be a no-op anyway; the
        guard just avoids re-broadcasting. Genesis needs no commits.
        """
        if block.index == 0:
            return
        validators = self.blockchain.validator_set(block.index)
        if self.validator_pubkey not in validators:
            return  # not a validator for this block — nothing to vote with
        if self.validator_pubkey in block.commit_signatures:
            return  # already voted; don't re-broadcast (avoids a storm)

        block.add_commit_signature(self.producer_key)
        self._broadcast_commit(
            block.hash,
            self.validator_pubkey,
            block.commit_signatures[self.validator_pubkey],
        )
        self._note_if_finalized(block)

    def _apply_commit(self, block_hash: str, signer: str, signature: str) -> bool:
        """Verify and attach one commit vote; return ``True`` iff newly attached.

        A commit counts only when it is (1) a genuine Ed25519 signature over the
        block's header and (2) cast by a validator in that block's prefix-derived
        set. Non-validator or forged commits are ignored, and a signer already on
        the block is a duplicate that neither re-attaches nor re-broadcasts (so it
        cannot double-count and cannot fuel a gossip loop). On a newly attached
        commit we re-check finality.
        """
        block = self._find_block_by_hash(block_hash)
        if block is None:
            return False  # we don't hold this block yet
        if signer in block.commit_signatures:
            return False  # duplicate: already counted, don't re-broadcast
        if not verify(signer, block.signing_bytes(), signature):
            self.logger.warning("dropping commit with bad signature for %s", block_hash[:12])
            return False
        if signer not in self.blockchain.validator_set(block.index):
            self.logger.warning("dropping commit from non-validator %s", signer[:12])
            return False

        block.commit_signatures[signer] = signature
        self._note_if_finalized(block)
        return True

    def _broadcast_commit(self, block_hash: str, signer: str, signature: str) -> int:
        """Gossip one commit vote to every known peer; return the peer count."""
        wire = commit_to_wire(block_hash, signer, signature)
        peers = self.get_peers()
        for peer in peers:
            self.ez_send(peer, CommitMessage(wire))
        return len(peers)

    def _note_if_finalized(self, block) -> None:
        """Log a block reaching quorum finality exactly once, with its commit count."""
        if block.hash in self._finalized_announced:
            return
        if not self.blockchain.is_final(block):
            return
        self._finalized_announced.add(block.hash)
        validators = self.blockchain.validator_set(block.index)
        commits = len(block.commit_signers() & validators)
        self.logger.info(
            "FINALIZED block %d (%s): %d/%d validator commits",
            block.index,
            block.hash[:12],
            commits,
            len(validators),
        )
