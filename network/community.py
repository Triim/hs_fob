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

- ``AttestationMessage`` (msg id 1) — one attestation transaction.
- ``BlockMessage`` (msg id 2) — one whole produced block.
- ``ChainRequestMessage`` (msg id 3) — "send me your whole chain", emitted when a
  received block does not extend our tip (a fork).
- ``ChainResponseMessage`` (msg id 4) — one whole chain, for fork choice.

Fork choice is deliberately naïve for the MVP: on any divergence a node asks the
sender for its *entire* chain and runs :meth:`Blockchain.replace_chain` (longest
valid chain wins). A production system would exchange headers and sync only the
missing suffix; that optimization is out of scope here.

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
from blockchain.blockchain import Blockchain
from reputation.derive import derive_registry
from reputation.genesis import GENESIS_AUTHORITY_KEYS
from network.wire import (
    block_to_wire,
    chain_to_wire,
    tx_to_wire,
    wire_to_block,
    wire_to_chain,
    wire_to_tx,
)


@dataclass
class AttestationMessage(DataClassPayload[1]):
    """A single attestation transaction, carried as its wire JSON string."""

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
            genesis=getattr(settings, "genesis", None)
        )
        # The key this node signs blocks with. Falls back to the shared genesis
        # authority so blocks produced here pass Proof-of-Authority validation.
        self.producer_key = (
            getattr(settings, "producer_key", None)
            or GENESIS_AUTHORITY_KEYS["genesis-authority"][0]
        )

        # Map each message type to its handler. The wire string is decoded and
        # validated inside the handler, never here.
        self.add_message_handler(AttestationMessage, self.on_attestation)
        self.add_message_handler(BlockMessage, self.on_block)
        self.add_message_handler(ChainRequestMessage, self.on_chain_request)
        self.add_message_handler(ChainResponseMessage, self.on_chain_response)

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

    # ------------------------------------------------------------------ send

    def broadcast_attestation(self, tx) -> int:
        """Send an attestation to every currently-known peer.

        Returns the number of peers it was sent to, so callers/tests can see the
        fan-out. Encoding goes through the wire bridge so the bytes on the
        network match exactly what the core hashed.
        """
        wire = tx_to_wire(tx)
        peers = self.get_peers()
        for peer in peers:
            self.ez_send(peer, AttestationMessage(wire))
        return len(peers)

    def mine_and_broadcast_block(self):
        """Mine the local mempool into a block and gossip it to all peers.

        Returns the produced block. Uses the chain's own ``add_block``, signing
        it with this node's producer key so it satisfies Proof-of-Authority, then
        broadcasts the result — so every node runs the same validation on receipt.
        """
        block = self.blockchain.add_block(producer_key=self.producer_key)
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

    @lazy_wrapper(AttestationMessage)
    def on_attestation(self, peer: Peer, payload: AttestationMessage) -> None:
        """Handle an incoming attestation: validate, then pool it if new."""
        sender_id = peer.mid.hex()  # identity by public key material, not address
        try:
            tx = wire_to_tx(payload.wire)
        except ValueError:
            self.logger.warning("dropping malformed attestation from %s", sender_id)
            return

        if not is_attestation(tx):
            self.logger.warning("dropping non-attestation tx from %s", sender_id)
            return

        if self._already_seen(tx):
            return  # idempotent: gossip can deliver the same tx many times

        self.blockchain.add_transaction(tx)
        self.logger.info("pooled attestation %s from %s", tx.hash[:12], sender_id)

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
        """Adopt the peer's chain if fork choice prefers it (longest valid wins)."""
        sender_id = peer.mid.hex()
        try:
            candidate = wire_to_chain(payload.wire)
        except ValueError:
            self.logger.warning("dropping malformed chain from %s", sender_id)
            return

        if self.blockchain.replace_chain(candidate):
            self.logger.info(
                "adopted longer chain (height %d) from %s",
                len(self.blockchain.blocks),
                sender_id,
            )
        else:
            self.logger.info(
                "kept our chain; candidate from %s was not preferred", sender_id
            )

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
