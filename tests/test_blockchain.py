"""Tests for the Blockchain: producing, linking, and Proof-of-Authority validation."""

import unittest

from attestation.aggregator import make_certificate
from attestation.attestation import make_attestation
from blockchain.block import view_change_signing_bytes
from blockchain.blockchain import AUTHORITY_THRESHOLD, Blockchain, quorum_size
from blockchain.transaction import Transaction
from crypto.keys import generate_keypair, keypair_from_seed, sign
from reputation.genesis import GENESIS_AUTHORITY_KEYS

# The reproducible genesis authority: its private key signs blocks, its public
# key carries consensus weight, so blocks it produces pass PoA validation.
AUTHORITY_KEY, AUTHORITY_PUBKEY = GENESIS_AUTHORITY_KEYS["genesis-authority"]

# A stand-in submission hash (hex) every review/certificate in these tests binds
# to. Attestations and the certificates that re-derive from them share it, so the
# per-submission scope lines up.
SUB = "5ab" + "0" * 61


def _quorum_view_change(chain, height, view, priv_by_pub) -> dict:
    """A quorum of validator view-change votes justifying ``view`` at ``height``.

    Signs :func:`view_change_signing_bytes` with the first ``quorum_size(N)``
    validators (by pubkey order) — exactly the justification
    :meth:`Blockchain.is_valid_chain` requires for a block produced in a view
    above 0. Returned as the ``pubkey -> signature`` map ``add_block`` accepts.
    """
    ordered = sorted(chain.validator_set(height))
    message = view_change_signing_bytes(height, view)
    return {
        pub: sign(priv_by_pub[pub], message)
        for pub in ordered[: quorum_size(len(ordered))]
    }


def propose_scheduled(chain, priv_by_pub, view: int = 0):
    """Append a block by the validator the schedule assigns to the next height/view.

    Resolves the scheduled proposer for the tip's height, signs with its key, and
    (for ``view > 0``) attaches a quorum of view-change votes so the advance is
    justified. This is how honest producers are chosen once the schedule is
    enforced, so tests build valid chains without hard-coding whose turn it is.
    """
    height = len(chain.blocks)
    proposer = chain.proposer_for(height, view)
    vc = _quorum_view_change(chain, height, view, priv_by_pub) if view > 0 else None
    return chain.add_block(producer_key=priv_by_pub[proposer], view=view, view_change_messages=vc)


def propose_as(chain, producer_priv, producer_pub, priv_by_pub):
    """Append a block produced by a SPECIFIC validator, advancing the view to its turn.

    Picks the smallest view whose scheduled proposer is ``producer_pub`` and, when
    that view is above 0, attaches the quorum view-change justification for it — so
    a chosen validator can produce even when it is not the natural (view-0) leader
    for this height. Used by tests whose narrative fixes *who* produces a block.
    """
    height = len(chain.blocks)
    ordered = sorted(chain.validator_set(height))
    view = (ordered.index(producer_pub) - height) % len(ordered)
    vc = _quorum_view_change(chain, height, view, priv_by_pub) if view > 0 else None
    return chain.add_block(producer_key=producer_priv, view=view, view_change_messages=vc)


def tx(i: int) -> Transaction:
    """A valid, signed participant transaction for structural tests.

    Consensus is fail-closed: a plain unknown-payload transaction would itself
    invalidate the chain, so structural tests (which only need a transaction to
    *exist* inside a block) use the simplest thing that actually validates — a
    signed attestation. ``item_index=i`` keeps successive txs distinct so their
    hashes differ, exactly as the old ``{"i": i}`` filler did.
    """
    priv, pub = generate_keypair()
    att = make_attestation(pub, "subject", "rubric", i, True, 1, SUB)
    att.sign(priv)
    return att


def build_chain(num_blocks: int = 3) -> Blockchain:
    chain = Blockchain()
    for b in range(num_blocks):
        chain.add_transaction(tx(2 * b))
        chain.add_transaction(tx(2 * b + 1))
        chain.add_block(producer_key=AUTHORITY_KEY)
    return chain


class ChainStructureTests(unittest.TestCase):
    def test_starts_with_only_genesis(self):
        chain = Blockchain()
        self.assertEqual(len(chain.blocks), 1)
        self.assertEqual(chain.blocks[0].index, 0)
        self.assertEqual(chain.blocks[0].previous_hash, "0" * 64)

    def test_add_block_produces_links_signs_and_clears_mempool(self):
        chain = Blockchain()
        chain.add_transaction(tx(1))
        block = chain.add_block(producer_key=AUTHORITY_KEY)

        self.assertEqual(len(chain.blocks), 2)
        self.assertEqual(block.index, 1)
        self.assertEqual(block.previous_hash, chain.blocks[0].hash)
        # PoA replaces PoW: the block is signed by its producer, not mined.
        self.assertEqual(block.producer, AUTHORITY_PUBKEY)
        self.assertTrue(block.verify_producer_signature())
        self.assertEqual(chain.mempool, [])  # emptied after production

    def test_produced_block_ignores_later_mempool_activity(self):
        """A block snapshots the mempool at production time, so transactions pooled
        afterwards do not retroactively join it."""
        chain = Blockchain()
        chain.add_transaction(tx(1))
        block = chain.add_block(producer_key=AUTHORITY_KEY)
        self.assertEqual(len(block.transactions), 1)

        chain.add_transaction(tx(2))  # pooled after the block was produced
        self.assertEqual(len(block.transactions), 1)  # unchanged
        self.assertEqual(len(chain.mempool), 1)


class ValidationTests(unittest.TestCase):
    def test_fresh_chain_is_valid(self):
        self.assertTrue(build_chain(3).is_valid_chain())

    def test_tampering_past_transaction_invalidates_chain(self):
        """Editing a transaction in an earlier block breaks the next block's
        previous-hash link, so the chain no longer validates."""
        chain = build_chain(3)
        self.assertTrue(chain.is_valid_chain())

        chain.blocks[1].transactions[0].payload = {"i": -1}  # tamper block 1

        self.assertFalse(chain.is_valid_chain())

    def test_tampering_last_block_invalidates_via_signature(self):
        """Editing the last block's transaction changes its header, so the
        producer's signature no longer verifies (PoA's tamper check, replacing
        the old proof-of-work one)."""
        chain = build_chain(2)
        self.assertTrue(chain.is_valid_chain())

        chain.blocks[-1].transactions[0].payload = {"i": -1}  # tamper tip

        self.assertFalse(chain.is_valid_chain())

    def test_breaking_a_link_invalidates_chain(self):
        chain = build_chain(3)
        chain.blocks[2].previous_hash = "f" * 64
        self.assertFalse(chain.is_valid_chain())


class ProofOfAuthorityTests(unittest.TestCase):
    def _chain_with_block_by(self, producer_key) -> Blockchain:
        chain = Blockchain()
        chain.add_transaction(tx(1))
        chain.add_block(producer_key=producer_key)
        return chain

    def test_genesis_authority_block_validates(self):
        """A block signed by a genesis authority is accepted."""
        self.assertTrue(self._chain_with_block_by(AUTHORITY_KEY).is_valid_chain())

    def test_non_authority_producer_is_rejected(self):
        """A block signed by a key with zero reputation is rejected — it is validly
        signed but its producer is not an authority."""
        stranger, _ = generate_keypair()  # a real key, but no genesis weight
        chain = self._chain_with_block_by(stranger)

        self.assertTrue(chain.blocks[-1].verify_producer_signature())  # signature is fine
        self.assertFalse(chain.is_valid_chain())                       # authority is not

    def test_bad_producer_signature_is_rejected(self):
        """A block whose producer signature does not verify is rejected."""
        chain = self._chain_with_block_by(AUTHORITY_KEY)
        chain.blocks[-1].producer_signature = "00" * 64  # corrupt the signature

        self.assertFalse(chain.is_valid_chain())

    def test_unproduced_block_is_rejected(self):
        """A block that was never signed at all is rejected under PoA."""
        chain = self._chain_with_block_by(None)  # add_block without a key

        self.assertEqual(chain.blocks[-1].producer, "")
        self.assertFalse(chain.is_valid_chain())

    def test_authority_is_judged_by_prefix_not_the_block_itself(self):
        """A producer who would only become an authority *because of their own
        block* is still rejected — authority is derived from blocks 0..N-1.

        A fresh key has no genesis weight. We hand it enough *genuinely earned*
        certificate rewards to cross the threshold, then have it produce a *later*
        block: that later block validates. But when the very block that would earn
        it authority is also the one it produces, the prefix (which excludes that
        block) still shows zero weight, so it is refused.

        Certificates are now re-derived by consensus, so each must be legitimate:
        a weighty attester (given consensus weight by this test's own anchor)
        positively attests the newcomer against a distinct rubric, and only then
        does the certificate for that rubric clear ``CERTIFICATE_THRESHOLD``. The
        attestations sit in an *earlier* block than the certificates, so each
        certificate re-derives from a prefix that already contains its support.
        """
        from reputation.derive import CERTIFICATE_REWARD

        # How many certificate rewards it takes to reach the authority threshold.
        needed = -(-AUTHORITY_THRESHOLD // CERTIFICATE_REWARD)  # ceil division

        newcomer, newcomer_pub = generate_keypair()
        att_priv, att_pub = generate_keypair()
        # This test's own anchor: the authority can produce blocks, and the
        # attester carries enough consensus weight (300 > threshold) that a single
        # positive attestation legitimately certifies the newcomer.
        anchor = {
            AUTHORITY_PUBKEY: {"consensus": 100},
            att_pub: {"consensus": 300},
        }

        def earned(rubric_root):
            """A (signed attestation, certificate) pair that legitimately certifies
            the newcomer in the 'consensus' domain against ``rubric_root``."""
            att = make_attestation(
                att_pub, newcomer_pub, rubric_root, 0, True, 1, SUB, domain="consensus"
            )
            att.sign(att_priv)
            cert = make_certificate(newcomer_pub, rubric_root, "consensus", SUB, [att_pub])
            return att, cert

        # Distinct rubrics so each certificate has a distinct identity (no double-issue).
        pairs = [earned(f"rubric-{k}") for k in range(needed)]
        # The founding validators' keys, so each block can be produced by the one
        # the schedule assigns; the newcomer is added once its authority is earned.
        priv_by_pub = {AUTHORITY_PUBKEY: AUTHORITY_KEY, att_pub: att_priv}

        # Case A — the newcomer produces the block that would grant its authority.
        # The certificates are legitimate (their support sits in block 1), but the
        # newcomer's own authority is judged against the prefix, which excludes the
        # very block crediting it — and it is not even in the schedule yet, so the
        # block is rejected.
        chain = Blockchain(genesis=anchor)
        for att, _ in pairs:
            chain.add_transaction(att)
        propose_scheduled(chain, priv_by_pub)        # block 1: the attestations
        for _, cert in pairs:
            chain.add_transaction(cert)
        chain.add_block(producer_key=newcomer)       # block 2: the certificates, BY the newcomer
        self.assertFalse(chain.is_valid_chain())

        # Case B — the same rewards are committed by a scheduled validator first,
        # and only in a *later* block does the newcomer produce. Now the prefix
        # already credits it (making it a validator in the schedule), so its block
        # — produced in the view that schedules it — validates.
        chain2 = Blockchain(genesis=anchor)
        for att, _ in pairs:
            chain2.add_transaction(att)
        propose_scheduled(chain2, priv_by_pub)       # block 1: the attestations
        for _, cert in pairs:
            chain2.add_transaction(cert)
        propose_scheduled(chain2, priv_by_pub)       # block 2: the certificates
        chain2.add_transaction(tx(1))
        priv_by_pub[newcomer_pub] = newcomer         # newcomer is now an authority
        propose_as(chain2, newcomer, newcomer_pub, priv_by_pub)  # block 3, by the newcomer
        self.assertTrue(chain2.is_valid_chain())

    def test_slash_affects_authority_only_after_its_block(self):
        """Slashing a producer below threshold gates only *later* blocks (prefix).

        A slash is now evidence-based and quorum-approved: block 1 carries the
        authority's *equivocation* (two conflicting attestations it signed), block
        2 the quorum-approved slash of that authority's consensus weight (still
        valid — the slash's own producer is judged against the pre-slash prefix),
        and a block 3 by the same, now-slashed authority is judged against a prefix
        that includes the slash, so it is rejected.
        """
        from reputation.genesis import CONSENSUS_DOMAIN
        from reputation.slashing import approve_slash, make_slash

        # Two validators so a slash quorum is a genuine peer decision (quorum
        # of N=2 is 2): the authority under review plus a second validator.
        v2_key, v2_pub = keypair_from_seed(bytes.fromhex("02" * 32))
        anchor = {
            AUTHORITY_PUBKEY: {CONSENSUS_DOMAIN: 100},
            v2_pub: {CONSENSUS_DOMAIN: 100},
        }
        priv_by_pub = {AUTHORITY_PUBKEY: AUTHORITY_KEY, v2_pub: v2_key}
        chain = Blockchain(genesis=anchor)

        # Block 1: the authority equivocates — two contradictory verdicts on one
        # claim, each validly signed by it. Produced by the scheduled validator.
        yes = make_attestation(AUTHORITY_PUBKEY, "s", "r", 0, True, 1, SUB, CONSENSUS_DOMAIN)
        yes.sign(AUTHORITY_KEY)
        no = make_attestation(AUTHORITY_PUBKEY, "s", "r", 0, False, 1, SUB, CONSENSUS_DOMAIN)
        no.sign(AUTHORITY_KEY)
        chain.add_transaction(yes)
        chain.add_transaction(no)
        propose_scheduled(chain, priv_by_pub)
        self.assertTrue(chain.is_valid_chain())

        # Block 2: a quorum (both validators) approve slashing the authority's
        # consensus weight to 0, referencing the on-chain equivocation. The slash's
        # own producer is the scheduled validator, judged against the pre-slash prefix.
        evidence = sorted([yes.hash, no.hash])
        approvals = dict(
            approve_slash(k, AUTHORITY_PUBKEY, CONSENSUS_DOMAIN, 100, evidence)
            for k in (AUTHORITY_KEY, v2_key)
        )
        slash = make_slash(AUTHORITY_PUBKEY, CONSENSUS_DOMAIN, evidence, approvals, amount=100)
        chain.add_transaction(slash)
        propose_scheduled(chain, priv_by_pub)
        self.assertTrue(chain.is_valid_chain())

        # Block 3: the now-slashed authority (consensus weight 0) is no longer even
        # in the validator set, so it can neither be scheduled nor produce — a block
        # it signs is judged against a prefix that includes the slash and rejected.
        chain.add_transaction(tx(1))
        chain.add_block(producer_key=AUTHORITY_KEY)
        self.assertFalse(chain.is_valid_chain())

    def test_fabricated_slash_is_rejected(self):
        """Fail-closed: a slash whose evidence isn't on-chain invalidates the chain."""
        from reputation.genesis import CONSENSUS_DOMAIN
        from reputation.slashing import approve_slash, make_slash

        offender_key, offender = keypair_from_seed(bytes.fromhex("0f" * 32))
        anchor = {
            AUTHORITY_PUBKEY: {CONSENSUS_DOMAIN: 100},
            offender: {"bio": 100},
        }
        chain = Blockchain(genesis=anchor)
        # Evidence hashes reference transactions that never existed.
        evidence = sorted(["dead" * 16, "beef" * 16])
        approvals = dict([approve_slash(AUTHORITY_KEY, offender, "bio", 40, evidence)])
        chain.add_transaction(make_slash(offender, "bio", evidence, approvals, amount=40))
        chain.add_block(producer_key=AUTHORITY_KEY)

        self.assertFalse(chain.is_valid_chain())

    def test_slash_without_quorum_is_rejected(self):
        """Fail-closed: real evidence but no quorum approval invalidates the chain."""
        from reputation.genesis import CONSENSUS_DOMAIN
        from reputation.slashing import make_slash

        offender_key, offender = keypair_from_seed(bytes.fromhex("0f" * 32))
        anchor = {
            AUTHORITY_PUBKEY: {CONSENSUS_DOMAIN: 100},
            offender: {"bio": 100},
        }
        chain = Blockchain(genesis=anchor)
        yes = make_attestation(offender, "s", "r", 0, True, 1, SUB, "bio")
        yes.sign(offender_key)
        no = make_attestation(offender, "s", "r", 0, False, 1, SUB, "bio")
        no.sign(offender_key)
        chain.add_transaction(yes)
        chain.add_transaction(no)
        chain.add_block(producer_key=AUTHORITY_KEY)
        evidence = sorted([yes.hash, no.hash])
        # No approvals at all — below quorum_size(1) = 1.
        chain.add_transaction(make_slash(offender, "bio", evidence, {}, amount=40))
        chain.add_block(producer_key=AUTHORITY_KEY)

        self.assertFalse(chain.is_valid_chain())

    def test_slash_of_non_offenders_evidence_is_rejected(self):
        """Fail-closed: evidence signed by someone other than the offender is invalid."""
        from reputation.genesis import CONSENSUS_DOMAIN
        from reputation.slashing import approve_slash, make_slash

        offender_key, offender = keypair_from_seed(bytes.fromhex("0f" * 32))
        other_key, other = keypair_from_seed(bytes.fromhex("03" * 32))
        anchor = {
            AUTHORITY_PUBKEY: {CONSENSUS_DOMAIN: 100},
            offender: {"bio": 100},
        }
        chain = Blockchain(genesis=anchor)
        # The conflicting attestations are OTHER's, but the slash names OFFENDER.
        yes = make_attestation(other, "s", "r", 0, True, 1, SUB, "bio")
        yes.sign(other_key)
        no = make_attestation(other, "s", "r", 0, False, 1, SUB, "bio")
        no.sign(other_key)
        chain.add_transaction(yes)
        chain.add_transaction(no)
        chain.add_block(producer_key=AUTHORITY_KEY)
        evidence = sorted([yes.hash, no.hash])
        approvals = dict([approve_slash(AUTHORITY_KEY, offender, "bio", 40, evidence)])
        chain.add_transaction(make_slash(offender, "bio", evidence, approvals, amount=40))
        chain.add_block(producer_key=AUTHORITY_KEY)

        self.assertFalse(chain.is_valid_chain())


class TransactionSignatureTests(unittest.TestCase):
    """The chain requires valid author signatures on participant transactions."""

    def _chain_with(self, *transactions) -> Blockchain:
        chain = Blockchain()
        for t in transactions:
            chain.add_transaction(t)
        chain.add_block(producer_key=AUTHORITY_KEY)
        return chain

    def test_rejects_unsigned_attestation(self):
        """A block containing an unsigned attestation makes the chain invalid."""
        from attestation.attestation import make_attestation

        att = make_attestation("attester-pub", "subject", "rubric", 0, True, 1, SUB)
        # not signed
        chain = self._chain_with(att)

        self.assertFalse(chain.is_valid_chain())

    def test_accepts_signed_attestation(self):
        """The same attestation, signed with the sender's key, validates."""
        from attestation.attestation import make_attestation

        priv, pub = generate_keypair()
        att = make_attestation(pub, "subject", "rubric", 0, True, 1, SUB)
        att.sign(priv)
        chain = self._chain_with(att)

        self.assertTrue(chain.is_valid_chain())

    def test_rejects_attestation_signed_by_wrong_key(self):
        """sender must be the signer: a signature by a different key is rejected."""
        from attestation.attestation import make_attestation

        _, pub = generate_keypair()
        other_priv, _ = generate_keypair()
        att = make_attestation(pub, "subject", "rubric", 0, True, 1, SUB)
        att.sign(other_priv)  # signed, but not by `pub`
        chain = self._chain_with(att)

        self.assertTrue(att.is_signed())         # a signature is present…
        self.assertFalse(chain.is_valid_chain())  # …but it does not verify against sender

    def test_rejects_unsigned_submission(self):
        from attestation.submission import make_submission

        sub = make_submission("subject-pub", "domain", "rubric", "Title", "aa")
        chain = self._chain_with(sub)

        self.assertFalse(chain.is_valid_chain())

    def test_certificate_is_exempt_and_validates_unsigned(self):
        """A certificate is protocol-generated: it carries no author signature, yet
        a *legitimately earned* one still validates.

        The certificate is never individually signed (no ``sender`` key), so it is
        exempt from the participant-signature rule. It is not exempt from being
        real, though — consensus re-derives it — so its support (a signed
        attestation from a weighty attester) is committed in an earlier block.
        """
        priv, pub = generate_keypair()
        anchor = {AUTHORITY_PUBKEY: {"consensus": 100}, pub: {"bioinformatics": 300}}
        chain = Blockchain(genesis=anchor)

        att = make_attestation(pub, "subject", "rubric", 0, True, 1, SUB, domain="bioinformatics")
        att.sign(priv)
        chain.add_transaction(att)
        chain.add_block(producer_key=AUTHORITY_KEY)  # block 1: the supporting attestation

        cert = make_certificate("subject", "rubric", "bioinformatics", SUB, [pub])
        self.assertFalse(cert.is_signed())  # certificates are never individually signed
        chain.add_transaction(cert)
        chain.add_block(producer_key=AUTHORITY_KEY)  # block 2: the certificate

        self.assertTrue(chain.is_valid_chain())

    def test_unknown_type_transaction_invalidates_chain(self):
        """Consensus is fail-closed: a transaction that is neither a known signed
        participant type nor a re-derivable certificate is rejected outright, so an
        unrecognised payload cannot ride into a signed block unchecked."""
        unknown = Transaction(sender="peer", payload={"i": 1})
        chain = self._chain_with(unknown)
        self.assertFalse(chain.is_valid_chain())

    def test_non_dict_payload_transaction_invalidates_chain(self):
        """A non-dict payload is unrecognised too, and fails closed rather than
        being waved through."""
        malformed = Transaction(sender="peer", payload="oops")
        chain = self._chain_with(malformed)
        self.assertFalse(chain.is_valid_chain())


class CertificateValidationTests(unittest.TestCase):
    """Certificates are deterministic protocol events: consensus re-derives every
    on-chain certificate from the prefix and forbids re-issuing one."""

    DOMAIN = "bioinformatics"

    def setUp(self):
        # A weighty attester (300 > CERTIFICATE_THRESHOLD) plus a producing
        # authority, declared by this test's own anchor.
        self.att_priv, self.att_pub = generate_keypair()
        self.anchor = {
            AUTHORITY_PUBKEY: {"consensus": 100},
            self.att_pub: {self.DOMAIN: 300},
        }

    def _attestation(self, subject, rubric_root):
        att = make_attestation(
            self.att_pub, subject, rubric_root, 0, True, 1, SUB, domain=self.DOMAIN
        )
        att.sign(self.att_priv)
        return att

    def test_forged_certificate_invalidates_chain(self):
        """A certificate minted with no genuine support (threshold unmet) is rejected,
        so an authority cannot inflate reputation by fiat."""
        chain = Blockchain(genesis=self.anchor)
        # No attestation anywhere: the certificate's real weighted support is 0.
        cert = make_certificate("subject", "rubric", self.DOMAIN, SUB, [self.att_pub])
        chain.add_transaction(cert)
        chain.add_block(producer_key=AUTHORITY_KEY)

        self.assertFalse(chain.is_valid_chain())

    def test_certificate_crediting_wrong_attesters_invalidates_chain(self):
        """Even with enough support, a certificate whose ``granted_by`` does not
        match the real positive attesters is rejected."""
        chain = Blockchain(genesis=self.anchor)
        chain.add_transaction(self._attestation("subject", "rubric"))
        chain.add_block(producer_key=AUTHORITY_KEY)
        # Claims a different attester than the one who actually attested.
        cert = make_certificate("subject", "rubric", self.DOMAIN, SUB, ["someone-else"])
        chain.add_transaction(cert)
        chain.add_block(producer_key=AUTHORITY_KEY)

        self.assertFalse(chain.is_valid_chain())

    def test_duplicate_certificate_invalidates_chain(self):
        """The same certified claim cannot be issued twice: a second certificate
        with the same identity invalidates the chain (no double reward)."""
        chain = Blockchain(genesis=self.anchor)
        chain.add_transaction(self._attestation("subject", "rubric"))
        chain.add_block(producer_key=AUTHORITY_KEY)  # block 1: support

        cert = make_certificate("subject", "rubric", self.DOMAIN, SUB, [self.att_pub])
        chain.add_transaction(cert)
        chain.add_block(producer_key=AUTHORITY_KEY)  # block 2: first (legit) issue
        self.assertTrue(chain.is_valid_chain())

        dup = make_certificate("subject", "rubric", self.DOMAIN, SUB, [self.att_pub])
        chain.add_transaction(dup)
        chain.add_block(producer_key=AUTHORITY_KEY)  # block 3: re-issue of the same claim
        self.assertFalse(chain.is_valid_chain())

    def test_legitimately_earned_certificate_validates(self):
        """A certificate whose real support clears the threshold and whose
        ``granted_by`` matches the genuine attesters validates."""
        chain = Blockchain(genesis=self.anchor)
        chain.add_transaction(self._attestation("subject", "rubric"))
        chain.add_block(producer_key=AUTHORITY_KEY)  # block 1: support

        cert = make_certificate("subject", "rubric", self.DOMAIN, SUB, [self.att_pub])
        chain.add_transaction(cert)
        chain.add_block(producer_key=AUTHORITY_KEY)  # block 2: the certificate

        self.assertTrue(chain.is_valid_chain())


class RequiredItemCoverageConsensusTests(unittest.TestCase):
    """is_valid_chain re-derives every certificate under the SAME required-item
    coverage check certify() applies, so a certificate that clears the weighted
    threshold but leaves a required rubric item uncovered is rejected — while a
    certificate covering every required item validates."""

    DOMAIN = "bioinformatics"

    def setUp(self):
        # One weighty attester (300 > CERTIFICATE_THRESHOLD 250) plus the producing
        # authority. The single attester can cover several items; coverage needs only
        # one weight-bearing positive attester per required item.
        self.att_priv, self.att_pub = generate_keypair()
        self.anchor = {
            AUTHORITY_PUBKEY: {"consensus": 100},
            self.att_pub: {self.DOMAIN: 300},
        }

    def _att(self, item_index):
        att = make_attestation(
            self.att_pub, "subject", "rubric", item_index, True, 1, SUB, domain=self.DOMAIN
        )
        att.sign(self.att_priv)
        return att

    def test_uncovered_required_item_certificate_is_rejected(self):
        """Only item 0 is attested; the certificate declares items [0, 1] required,
        so item 1 is uncovered → the certificate is chain-invalid, even though its
        weighted support (300) clears the threshold."""
        chain = Blockchain(genesis=self.anchor)
        chain.add_transaction(self._att(0))  # item 1 left uncovered
        chain.add_block(producer_key=AUTHORITY_KEY)

        cert = make_certificate(
            "subject", "rubric", self.DOMAIN, SUB, [self.att_pub], required_items=[0, 1]
        )
        chain.add_transaction(cert)
        chain.add_block(producer_key=AUTHORITY_KEY)

        self.assertFalse(chain.is_valid_chain())

    def test_full_coverage_certificate_validates(self):
        """Both required items 0 and 1 are covered by the weight-bearing attester and
        support clears the threshold → the certificate validates."""
        chain = Blockchain(genesis=self.anchor)
        chain.add_transaction(self._att(0))
        chain.add_transaction(self._att(1))
        chain.add_block(producer_key=AUTHORITY_KEY)

        cert = make_certificate(
            "subject", "rubric", self.DOMAIN, SUB, [self.att_pub], required_items=[0, 1]
        )
        chain.add_transaction(cert)
        chain.add_block(producer_key=AUTHORITY_KEY)

        self.assertTrue(chain.is_valid_chain())


class CollusionCapConsensusTests(unittest.TestCase):
    """is_valid_chain re-derives every certificate under the SAME collusion cap
    certify() applies, so a certificate that clears CERTIFICATE_THRESHOLD only via
    an over-concentrated (>ALPHA) cross-attesting cluster is rejected — while a
    certificate carried by genuinely independent attesters validates."""

    DOMAIN = "bioinformatics"
    SUBJECT = "paying-subject"
    RUBRIC = "rubric-root"

    def setUp(self):
        # Three attesters at weight 100 each in DOMAIN (raw support 300 >
        # CERTIFICATE_THRESHOLD 250) plus the producing authority. Each also gets a
        # real keypair so their attestations carry a valid author signature.
        self.keys = {name: generate_keypair() for name in ("a", "b", "c")}
        self.anchor = {AUTHORITY_PUBKEY: {"consensus": 100}}
        for _name, (_priv, pub) in self.keys.items():
            self.anchor[pub] = {self.DOMAIN: 100}

    def _pub(self, name: str) -> str:
        return self.keys[name][1]

    def _att(self, name: str, subject: str):
        priv, pub = self.keys[name]
        tx = make_attestation(pub, subject, self.RUBRIC, 0, True, 1, SUB, domain=self.DOMAIN)
        tx.sign(priv)
        return tx

    def test_over_concentrated_cluster_certificate_is_rejected(self):
        """a, b, c mutually cross-attest (one cluster capped to floor(0.34*300)=102),
        then all back the subject. Raw support 300 clears the threshold, but the
        cap drops the counted support to 102 < 250, so the certificate is invalid."""
        chain = Blockchain(genesis=self.anchor)
        # Mutual cross-attestations weld a, b, c into one cluster...
        for u, v in (("a", "b"), ("b", "a"), ("a", "c"), ("c", "a"), ("b", "c"), ("c", "b")):
            chain.add_transaction(self._att(u, self._pub(v)))
        # ...and all three back the paying subject.
        for name in ("a", "b", "c"):
            chain.add_transaction(self._att(name, self.SUBJECT))
        chain.add_block(producer_key=AUTHORITY_KEY)  # block 1: support + collusion

        granted = sorted(self._pub(n) for n in ("a", "b", "c"))
        cert = make_certificate(self.SUBJECT, self.RUBRIC, self.DOMAIN, SUB, granted)
        chain.add_transaction(cert)
        chain.add_block(producer_key=AUTHORITY_KEY)  # block 2: the over-concentrated cert

        self.assertFalse(chain.is_valid_chain())

    def test_independent_attesters_certificate_validates(self):
        """Control: the same three attesters and weights, but WITHOUT cross-
        attestation, are three singletons. Support 300 is uncapped and the
        certificate is accepted — showing the cap, not the attesters, is decisive."""
        chain = Blockchain(genesis=self.anchor)
        for name in ("a", "b", "c"):
            chain.add_transaction(self._att(name, self.SUBJECT))
        chain.add_block(producer_key=AUTHORITY_KEY)  # block 1: independent support

        granted = sorted(self._pub(n) for n in ("a", "b", "c"))
        cert = make_certificate(self.SUBJECT, self.RUBRIC, self.DOMAIN, SUB, granted)
        chain.add_transaction(cert)
        chain.add_block(producer_key=AUTHORITY_KEY)  # block 2: the certificate

        self.assertTrue(chain.is_valid_chain())


class QuorumMathTests(unittest.TestCase):
    """The BFT quorum is floor(2N/3) + 1 over the validator set of size N."""

    def test_quorum_values(self):
        self.assertEqual(quorum_size(1), 1)   # a single validator is its own quorum
        self.assertEqual(quorum_size(3), 3)   # N=3 tolerates 0 faults
        self.assertEqual(quorum_size(4), 3)   # N=3f+1 with f=1 -> quorum 3
        self.assertEqual(quorum_size(7), 5)   # f=2 -> quorum 5
        self.assertEqual(quorum_size(10), 7)


class QuorumCommitTests(unittest.TestCase):
    """A block is final only when a quorum of the validator set has validly
    committed it. The validator set is the authorities derived from the prefix."""

    def setUp(self):
        # Four validators, each an authority (weight 100 >= AUTHORITY_THRESHOLD in
        # "consensus"): the genesis authority (who also produces) plus three more.
        # N = 4, so quorum_size(4) = 3.
        self.v_priv = {}
        self.anchor = {AUTHORITY_PUBKEY: {"consensus": 100}}
        for name in ("v1", "v2", "v3"):
            priv, pub = generate_keypair()
            self.v_priv[pub] = priv
            self.anchor[pub] = {"consensus": 100}
        self.validators = [AUTHORITY_PUBKEY, *self.v_priv]  # 4 validator pubkeys
        # A non-validator: a real keypair whose public key the anchor never names.
        self.outsider_priv, self.outsider_pub = generate_keypair()

    def _fresh_block(self):
        """A producer-signed (but not-yet-committed) block 1 on a fresh chain."""
        chain = Blockchain(genesis=self.anchor)
        block = chain.add_block(producer_key=AUTHORITY_KEY)  # block 1, proposed
        return chain, block

    def _priv_of(self, pubkey):
        """Private key for a validator pubkey (the producer reuses AUTHORITY_KEY)."""
        return AUTHORITY_KEY if pubkey == AUTHORITY_PUBKEY else self.v_priv[pubkey]

    def test_quorum_of_valid_commits_is_final(self):
        chain, block = self._fresh_block()
        # N=4 -> quorum 3; commit with exactly three distinct validators.
        for pub in self.validators[:3]:
            block.add_commit_signature(self._priv_of(pub))
        self.assertEqual(len(block.commit_signers()), 3)
        self.assertTrue(chain.is_final(block))

    def test_below_quorum_is_not_final(self):
        chain, block = self._fresh_block()
        for pub in self.validators[:2]:  # only two of four validators
            block.add_commit_signature(self._priv_of(pub))
        self.assertEqual(len(block.commit_signers()), 2)
        self.assertFalse(chain.is_final(block))  # 2 < quorum 3

    def test_non_validator_commit_does_not_count(self):
        chain, block = self._fresh_block()
        # Two genuine validators plus one genuine-but-non-validator signature.
        for pub in self.validators[:2]:
            block.add_commit_signature(self._priv_of(pub))
        block.add_commit_signature(self.outsider_priv)  # cryptographically valid…
        # …so it appears among commit_signers, but it is not in the validator set.
        self.assertIn(self.outsider_pub, block.commit_signers())
        self.assertFalse(chain.is_final(block))  # only 2 validators committed < 3

    def test_forged_commit_signature_is_ignored(self):
        chain, block = self._fresh_block()
        for pub in self.validators[:2]:
            block.add_commit_signature(self._priv_of(pub))
        # Forge a third validator's commit with garbage bytes (not their signature).
        forged_validator = self.validators[2]
        block.commit_signatures[forged_validator] = "00" * 64
        self.assertNotIn(forged_validator, block.commit_signers())  # dropped
        self.assertFalse(chain.is_final(block))  # still only 2 genuine < 3

    def test_genesis_block_is_final_by_definition(self):
        chain = Blockchain(genesis=self.anchor)
        self.assertTrue(chain.is_final(chain.blocks[0]))


class ReplaceChainTests(unittest.TestCase):
    def test_adopts_longer_non_conflicting_chain(self):
        """Finality doesn't freeze non-final growth: with no finalized block in
        conflict, the longer valid chain still wins on the length tiebreak."""
        short = build_chain(1)   # genesis + 1, nothing finalized
        long = build_chain(3)    # genesis + 3

        self.assertTrue(short.replace_chain(long.blocks))
        self.assertEqual(len(short.blocks), 4)
        self.assertEqual(short.last_block.hash, long.last_block.hash)

    def test_equal_length_forks_resolved_deterministically(self):
        """Two same-height, equally-final forks no longer 'keep current' by default;
        they are resolved by the deterministic tiebreak (lower tip hash wins), so
        both honest nodes settle on the *same* fork rather than churning."""
        a = build_chain(2)
        b = build_chain(2)
        # Neither is final and both are length 3, so the lower tip hash decides.
        low, high = sorted((a, b), key=lambda c: c.last_block.hash)
        # Rebuild independent copies (replace_chain mutates in place).
        low_blocks, high_blocks = list(low.blocks), list(high.blocks)

        starting_high = build_chain(0)
        starting_high.blocks = list(high_blocks)
        self.assertTrue(starting_high.replace_chain(low_blocks))   # lower hash adopted
        self.assertEqual(starting_high.last_block.hash, low.last_block.hash)

        starting_low = build_chain(0)
        starting_low.blocks = list(low_blocks)
        self.assertFalse(starting_low.replace_chain(high_blocks))  # higher hash refused

    def test_refuses_shorter_chain(self):
        long = build_chain(3)
        short = build_chain(1)
        self.assertFalse(long.replace_chain(short.blocks))

    def test_refuses_longer_but_invalid_chain(self):
        """Length alone is not enough — an invalid candidate is refused."""
        current = build_chain(1)
        candidate = build_chain(3)
        candidate.blocks[-1].producer_signature = "00" * 64  # corrupt the tip

        self.assertFalse(current.replace_chain(candidate.blocks))
        self.assertEqual(len(current.blocks), 2)  # unchanged

    def test_adopting_recomputes_mempool(self):
        """Pending txs the adopted chain already commits are dropped."""
        current = build_chain(1)
        longer = build_chain(3)
        # Pool a tx that the longer chain already committed in one of its blocks.
        committed_tx = longer.blocks[2].transactions[0]
        loose_tx = tx(999)
        current.mempool = [committed_tx, loose_tx]

        self.assertTrue(current.replace_chain(longer.blocks))
        pooled = {t.hash for t in current.mempool}
        self.assertNotIn(committed_tx.hash, pooled)  # dropped: now on-chain
        self.assertIn(loose_tx.hash, pooled)          # kept: still pending


class FinalityForkChoiceTests(unittest.TestCase):
    """BFT fork choice: finality — not length — decides, and a finalized block is
    irreversible even against a strictly longer competing fork."""

    def setUp(self):
        # Four validators (all authorities), so quorum_size(4) = 3. The genesis
        # authority both produces and validates; three more only validate.
        self.priv = {AUTHORITY_PUBKEY: AUTHORITY_KEY}
        self.anchor = {AUTHORITY_PUBKEY: {"consensus": 100}}
        self.extra = []
        for _ in range(3):
            p, pub = generate_keypair()
            self.priv[pub] = p
            self.anchor[pub] = {"consensus": 100}
            self.extra.append((p, pub))
        self.validators = list(self.priv)                       # 4 validator pubkeys
        self.quorum_privs = [self.priv[v] for v in self.validators[:3]]  # 3 = quorum

    def _new_chain(self) -> Blockchain:
        return Blockchain(genesis=self.anchor)

    def _propose(self, chain, nonce=None):
        """Append a producer-signed (not-yet-final) block by the scheduled proposer.

        The producer is whichever validator the schedule assigns to this height
        (view 0), so every produced block is valid under the schedule. An optional
        ``nonce`` pools a distinguishing signed tx first, so two competing forks at
        the same height differ in hash without any of them going off-schedule.
        """
        if nonce is not None:
            chain.add_transaction(tx(nonce))
        height = len(chain.blocks)
        return chain.add_block(producer_key=self.priv[chain.proposer_for(height)])

    def _finalize(self, block):
        """Attach a quorum (3) of genuine validator commit signatures."""
        for priv in self.quorum_privs:
            block.add_commit_signature(priv)
        return block

    def test_finalized_block_survives_longer_competing_fork(self):
        """The key BFT property: a finalized block is NOT reverted by a longer fork
        that lacks it."""
        current = self._new_chain()
        b1 = self._finalize(self._propose(current))       # block 1, finalized
        self.assertTrue(current.is_final(b1))
        self.assertEqual(current._finalized_height(), 1)

        # A strictly longer fork that forks at height 1 (different producer) and so
        # does not contain our finalized b1.
        competitor = self._new_chain()
        self._propose(competitor, nonce=1)                    # block 1' != b1
        self._propose(competitor)                              # block 2'
        self._propose(competitor)                              # block 3' -> length 4
        self.assertGreater(len(competitor.blocks), len(current.blocks))
        self.assertNotEqual(competitor.blocks[1].hash, b1.hash)

        self.assertFalse(current.replace_chain(competitor.blocks))  # longer, refused
        self.assertEqual(len(current.blocks), 2)                    # unchanged
        self.assertEqual(current.blocks[1].hash, b1.hash)           # b1 intact

    def test_candidate_reverting_finalized_history_is_rejected(self):
        """Even a partial rewrite of finalized history (keeping b1, replacing the
        finalized b2) is refused."""
        current = self._new_chain()
        b1 = self._finalize(self._propose(current))       # block 1, finalized
        b2 = self._finalize(self._propose(current))       # block 2, finalized
        self.assertEqual(current._finalized_height(), 2)

        candidate = self._new_chain()
        candidate.blocks = [current.blocks[0], b1]         # same genesis + finalized b1
        self._propose(candidate, nonce=1)                    # block 2' != b2
        self._propose(candidate)                             # block 3' -> longer
        self.assertEqual(candidate.blocks[1].hash, b1.hash)
        self.assertNotEqual(candidate.blocks[2].hash, b2.hash)

        self.assertFalse(current.replace_chain(candidate.blocks))
        self.assertEqual(current.blocks[2].hash, b2.hash)   # finalized b2 intact

    def test_equivocation_at_same_height_resolved_by_lower_hash(self):
        """Two different blocks at the same height (equivocation), neither final,
        are resolved deterministically by the lower tip hash — both nodes agree."""
        fork_a = self._new_chain()
        self._propose(fork_a, nonce=1)
        fork_b = self._new_chain()
        self._propose(fork_b, nonce=2)                      # same scheduled proposer, diff tx -> diff hash
        self.assertNotEqual(fork_a.blocks[1].hash, fork_b.blocks[1].hash)

        low, high = sorted((fork_a, fork_b), key=lambda c: c.last_block.hash)
        low_blocks, high_blocks = list(low.blocks), list(high.blocks)

        start_high = self._new_chain()
        start_high.blocks = list(high_blocks)
        self.assertTrue(start_high.replace_chain(low_blocks))    # lower hash adopted
        self.assertEqual(start_high.last_block.hash, low.last_block.hash)

        start_low = self._new_chain()
        start_low.blocks = list(low_blocks)
        self.assertFalse(start_low.replace_chain(high_blocks))   # higher hash refused

    def test_chain_asserting_fake_finality_is_invalid(self):
        """A chain that pastes forged commit signatures to *claim* finality it did
        not earn is invalid — is_final counts the same (forged) sigs, so it is not
        fooled either."""
        chain = self._new_chain()
        block = self._propose(chain)
        for v in self.validators[:3]:
            block.commit_signatures[v] = "00" * 64     # forged 'quorum'
        self.assertFalse(chain.is_final(block))          # not actually final
        self.assertFalse(chain.is_valid_chain())         # and the chain is rejected

    def test_chain_with_non_validator_commit_is_invalid(self):
        """Padding a block's finality with a genuine signature from a non-validator
        makes the chain invalid."""
        chain = self._new_chain()
        block = self._propose(chain)
        outsider_priv, _ = generate_keypair()
        block.add_commit_signature(outsider_priv)        # genuine, but not a validator
        self.assertFalse(chain.is_valid_chain())

    def test_longer_non_conflicting_chain_extends_finalized_history(self):
        """Finality does not freeze growth: a longer chain that *contains* our
        finalized block and extends past it is adopted."""
        current = self._new_chain()
        b1 = self._finalize(self._propose(current))      # block 1, finalized
        self.assertEqual(current._finalized_height(), 1)

        candidate = self._new_chain()
        candidate.blocks = list(current.blocks)           # genesis + finalized b1
        self._propose(candidate)                          # block 2 (non-final)
        self._propose(candidate)                          # block 3 -> longer
        self.assertEqual(candidate.blocks[1].hash, b1.hash)  # finalized history kept

        self.assertTrue(current.replace_chain(candidate.blocks))
        self.assertEqual(len(current.blocks), 4)


class ViewChangeScheduleTests(unittest.TestCase):
    """The view-change rule that keeps the chain live when a proposer stalls:
    a deterministic proposer schedule, and consensus rules pinning both *who* may
    produce a block for its ``(height, view)`` and that any ``view > 0`` is
    justified by a quorum of view-change messages."""

    def setUp(self):
        from reputation.genesis import CONSENSUS_DOMAIN

        # Four reproducible validators (deterministic schedule across runs), so
        # ``quorum_size(4) = 3``. All hold consensus weight and nothing else.
        self.kp = [keypair_from_seed(bytes([s]) * 32) for s in (0x01, 0x11, 0x21, 0x31)]
        self.anchor = {pub: {CONSENSUS_DOMAIN: 100} for _priv, pub in self.kp}
        self.priv_by_pub = {pub: priv for priv, pub in self.kp}
        self.validators = set(self.priv_by_pub)

    def test_scheduled_proposer_is_deterministic(self):
        """The proposer for ``(height, view)`` is ``sorted(validators)[(height+view) mod N]``
        — a total function of the set, height, and view, so every node agrees."""
        from blockchain.blockchain import scheduled_proposer

        ordered = sorted(self.validators)
        n = len(ordered)
        for height in range(6):
            for view in range(n + 2):
                self.assertEqual(
                    scheduled_proposer(self.validators, height, view),
                    ordered[(height + view) % n],
                )
        # No validators -> no one can propose.
        self.assertIsNone(scheduled_proposer(set(), 3, 0))

    def test_happy_path_view0_block_validates_and_finalizes(self):
        """The unchanged normal path: the view-0 scheduled proposer's block is valid
        and finalizes with a quorum of commits — no view-change needed or present."""
        chain = Blockchain(genesis=self.anchor)
        block = propose_scheduled(chain, self.priv_by_pub)  # view 0
        self.assertEqual(block.view, 0)
        self.assertEqual(block.view_change_messages, {})
        self.assertTrue(chain.is_valid_chain())

        for pub in sorted(self.validators)[: quorum_size(len(self.validators))]:
            block.add_commit_signature(self.priv_by_pub[pub])
        self.assertTrue(chain.is_final(block))

    def test_block_from_wrong_proposer_for_its_view_is_invalid(self):
        """A validator that is not the scheduled proposer for ``(height, view)`` cannot
        produce a valid block there, even though it *is* a validator."""
        from blockchain.blockchain import scheduled_proposer

        chain = Blockchain(genesis=self.anchor)
        correct = scheduled_proposer(self.validators, 1, 0)
        wrong = next(p for p in sorted(self.validators) if p != correct)
        chain.add_block(producer_key=self.priv_by_pub[wrong], view=0)
        self.assertFalse(chain.is_valid_chain())

    def test_view_advance_without_quorum_view_change_is_invalid(self):
        """A ``view > 0`` block is rejected unless a quorum of validators signed the
        view-change to it — an unjustified rotation cannot ride into consensus."""
        from blockchain.blockchain import scheduled_proposer

        proposer = scheduled_proposer(self.validators, 1, 1)

        # (a) No justification at all.
        chain = Blockchain(genesis=self.anchor)
        chain.add_block(producer_key=self.priv_by_pub[proposer], view=1)
        self.assertFalse(chain.is_valid_chain())

        # (b) Fewer than a quorum of genuine view-change votes.
        chain = Blockchain(genesis=self.anchor)
        ordered = sorted(self.validators)
        message = view_change_signing_bytes(1, 1)
        short = {
            pub: sign(self.priv_by_pub[pub], message)
            for pub in ordered[: quorum_size(len(ordered)) - 1]
        }
        chain.add_block(producer_key=self.priv_by_pub[proposer], view=1, view_change_messages=short)
        self.assertFalse(chain.is_valid_chain())

    def test_stalled_proposer_view1_block_with_quorum_is_valid_and_finalizes(self):
        """The liveness payoff: after the view-0 proposer stalls, the *next* scheduled
        proposer produces a view-1 block justified by a quorum of view-change votes;
        it is valid and finalizes — the chain made progress without the stalled leader."""
        from blockchain.blockchain import scheduled_proposer

        chain = Blockchain(genesis=self.anchor)
        # The view-0 proposer for height 1 "stalls": we never produce its block and
        # instead advance to view 1 with a quorum of view-change votes.
        v0_proposer = scheduled_proposer(self.validators, 1, 0)
        v1_proposer = scheduled_proposer(self.validators, 1, 1)
        self.assertNotEqual(v1_proposer, v0_proposer)  # rotation picks a different leader

        justification = _quorum_view_change(chain, 1, 1, self.priv_by_pub)
        block = chain.add_block(
            producer_key=self.priv_by_pub[v1_proposer], view=1, view_change_messages=justification
        )
        self.assertEqual(block.view, 1)
        self.assertEqual(block.producer, v1_proposer)
        self.assertTrue(chain.is_valid_chain())

        for pub in sorted(self.validators)[: quorum_size(len(self.validators))]:
            block.add_commit_signature(self.priv_by_pub[pub])
        self.assertTrue(chain.is_final(block))


if __name__ == "__main__":
    unittest.main()
