"""Tests for the Blockchain: producing, linking, and Proof-of-Authority validation."""

import unittest

from attestation.aggregator import make_certificate
from attestation.attestation import make_attestation
from blockchain.blockchain import AUTHORITY_THRESHOLD, Blockchain, quorum_size
from blockchain.transaction import Transaction
from crypto.keys import generate_keypair
from reputation.genesis import GENESIS_AUTHORITY_KEYS

# The reproducible genesis authority: its private key signs blocks, its public
# key carries consensus weight, so blocks it produces pass PoA validation.
AUTHORITY_KEY, AUTHORITY_PUBKEY = GENESIS_AUTHORITY_KEYS["genesis-authority"]


def tx(i: int) -> Transaction:
    """A valid, signed participant transaction for structural tests.

    Consensus is fail-closed: a plain unknown-payload transaction would itself
    invalidate the chain, so structural tests (which only need a transaction to
    *exist* inside a block) use the simplest thing that actually validates — a
    signed attestation. ``item_index=i`` keeps successive txs distinct so their
    hashes differ, exactly as the old ``{"i": i}`` filler did.
    """
    priv, pub = generate_keypair()
    att = make_attestation(pub, "subject", "rubric", i, True, 1)
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
                att_pub, newcomer_pub, rubric_root, 0, True, 1, domain="consensus"
            )
            att.sign(att_priv)
            cert = make_certificate(newcomer_pub, rubric_root, "consensus", [att_pub])
            return att, cert

        # Distinct rubrics so each certificate has a distinct identity (no double-issue).
        pairs = [earned(f"rubric-{k}") for k in range(needed)]

        # Case A — the newcomer produces the block that would grant its authority.
        # The certificates are legitimate (their support sits in block 1), but the
        # newcomer's own authority is judged against the prefix, which excludes the
        # very block crediting it, so the block is rejected.
        chain = Blockchain(genesis=anchor)
        for att, _ in pairs:
            chain.add_transaction(att)
        chain.add_block(producer_key=AUTHORITY_KEY)  # block 1: the attestations
        for _, cert in pairs:
            chain.add_transaction(cert)
        chain.add_block(producer_key=newcomer)       # block 2: the certificates, BY the newcomer
        self.assertFalse(chain.is_valid_chain())

        # Case B — the same rewards are committed by a genesis authority first,
        # and only in a *later* block does the newcomer produce. Now the prefix
        # already credits it, so its block validates.
        chain2 = Blockchain(genesis=anchor)
        for att, _ in pairs:
            chain2.add_transaction(att)
        chain2.add_block(producer_key=AUTHORITY_KEY)  # block 1: the attestations
        for _, cert in pairs:
            chain2.add_transaction(cert)
        chain2.add_block(producer_key=AUTHORITY_KEY)  # block 2: the certificates
        chain2.add_transaction(tx(1))
        chain2.add_block(producer_key=newcomer)       # block 3, now the newcomer is an authority
        self.assertTrue(chain2.is_valid_chain())

    def test_slash_affects_authority_only_after_its_block(self):
        """Slashing a producer below threshold gates only *later* blocks (prefix).

        Block 1 *contains* the slash of the genesis authority, but its own
        producer is judged against the prefix (genesis, full weight), so it is
        valid. A block 2 by the same, now-slashed authority is judged against a
        prefix that includes the slash, so it is rejected.
        """
        from reputation.slashing import make_slash

        chain = Blockchain()
        # A slash is a participant transaction: the issuing authority signs it,
        # with sender = its public key, so it passes the signature requirement.
        slash = make_slash(
            AUTHORITY_PUBKEY, "consensus", "misbehaviour", "ref", amount=100,
            issuer=AUTHORITY_PUBKEY,
        )
        slash.sign(AUTHORITY_KEY)
        chain.add_transaction(slash)
        chain.add_block(producer_key=AUTHORITY_KEY)  # block 1 carries the slash
        self.assertTrue(chain.is_valid_chain())      # judged by the pre-slash prefix

        chain.add_transaction(tx(1))
        chain.add_block(producer_key=AUTHORITY_KEY)  # block 2, producer now slashed to 0
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

        att = make_attestation("attester-pub", "subject", "rubric", 0, True, 1)
        # not signed
        chain = self._chain_with(att)

        self.assertFalse(chain.is_valid_chain())

    def test_accepts_signed_attestation(self):
        """The same attestation, signed with the sender's key, validates."""
        from attestation.attestation import make_attestation

        priv, pub = generate_keypair()
        att = make_attestation(pub, "subject", "rubric", 0, True, 1)
        att.sign(priv)
        chain = self._chain_with(att)

        self.assertTrue(chain.is_valid_chain())

    def test_rejects_attestation_signed_by_wrong_key(self):
        """sender must be the signer: a signature by a different key is rejected."""
        from attestation.attestation import make_attestation

        _, pub = generate_keypair()
        other_priv, _ = generate_keypair()
        att = make_attestation(pub, "subject", "rubric", 0, True, 1)
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

        att = make_attestation(pub, "subject", "rubric", 0, True, 1, domain="bioinformatics")
        att.sign(priv)
        chain.add_transaction(att)
        chain.add_block(producer_key=AUTHORITY_KEY)  # block 1: the supporting attestation

        cert = make_certificate("subject", "rubric", "bioinformatics", [pub])
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
            self.att_pub, subject, rubric_root, 0, True, 1, domain=self.DOMAIN
        )
        att.sign(self.att_priv)
        return att

    def test_forged_certificate_invalidates_chain(self):
        """A certificate minted with no genuine support (threshold unmet) is rejected,
        so an authority cannot inflate reputation by fiat."""
        chain = Blockchain(genesis=self.anchor)
        # No attestation anywhere: the certificate's real weighted support is 0.
        cert = make_certificate("subject", "rubric", self.DOMAIN, [self.att_pub])
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
        cert = make_certificate("subject", "rubric", self.DOMAIN, ["someone-else"])
        chain.add_transaction(cert)
        chain.add_block(producer_key=AUTHORITY_KEY)

        self.assertFalse(chain.is_valid_chain())

    def test_duplicate_certificate_invalidates_chain(self):
        """The same certified claim cannot be issued twice: a second certificate
        with the same identity invalidates the chain (no double reward)."""
        chain = Blockchain(genesis=self.anchor)
        chain.add_transaction(self._attestation("subject", "rubric"))
        chain.add_block(producer_key=AUTHORITY_KEY)  # block 1: support

        cert = make_certificate("subject", "rubric", self.DOMAIN, [self.att_pub])
        chain.add_transaction(cert)
        chain.add_block(producer_key=AUTHORITY_KEY)  # block 2: first (legit) issue
        self.assertTrue(chain.is_valid_chain())

        dup = make_certificate("subject", "rubric", self.DOMAIN, [self.att_pub])
        chain.add_transaction(dup)
        chain.add_block(producer_key=AUTHORITY_KEY)  # block 3: re-issue of the same claim
        self.assertFalse(chain.is_valid_chain())

    def test_legitimately_earned_certificate_validates(self):
        """A certificate whose real support clears the threshold and whose
        ``granted_by`` matches the genuine attesters validates."""
        chain = Blockchain(genesis=self.anchor)
        chain.add_transaction(self._attestation("subject", "rubric"))
        chain.add_block(producer_key=AUTHORITY_KEY)  # block 1: support

        cert = make_certificate("subject", "rubric", self.DOMAIN, [self.att_pub])
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
    def test_adopts_strictly_longer_valid_chain(self):
        """A longer valid PoA chain replaces the current one (longest wins)."""
        short = build_chain(1)   # genesis + 1
        long = build_chain(3)    # genesis + 3

        self.assertTrue(short.replace_chain(long.blocks))
        self.assertEqual(len(short.blocks), 4)
        self.assertEqual(short.last_block.hash, long.last_block.hash)

    def test_refuses_equal_length_chain(self):
        """Ties keep the current chain, so a node never churns at equal height."""
        a = build_chain(2)
        b = build_chain(2)
        self.assertFalse(a.replace_chain(b.blocks))

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


if __name__ == "__main__":
    unittest.main()
