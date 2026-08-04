"""Reviewer credentials as the gate on attesting — and the lines they must not cross.

Two halves:

* **the gate** — a node admits an attestation only when it arrives with a valid
  Reviewer VC and a proof of possession for that domain, over both entry points
  (``POST /api/tx`` and gossip);
* **the invariants** — a credential grants *eligibility only*. It must not change
  reputation weight, must not appear on-chain, and must not be confused with
  validator authority.

These run on IPv8's in-memory harness, so packets are really serialized between
nodes and every node applies the gate itself.
"""

import copy
import json
from datetime import datetime, timedelta, timezone

from ipv8.peer import Peer
from ipv8.test.base import TestBase

from attestation.attestation import make_attestation
from attestation.submission import make_submission
from blockchain.blockchain import AUTHORITY_THRESHOLD, Blockchain
from credentials.presentation import make_presentation, sign_challenge
from credentials.vc import AUTHORITY_DID, issue_reviewer_credential
from crypto.did import public_key_to_did_key
from crypto.keys import generate_keypair, keypair_from_seed, public_hex
from network.community import AttestationCommunity, AttestationSettings
from network.http_bridge import (
    build_app,
    issue_reviewer_vc,
    produce_block,
    submit_transaction,
)
from network.wire import PRESENTATION_KEY, tx_to_wire, wire_to_presentation
from reputation.genesis import CONSENSUS_DOMAIN, GENESIS_AUTHORITY_KEYS
from reputation.registry import ReputationRegistry
from reputation.tally import weighted_support

DOMAIN = "computer-science"
SUBMISSION = "aa"
SUBJECT = "5375626a656374"
RUBRIC = "cafe"


def reviewer(domains=(DOMAIN,), **issue_kwargs):
    """A reviewer identity holding a Reviewer VC: ``(priv, pub, credential)``."""
    private_key, public_key = generate_keypair()
    credential = issue_reviewer_credential(
        public_key_to_did_key(public_key), list(domains), **issue_kwargs
    )
    return private_key, public_key, credential


def attestation_of(private_key, public_key, domain=DOMAIN, item=0, stake=1):
    """A signed attestation from ``public_key`` in ``domain``."""
    tx = make_attestation(
        public_key, SUBJECT, RUBRIC, item, True, stake, SUBMISSION, domain
    )
    tx.sign(private_key)
    return tx


class CredentialGateTests(TestBase):
    """A node accepts an attestation only from an eligible, key-possessing reviewer."""

    def setUp(self):
        super().setUp()
        self.overlay_class = AttestationCommunity
        self.nodes = [
            self.create_node(AttestationSettings(blockchain=Blockchain()))
            for _ in range(2)
        ]
        for node in self.nodes:
            for other in self.nodes:
                if other is node:
                    continue
                peer = Peer(other.my_peer.public_key, other.my_peer.address)
                node.network.add_verified_peer(peer)
                node.network.discover_services(peer, [AttestationCommunity.community_id])
        for i in range(len(self.nodes)):
            self.patch_overlays(i)

    def chain(self, i):
        return self.overlay(i).blockchain

    def body(self, tx, presentation):
        """The POST body: transaction plus the presentation riding beside it."""
        return {**tx.to_dict(), PRESENTATION_KEY: presentation}

    def present(self, node_index, private_key, credential):
        """A presentation over a challenge issued by node ``node_index``."""
        challenge = self.overlay(node_index).challenges.issue()["challenge"]
        return make_presentation(private_key, credential, challenge)

    # ------------------------------------------------------------- happy path

    async def test_valid_credential_and_pop_allow_attesting(self):
        priv, pub, credential = reviewer()
        tx = attestation_of(priv, pub)

        status, result = submit_transaction(
            self.overlay(0), self.body(tx, self.present(0, priv, credential))
        )
        await self.deliver_messages()

        self.assertEqual(status, 201, result)
        self.assertEqual(self.chain(0).mempool[0].hash, tx.hash)
        # The peer re-ran the gate on the gossiped presentation and admitted it too.
        self.assertEqual(self.chain(1).mempool[0].hash, tx.hash)

    async def test_attestation_without_any_credential_is_refused(self):
        priv, pub, _ = reviewer()
        tx = attestation_of(priv, pub)

        status, result = submit_transaction(self.overlay(0), tx.to_dict())

        self.assertEqual(status, 400)
        self.assertIn("credential", result["error"])
        self.assertEqual(len(self.chain(0).mempool), 0)

    # ------------------------------------------------------------ the refusals

    async def test_credential_for_the_wrong_domain_is_refused(self):
        priv, pub, credential = reviewer(domains=["bioinformatics"])
        tx = attestation_of(priv, pub, domain=DOMAIN)

        status, result = submit_transaction(
            self.overlay(0), self.body(tx, self.present(0, priv, credential))
        )

        self.assertEqual(status, 400)
        self.assertIn("does not grant review rights", result["error"])
        self.assertEqual(len(self.chain(0).mempool), 0)

    async def test_stolen_credential_without_the_holder_key_is_refused(self):
        """A thief copies the VC JSON verbatim and cannot use it."""
        victim_priv, victim_pub, credential = reviewer()
        thief_priv, thief_pub = generate_keypair()
        tx = attestation_of(thief_priv, thief_pub)  # the thief's own attestation
        challenge = self.overlay(0).challenges.issue()["challenge"]
        stolen = {
            "credential": credential,
            "challenge": challenge,
            "challenge_signature": sign_challenge(
                thief_priv, challenge, public_key_to_did_key(victim_pub)
            ),
        }

        status, result = submit_transaction(self.overlay(0), self.body(tx, stolen))

        self.assertEqual(status, 400)
        self.assertIn("not the attesting key", result["error"])
        self.assertEqual(len(self.chain(0).mempool), 0)

    async def test_expired_credential_is_refused(self):
        past = datetime.now(timezone.utc) - timedelta(days=2)
        priv, pub, credential = reviewer(
            valid_from=past, valid_until=past + timedelta(days=1)
        )
        tx = attestation_of(priv, pub)

        status, result = submit_transaction(
            self.overlay(0), self.body(tx, self.present(0, priv, credential))
        )

        self.assertEqual(status, 400)
        self.assertIn("expired", result["error"])
        self.assertEqual(len(self.chain(0).mempool), 0)

    async def test_credential_not_signed_by_the_trusted_issuer_is_refused(self):
        """Self-issued eligibility is the attack a trusted issuer list exists for."""
        priv, pub = generate_keypair()
        self_issued = issue_reviewer_credential(
            public_key_to_did_key(pub),
            [DOMAIN],
            issuer_private_key=priv,               # signs their own credential …
            issuer_did=public_key_to_did_key(pub),
        )
        tx = attestation_of(priv, pub)

        status, result = submit_transaction(
            self.overlay(0), self.body(tx, self.present(0, priv, self_issued))
        )

        self.assertEqual(status, 400)
        self.assertIn("not a trusted", result["error"])
        self.assertEqual(len(self.chain(0).mempool), 0)

    async def test_tampered_credential_is_refused(self):
        priv, pub, credential = reviewer(domains=["bioinformatics"])
        widened = copy.deepcopy(credential)
        widened["credentialSubject"]["domains"].append(DOMAIN)
        tx = attestation_of(priv, pub)

        status, result = submit_transaction(
            self.overlay(0), self.body(tx, self.present(0, priv, widened))
        )

        self.assertEqual(status, 400)
        self.assertIn("signature", result["error"])

    async def test_challenge_is_single_use(self):
        """A captured presentation cannot be re-attached to a second attestation."""
        priv, pub, credential = reviewer()
        presentation = self.present(0, priv, credential)
        first = attestation_of(priv, pub, item=0)
        second = attestation_of(priv, pub, item=1)

        self.assertEqual(
            submit_transaction(self.overlay(0), self.body(first, presentation))[0], 201
        )
        status, result = submit_transaction(
            self.overlay(0), self.body(second, presentation)
        )

        self.assertEqual(status, 400)
        self.assertIn("challenge", result["error"])
        self.assertEqual(len(self.chain(0).mempool), 1)

    async def test_challenge_from_another_node_is_not_accepted_here(self):
        """Freshness is per-node: node 0 only spends challenges node 0 issued."""
        priv, pub, credential = reviewer()
        tx = attestation_of(priv, pub)
        foreign = self.present(1, priv, credential)  # node 1's challenge

        status, result = submit_transaction(self.overlay(0), self.body(tx, foreign))

        self.assertEqual(status, 400)
        self.assertIn("challenge", result["error"])

    # --------------------------------------------------------------- gossip path

    async def test_gossiped_attestation_without_a_credential_is_dropped(self):
        priv, pub, _ = reviewer()
        tx = attestation_of(priv, pub)

        self.overlay(0).broadcast_transaction(tx)  # no presentation attached
        await self.deliver_messages()

        self.assertEqual(len(self.chain(1).mempool), 0)

    async def test_gossiped_attestation_with_a_wrong_domain_credential_is_dropped(self):
        priv, pub, credential = reviewer(domains=["bioinformatics"])
        tx = attestation_of(priv, pub, domain=DOMAIN)

        self.overlay(0).broadcast_transaction(
            tx, make_presentation(priv, credential, "c")
        )
        await self.deliver_messages()

        self.assertEqual(len(self.chain(1).mempool), 0)

    async def test_submit_local_refuses_an_ineligible_attestation(self):
        priv, pub, _ = reviewer()
        tx = attestation_of(priv, pub)

        self.assertIsNone(self.overlay(0).submit_local(tx))
        self.assertEqual(len(self.chain(0).mempool), 0)

    # ------------------------------------------------- submissions are not gated

    async def test_submitting_your_own_work_needs_no_reviewer_credential(self):
        """A student is not reviewing anyone, so eligibility does not apply."""
        priv, pub = generate_keypair()
        tx = make_submission(pub, DOMAIN, RUBRIC, "My work", "ab", "w.pdf")
        tx.sign(priv)

        status, _ = submit_transaction(self.overlay(0), tx.to_dict())

        self.assertEqual(status, 201)
        self.assertEqual(self.chain(0).mempool[0].hash, tx.hash)


class CredentialInvariantTests(TestBase):
    """Eligibility ≠ weight, eligibility ≠ validator authority, VC stays off-chain."""

    def setUp(self):
        super().setUp()
        self.overlay_class = AttestationCommunity
        self.nodes = [self.create_node(AttestationSettings(blockchain=Blockchain()))]
        self.patch_overlays(0)

    def chain(self):
        return self.nodes[0].overlay.blockchain

    async def test_reputation_weight_is_unchanged_by_the_presence_of_a_credential(self):
        """The credential decides *whether* the vote is admitted, never its size.

        Two chains carry the identical attestation: one admitted through the
        credential gate, one placed directly. The weighted support they produce is
        the same number, because weight comes from the registry and nothing else.
        """
        priv, pub, credential = reviewer()
        tx = attestation_of(priv, pub, stake=0)
        registry = ReputationRegistry({pub: {DOMAIN: 42}})

        gated = self.overlay(0)
        challenge = gated.challenges.issue()["challenge"]
        status, _ = submit_transaction(
            gated,
            {**tx.to_dict(), PRESENTATION_KEY: make_presentation(priv, credential, challenge)},
        )
        self.assertEqual(status, 201)
        produce_block(gated)

        control = Blockchain()
        control.add_transaction(tx)
        control.add_block(producer_key=GENESIS_AUTHORITY_KEYS["genesis-authority"][0])

        with_vc = weighted_support(
            gated.blockchain, registry, SUBJECT, RUBRIC, DOMAIN, SUBMISSION
        )
        without_vc = weighted_support(
            control, registry, SUBJECT, RUBRIC, DOMAIN, SUBMISSION
        )
        self.assertEqual(with_vc, 42)
        self.assertEqual(with_vc, without_vc)

    async def test_a_credential_grants_no_reputation(self):
        """Holding a VC leaves the holder's weight exactly where it was: zero."""
        priv, pub, credential = reviewer()
        node = self.overlay(0)
        before = node.reputation.weight(pub, DOMAIN)

        challenge = node.challenges.issue()["challenge"]
        submit_transaction(
            node,
            {
                **attestation_of(priv, pub, stake=0).to_dict(),
                PRESENTATION_KEY: make_presentation(priv, credential, challenge),
            },
        )
        produce_block(node)

        self.assertEqual(before, 0)
        self.assertEqual(node.reputation.weight(pub, DOMAIN), 0)

    async def test_a_reviewer_credential_confers_no_validator_authority(self):
        """Eligibility to review and authority to validate are separate powers."""
        _priv, pub, _credential = reviewer()
        node = self.overlay(0)

        self.assertNotIn(pub, node.blockchain.validator_set(len(node.blockchain.blocks)))
        self.assertFalse(node.reputation.is_authority(pub, AUTHORITY_THRESHOLD))
        self.assertEqual(node.reputation.weight(pub, CONSENSUS_DOMAIN), 0)

    async def test_a_validator_still_cannot_attest_without_a_credential(self):
        """The converse: consensus authority is not reviewer eligibility."""
        validator_priv, validator_pub = GENESIS_AUTHORITY_KEYS["genesis-authority"]
        node = self.overlay(0)
        self.assertTrue(node.reputation.is_authority(validator_pub, AUTHORITY_THRESHOLD))

        status, result = submit_transaction(
            node, attestation_of(validator_priv, validator_pub, stake=0).to_dict()
        )

        self.assertEqual(status, 400)
        self.assertIn("credential", result["error"])

    async def test_the_credential_never_reaches_the_chain(self):
        """No credential, DID document or issuer data is stored on-chain."""
        priv, pub, credential = reviewer()
        node = self.overlay(0)
        challenge = node.challenges.issue()["challenge"]
        submit_transaction(
            node,
            {
                **attestation_of(priv, pub, stake=0).to_dict(),
                PRESENTATION_KEY: make_presentation(priv, credential, challenge),
            },
        )
        produce_block(node)

        pooled_and_mined = [tx for block in node.blockchain.blocks for tx in block.transactions]
        self.assertEqual(len(pooled_and_mined[-1].payload), 8)  # the attestation schema
        chain_json = json.dumps([b.to_dict() for b in node.blockchain.blocks])
        for marker in (PRESENTATION_KEY, "GradEDReviewerCredential", AUTHORITY_DID,
                       "proofValue", challenge):
            self.assertNotIn(marker, chain_json)

    async def test_the_presentation_does_not_change_the_transaction_bytes(self):
        """The envelope is a sibling of the tx, so hash and signature are untouched."""
        priv, pub, credential = reviewer()
        tx = attestation_of(priv, pub)
        presentation = make_presentation(priv, credential, "c")

        bare = tx_to_wire(tx)
        with_vc = tx_to_wire(tx, presentation)

        self.assertNotEqual(bare, with_vc)
        self.assertEqual(json.loads(bare), {
            k: v for k, v in json.loads(with_vc).items() if k != PRESENTATION_KEY
        })
        self.assertEqual(wire_to_presentation(with_vc), presentation)
        self.assertIsNone(wire_to_presentation(bare))


class CredentialEndpointTests(TestBase):
    """The three HTTP routes a holder uses to become — and prove they are — eligible."""

    def setUp(self):
        super().setUp()
        self.overlay_class = AttestationCommunity
        self.nodes = [self.create_node(AttestationSettings(blockchain=Blockchain()))]
        self.patch_overlays(0)

    async def _client(self):
        from aiohttp.test_utils import TestClient, TestServer

        app = build_app(None, self.overlay(0), ws_interval=1000)
        client = TestClient(TestServer(app))
        await client.start_server()
        return client

    async def test_issue_endpoint_returns_a_verifiable_credential(self):
        _priv, pub = generate_keypair()
        did = public_key_to_did_key(pub)

        status, result = issue_reviewer_vc(
            self.overlay(0), {"subject_did": did, "domains": [DOMAIN]}
        )

        self.assertEqual(status, 201)
        self.assertEqual(result["issuer"]["did"], AUTHORITY_DID)
        self.assertEqual(result["credential"]["credentialSubject"]["id"], did)

    async def test_issue_endpoint_accepts_a_hex_public_key(self):
        _priv, pub = generate_keypair()

        status, result = issue_reviewer_vc(
            self.overlay(0), {"subject": pub, "domains": DOMAIN}
        )

        self.assertEqual(status, 201)
        self.assertEqual(
            result["credential"]["credentialSubject"]["id"], public_key_to_did_key(pub)
        )

    async def test_issue_endpoint_rejects_bad_input(self):
        for body in (
            "not a dict",
            {},
            {"subject": "zzz", "domains": [DOMAIN]},
            {"subject_did": public_key_to_did_key(generate_keypair()[1])},
            {"subject_did": public_key_to_did_key(generate_keypair()[1]),
             "domains": [DOMAIN], "validity_days": 0},
        ):
            status, _ = issue_reviewer_vc(self.overlay(0), body)
            self.assertEqual(status, 400, body)

    async def test_http_issue_challenge_and_issuer_routes(self):
        client = await self._client()
        try:
            _priv, pub = generate_keypair()
            issued = await client.post(
                "/api/credentials/reviewer/issue",
                json={"subject": pub, "domains": [DOMAIN]},
            )
            self.assertEqual(issued.status, 201)
            credential = (await issued.json())["credential"]
            self.assertEqual(
                credential["credentialSubject"]["id"], public_key_to_did_key(pub)
            )

            challenge = await (await client.post("/api/credentials/challenge")).json()
            self.assertEqual(len(challenge["challenge"]), 64)

            issuer = await (await client.get("/api/credentials/issuer")).json()
            self.assertEqual(issuer["authority"]["did"], AUTHORITY_DID)
            self.assertIn(AUTHORITY_DID, issuer["trusted_issuers"])
        finally:
            await client.close()

    async def test_http_attest_flow_end_to_end(self):
        """Issue → challenge → sign → POST /api/tx, exactly as the browser does."""
        client = await self._client()
        try:
            priv, pub = generate_keypair()
            issued = await client.post(
                "/api/credentials/reviewer/issue",
                json={"subject": pub, "domains": [DOMAIN]},
            )
            credential = (await issued.json())["credential"]
            challenge = (
                await (await client.post("/api/credentials/challenge")).json()
            )["challenge"]

            tx = attestation_of(priv, pub, stake=0)
            posted = await client.post(
                "/api/tx",
                json={
                    **tx.to_dict(),
                    PRESENTATION_KEY: make_presentation(priv, credential, challenge),
                },
            )

            self.assertEqual(posted.status, 201)
            self.assertEqual(self.overlay(0).blockchain.mempool[0].hash, tx.hash)
        finally:
            await client.close()

    async def test_a_node_can_be_configured_to_trust_another_issuer(self):
        """Trusted issuers are node policy, not consensus configuration."""
        other_priv, other_pub = keypair_from_seed(bytes.fromhex("5c" * 32))
        other_did = public_key_to_did_key(other_pub)
        node = self.create_node(
            AttestationSettings(blockchain=Blockchain(), trusted_issuer_dids=[other_did])
        )
        self.nodes.append(node)
        self.patch_overlays(1)

        priv, pub = generate_keypair()
        credential = issue_reviewer_credential(
            public_key_to_did_key(pub),
            [DOMAIN],
            issuer_private_key=other_priv,
            issuer_did=other_did,
        )
        tx = attestation_of(priv, pub, stake=0)
        challenge = self.overlay(1).challenges.issue()["challenge"]
        body = {
            **tx.to_dict(),
            PRESENTATION_KEY: make_presentation(priv, credential, challenge),
        }

        # Accepted by the node that trusts this issuer …
        self.assertEqual(submit_transaction(self.overlay(1), body)[0], 201)
        # … and refused by the node that does not, with no effect on either chain's
        # validity: credentials never enter consensus.
        self.assertEqual(submit_transaction(self.overlay(0), body)[0], 400)
        self.assertTrue(self.overlay(1).blockchain.is_valid_chain())

    async def test_the_issuer_did_is_derived_from_the_authority_public_key(self):
        """A verifier needs the DID and nothing else — no key registry, no fetch."""
        from credentials.vc import AUTHORITY_PUBLIC_HEX

        self.assertEqual(AUTHORITY_DID, public_key_to_did_key(AUTHORITY_PUBLIC_HEX))
