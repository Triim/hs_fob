"""The browser's proof-of-possession must be the one Python verifies.

The holder signs in the browser (``frontend/app.js``) and the node verifies in
Python (:mod:`credentials.presentation`). Those are two implementations of one
byte string, and if they ever drift, every attestation from the UI is refused
with a signature error that looks like a key problem. These tests extract the
PoP message the browser builds — from the real ``app.js`` source, not a copy —
and compare it to :func:`credentials.presentation.pop_signing_bytes`, then check
that a signature made over the browser's bytes verifies on the Python side.

Skipped (not failed) when Node is unavailable, mirroring :mod:`tests.test_did_js`.
"""

import json
import re
import shutil
import subprocess
import unittest
from pathlib import Path

from credentials.presentation import POP_CONTEXT, pop_signing_bytes, verify_presentation
from credentials.vc import issue_reviewer_credential
from crypto.did import public_key_to_did_key
from crypto.keys import generate_keypair, sign

APP_JS = Path(__file__).resolve().parent.parent / "frontend" / "app.js"
NODE = shutil.which("node")


def _browser_pop_message(challenge: str, did: str) -> str:
    """Build the PoP message with the template literal app.js actually uses.

    ``app.js`` is a browser script (it touches ``window`` and the DOM), so it is
    not requireable under Node. Instead the exact template literal is lifted out
    of the source and evaluated, which keeps this test honest: edit the format in
    the browser and this test changes with it.
    """
    source = APP_JS.read_text(encoding="utf-8")
    match = re.search(r"enc\.encode\((`[^`]*POP_CONTEXT[^`]*`)\)", source)
    assert match, "could not find the PoP template literal in app.js"
    context = re.search(r'const POP_CONTEXT = "([^"]+)";', source)
    assert context, "could not find POP_CONTEXT in app.js"
    script = (
        f'const POP_CONTEXT = {json.dumps(context.group(1))};\n'
        f'const body = {{ challenge: {json.dumps(challenge)} }};\n'
        f'const did = {json.dumps(did)};\n'
        f"console.log({match.group(1)});"
    )
    return subprocess.run(
        [NODE, "-e", script], capture_output=True, text=True, check=True
    ).stdout.rstrip("\n")


@unittest.skipUnless(NODE, "node is not installed")
class BrowserPopTests(unittest.TestCase):
    def test_browser_pop_context_matches_python(self):
        source = APP_JS.read_text(encoding="utf-8")
        self.assertIn(f'const POP_CONTEXT = "{POP_CONTEXT}";', source)

    def test_browser_pop_message_matches_python_signing_bytes(self):
        _priv, pub = generate_keypair()
        did = public_key_to_did_key(pub)
        challenge = "9f" * 32

        self.assertEqual(
            _browser_pop_message(challenge, did).encode("utf-8"),
            pop_signing_bytes(challenge, did),
        )

    def test_a_signature_over_the_browser_bytes_verifies_on_the_node(self):
        """End to end across the language boundary: browser signs, Python accepts."""
        priv, pub = generate_keypair()
        did = public_key_to_did_key(pub)
        challenge = "ab" * 32
        credential = issue_reviewer_credential(did, ["computer-science"])

        message = _browser_pop_message(challenge, did).encode("utf-8")
        presentation = {
            "credential": credential,
            "challenge": challenge,
            "challenge_signature": sign(priv, message),
        }

        ok, reason = verify_presentation(presentation, pub, "computer-science")
        self.assertTrue(ok, reason)

    def test_the_browser_sends_the_presentation_beside_the_transaction(self):
        """The envelope key must match the one the node reads (network.wire)."""
        from network.wire import PRESENTATION_KEY

        source = APP_JS.read_text(encoding="utf-8")
        self.assertIn(f"{PRESENTATION_KEY}: presentation", source)


if __name__ == "__main__":
    unittest.main()
