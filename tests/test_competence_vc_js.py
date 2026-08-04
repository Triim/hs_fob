"""The browser must be able to verify a credential the node signed.

The verifier page's whole point is that a third party does not have to trust the
node about the one thing cryptography settles on its own: the issuer's signature
is checked **in the browser** (``frontend/app.js``), against the key inside the
issuer's own ``did:key``. That is a second implementation of
:func:`credentials.vc.credential_signing_bytes` — canonical JSON, two SHA-256
halves, Ed25519 — and if it ever drifts from Python's, the page would reject
perfectly good credentials (or, far worse, accept edited ones).

So these tests lift the real functions out of ``app.js`` (not a copy) and run
them under Node against credentials this repo's Python actually exported.

``app.js`` is a browser script — it reads ``window`` at load — so it cannot be
required. The three pure functions the verifier is built on are extracted by
name and evaluated, which keeps the test honest: change the format in the
browser and this test changes with it.

Skipped (not failed) when Node is unavailable, mirroring :mod:`tests.test_did_js`.
"""

import json
import re
import shutil
import subprocess
import unittest
from pathlib import Path

from credentials.competence import export_competence_credential
from tests.test_competence_vc import certified_chain

FRONTEND = Path(__file__).resolve().parent.parent / "frontend"
APP_JS = FRONTEND / "app.js"
NODE = shutil.which("node")


def _extract(name: str) -> str:
    """The source of the top-level ``function name(...) {...}`` in app.js.

    Matched from the declaration to the first line that closes it at column 0,
    which is how every function in that file is formatted.
    """
    source = APP_JS.read_text(encoding="utf-8")
    match = re.search(rf"^function {name}\(.*?^\}}", source, re.S | re.M)
    assert match, f"could not find function {name} in app.js"
    return match.group(0)


def _run_js(credential: dict) -> dict:
    """Verify ``credential`` with the browser's own verifier code, under Node."""
    script = f"""
require({json.dumps(str(FRONTEND / "noble-ed25519.js"))});
const didKey = require({json.dumps(str(FRONTEND / "did.js"))});
// The three globals app.js reads at load time, provided here instead of a DOM.
const ed = globalThis.nobleEd25519;
const sha256 = globalThis.nobleSha256;
const enc = new TextEncoder();
const short = (s) => (s ? s.slice(0, 12) : "");
globalThis.window = {{ didKey }};

{_extract("canonicalJSON")}
{_extract("credentialSigningBytes")}
{_extract("verifyCredentialSignature")}

const credential = {json.dumps(credential)};
console.log(JSON.stringify({{
  signingBytes: Buffer.from(credentialSigningBytes(credential)).toString("hex"),
  canonical: canonicalJSON(credential),
  result: verifyCredentialSignature(credential),
}}));
"""
    result = subprocess.run(
        [NODE, "-e", script], capture_output=True, text=True, check=True
    )
    return json.loads(result.stdout)


@unittest.skipUnless(NODE, "node is not installed")
class BrowserVerifierTests(unittest.TestCase):
    def setUp(self):
        chain, _submission, certificate = certified_chain()
        self.chain = chain
        self.credential = export_competence_credential(chain, certificate.hash)

    def test_browser_computes_the_same_signing_bytes_as_python(self):
        """One document, one canonical byte string — on both sides."""
        from credentials.vc import credential_signing_bytes

        out = _run_js(self.credential)

        expected = credential_signing_bytes(
            self.credential, self.credential["proof"]
        ).hex()
        self.assertEqual(out["signingBytes"], expected)

    def test_browser_canonicalization_matches_jcs(self):
        """The browser's canonicalJSON must agree with RFC 8785 on these documents
        (ASCII keys, strings, integers and booleans — no floats anywhere)."""
        from credentials.jcs import canonicalize

        out = _run_js(self.credential)

        self.assertEqual(out["canonical"], canonicalize(self.credential).decode())

    def test_browser_verifies_a_genuine_credential(self):
        out = _run_js(self.credential)
        self.assertTrue(out["result"]["ok"], out["result"]["detail"])

    def test_browser_rejects_a_tampered_credential(self):
        """The edit a forger would actually make: upgrade the competence."""
        forged = json.loads(json.dumps(self.credential))
        forged["credentialSubject"]["competence"] = "astrophysics/forged"

        out = _run_js(forged)

        self.assertFalse(out["result"]["ok"])

    def test_browser_rejects_a_credential_with_a_swapped_issuer(self):
        """Re-pointing the issuer at another DID does not make the proof verify."""
        forged = json.loads(json.dumps(self.credential))
        forged["issuer"] = "did:key:z6Mkon3Necd6NkkyfoGoHxid2znGc59LU3K7mubaRcFbLfLX"

        out = _run_js(forged)

        self.assertFalse(out["result"]["ok"])


if __name__ == "__main__":
    unittest.main()
