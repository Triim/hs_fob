"""The browser did:key mirror must agree with Python, character for character.

``frontend/did.js`` reimplements :mod:`crypto.did` for the browser. Two
independent implementations of the same encoding are exactly the kind of pair
that drifts silently — a DID shown in the UI that no verifier can resolve back
to the signing key would be worse than showing raw hex. So these tests run the
real JS file under Node and compare its output to Python's on the same inputs,
including random keys generated fresh each run.

Skipped (not failed) when Node is unavailable, so the Python suite still runs
on a machine without it.
"""

import json
import shutil
import subprocess
import unittest
from pathlib import Path

from crypto.did import did_key_to_public_hex, public_key_to_did_key
from crypto.keys import generate_keypair

DID_JS = Path(__file__).resolve().parent.parent / "frontend" / "did.js"
NODE = shutil.which("node")


def _run_js(public_keys: list[str], dids: list[str]) -> dict:
    """Encode ``public_keys`` and decode ``dids`` with the browser implementation."""
    script = f"""
const didKey = require({json.dumps(str(DID_JS))});
const pubs = {json.dumps(public_keys)};
const dids = {json.dumps(dids)};
console.log(JSON.stringify({{
  encoded: pubs.map(didKey.publicKeyToDidKey),
  decoded: dids.map(didKey.didKeyToPublicHex),
}}));
"""
    result = subprocess.run(
        [NODE, "-e", script], capture_output=True, text=True, check=True
    )
    return json.loads(result.stdout)


@unittest.skipUnless(NODE, "node is not installed")
class JsMirrorTests(unittest.TestCase):
    def test_js_encoding_matches_python(self):
        """Same public keys in, byte-identical did:key strings out."""
        keys = [generate_keypair()[1] for _ in range(20)]

        out = _run_js(keys, [])

        self.assertEqual(out["encoded"], [public_key_to_did_key(k) for k in keys])

    def test_js_decoding_matches_python(self):
        dids = [public_key_to_did_key(generate_keypair()[1]) for _ in range(20)]

        out = _run_js([], dids)

        self.assertEqual(out["decoded"], [did_key_to_public_hex(d) for d in dids])

    def test_js_round_trips_and_matches_spec_vector(self):
        """The JS side reproduces the pinned known answer too."""
        key = "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c"
        did = "did:key:z6Mkon3Necd6NkkyfoGoHxid2znGc59LU3K7mubaRcFbLfLX"

        out = _run_js([key], [did])

        self.assertEqual(out["encoded"], [did])
        self.assertEqual(out["decoded"], [key])

    def test_js_leading_zero_bytes_survive(self):
        """A key whose bytes start with zeros still round-trips in the browser.

        The multicodec prefix means a did:key payload never actually leads with
        a zero byte, but the base58 long division is where a leading-zero bug
        would hide, so it is exercised deliberately.
        """
        key = "00" * 4 + "11" * 28

        out = _run_js([key], [public_key_to_did_key(key)])

        self.assertEqual(out["encoded"], [public_key_to_did_key(key)])
        self.assertEqual(out["decoded"], [key])


if __name__ == "__main__":
    unittest.main()
