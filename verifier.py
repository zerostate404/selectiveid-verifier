"""VERIFIER (website): runs the six checks and learns only the revealed facts."""

import json
import os
import time
import secrets

from flask import Flask, jsonify, request
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from common import canon, sha256_hex, b64, unb64, make_digest

ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "")

AUDIENCE = "selectiveid-demo"
NONCE_TTL = 120  # seconds a challenge stays valid

app = Flask(__name__)
_nonces = {}  # nonce -> expiry (in memory, single server demo)


def new_nonce():
    """Fresh single-use challenge."""
    n = secrets.token_hex(16)
    _nonces[n] = time.time() + NONCE_TTL
    return n


def load_pub(text):
    """Base64 text -> Ed25519 public key."""
    return Ed25519PublicKey.from_public_bytes(unb64(text.strip()))


def verify(pres, issuer_pub, revoked=()):
    """Run the six checks in order. First failure stops and returns the reason."""
    try:
        cred, shown, proof = pres["cred"], pres["shown"], pres["proof"]
        payload = cred["payload"]
    except (KeyError, TypeError):
        return False, "malformed presentation"

    # 1. issuer signature valid?
    try:
        issuer_pub.verify(unb64(cred["sig"]), canon(payload))
    except Exception:
        return False, "issuer signature invalid (forged or edited credential)"

    # 2. not expired?
    if int(payload["expires"]) < int(time.time()):
        return False, "credential expired"

    # 3. not on revocation list?
    if payload["cred_id"] in revoked:
        return False, "credential revoked"

    # 4. nonce fresh and never used?
    nonce = proof.get("nonce")
    exp = _nonces.pop(nonce, None)  # single use: pop removes it
    if exp is None:
        return False, "replay attack (unknown or already-used nonce)"
    if exp < time.time():
        return False, "nonce expired"

    # 5. holder signature valid?
    msg = canon(
        {
            "nonce": nonce,
            "aud": AUDIENCE,
            "shown": sha256_hex(canon(shown)),
        }
    )
    try:
        load_pub(payload["holder_key"]).verify(unb64(proof["sig"]), msg)
    except Exception:
        return False, "holder signature invalid (not the owner or altered presentation)"

    # 6. each revealed fact hashes to a signed digest?
    signed = set(payload["digests"])
    for name, (salt_b64, value) in shown.items():
        if make_digest(unb64(salt_b64), name, value) not in signed:
            return False, "tampered fact: " + name

    # all six passed: release ONLY the chosen facts
    return True, {k: v[1] for k, v in shown.items()}


@app.route("/challenge")
def challenge():
    """Step 2 of the presentation protocol: hand out a nonce."""
    return jsonify({"nonce": new_nonce(), "aud": AUDIENCE})


def _load_revoked():
    """Read revoked.json; tolerate missing, empty, or malformed files."""
    try:
        with open("revoked.json") as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except (FileNotFoundError, json.JSONDecodeError):
        return []


@app.route("/verify", methods=["POST"])
def verify_endpoint():
    """Step 4: receive a presentation and answer ACCEPT or REJECT + reason."""
    try:
        issuer_pub = load_pub(open("issuer_pub.txt").read())
        revoked = _load_revoked()
        pres = request.get_json(force=True, silent=True) or {}
        ok, result = verify(pres, issuer_pub, revoked)
        return jsonify({"ok": ok, "result": result}), (200 if ok else 400)
    except Exception as e:
        # never leak a 500 HTML page to the holder
        return jsonify({"ok": False, "result": f"server error: {e}"}), 500


@app.get("/health")
def health():
    return jsonify(
        {
            "ok": True,
            "service": "selectiveid-verifier",
            "issuer_key_loaded": os.path.exists("issuer_pub.txt"),
        }
    )


@app.post("/admin/revoke/<cred_id>")
def admin_revoke(cred_id):
    """Token-protected: curl -X POST -H 'X-Admin-Token: ...' .../admin/revoke/<id>"""
    if not ADMIN_TOKEN or request.headers.get("X-Admin-Token") != ADMIN_TOKEN:
        return jsonify({"error": "unauthorized"}), 401
    ids = _load_revoked()
    if cred_id not in ids:
        ids.append(cred_id)
        json.dump(ids, open("revoked.json", "w"))
    return jsonify({"revoked": ids})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
