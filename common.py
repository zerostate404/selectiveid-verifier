"""Shared helpers: canonical JSON, SHA-256, base64."""

import json
import hashlib
import base64


def canon(obj):
    """Same object -> same bytes, always."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def sha256_hex(data):
    """Return SHA-256 digest as a hex string."""
    return hashlib.sha256(data).hexdigest()


def b64(raw):
    """Base64-encode bytes into a text string."""
    return base64.b64encode(raw).decode()


def unb64(text):
    """Base64-decode a text string back into bytes."""
    return base64.b64decode(text)


def make_digest(salt, name, value):
    """H(salt || name || value). Shared by issuer and verifier."""
    return sha256_hex(salt + canon([name, value]))
