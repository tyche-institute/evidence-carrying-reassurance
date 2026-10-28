"""Deterministic Ed25519 keys and detached signatures over canonical JSON.

A key is derived from a label: seed = SHA-256("ecr-fixture-key:" + label).
The derivation is for fixture generation only; it has no security purpose
beyond reproducibility, and the labels are listed in CODEBOOK.md.

A signature block carries the public key, so every signed object verifies
on its own. Identity is decided elsewhere: policy pins `key_id`
(= `sha256:` over the raw 32-byte public key) for roots, status sources,
timestamp roots, brokers and approvers.
"""

from __future__ import annotations

import base64
import hashlib
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .canon import canonical_bytes

_SEED_PREFIX = b"ecr-fixture-key:"


def private_key_for(label: str) -> Ed25519PrivateKey:
    seed = hashlib.sha256(_SEED_PREFIX + label.encode("utf-8")).digest()
    return Ed25519PrivateKey.from_private_bytes(seed)


def public_raw(pub: Ed25519PublicKey) -> bytes:
    return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def key_id_of_raw(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def key_id_for(label: str) -> str:
    return key_id_of_raw(public_raw(private_key_for(label).public_key()))


def public_key_b64_for(label: str) -> str:
    return base64.b64encode(public_raw(private_key_for(label).public_key())).decode("ascii")


def sign(payload: Any, label: str) -> dict:
    priv = private_key_for(label)
    raw = public_raw(priv.public_key())
    sig = priv.sign(canonical_bytes(payload))
    return {
        "alg": "Ed25519",
        "canon": "RFC8785",
        "key_id": key_id_of_raw(raw),
        "public_key": base64.b64encode(raw).decode("ascii"),
        "value": base64.b64encode(sig).decode("ascii"),
    }


def verify(payload: Any, signature: dict) -> tuple[bool, str]:
    """Verify a detached signature block. Returns (ok, detail)."""
    if not isinstance(signature, dict):
        return False, "signature block missing"
    if signature.get("alg") != "Ed25519" or signature.get("canon") != "RFC8785":
        return False, "unsupported alg or canonicalisation"
    try:
        raw = base64.b64decode(signature["public_key"], validate=True)
        sig = base64.b64decode(signature["value"], validate=True)
    except (KeyError, ValueError, TypeError):
        return False, "signature block malformed"
    if key_id_of_raw(raw) != signature.get("key_id"):
        return False, "key_id does not match carried public key"
    try:
        Ed25519PublicKey.from_public_bytes(raw).verify(sig, canonical_bytes(payload))
    except (InvalidSignature, ValueError):
        return False, "signature does not verify over canonical payload"
    return True, "ok"
