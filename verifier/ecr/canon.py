"""Canonical JSON (RFC 8785 subset) and digests.

The subset: objects, arrays, strings, integers, booleans and null. Floating
point numbers are refused because their RFC 8785 serialisation (ECMAScript
Number-to-String) is not reproduced here. Every signed object in the artifact
stays inside this subset, so `json.dumps(sort_keys=True, separators=(",", ":"))`
over UTF-8 is byte-for-byte the RFC 8785 canonical form.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any


class NonCanonicalValue(ValueError):
    pass


def _check(value: Any, path: str = "$") -> None:
    if isinstance(value, bool) or value is None or isinstance(value, str):
        return
    if isinstance(value, int):
        return
    if isinstance(value, float):
        raise NonCanonicalValue(f"{path}: floating point numbers are outside the canonical subset")
    if isinstance(value, dict):
        for k, v in value.items():
            if not isinstance(k, str):
                raise NonCanonicalValue(f"{path}: non-string key {k!r}")
            _check(v, f"{path}.{k}")
        return
    if isinstance(value, (list, tuple)):
        for i, v in enumerate(value):
            _check(v, f"{path}[{i}]")
        return
    raise NonCanonicalValue(f"{path}: unsupported type {type(value).__name__}")


def canonical_bytes(value: Any) -> bytes:
    _check(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest(value: Any) -> str:
    """`sha256:<hex>` over the canonical bytes of `value`."""
    return "sha256:" + sha256_hex(canonical_bytes(value))


def file_sha256(path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()
