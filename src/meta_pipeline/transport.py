"""Versioned, lossless local evidence exchange; never a provider API override.

The incumbent export is canonical expanded JSON. Optional compressed exports
retain its exact byte-content identity and require bounded independent decoding.
Hashes establish consistency only; authorization is always out of band.
"""
from __future__ import annotations

import base64
import hashlib
import json
import zlib

from .protocol import PROTOCOL_ID, digest

MAX_EXPANDED = 8 * 1024 * 1024
MAX_WIRE = 12 * 1024 * 1024


def expanded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode()


def encode(value, *, version="evidence-zlib-v1"):
    if version != "evidence-zlib-v1":
        raise ValueError("Unsupported evidence transport version")
    raw = expanded(value)
    if len(raw) > MAX_EXPANDED:
        raise ValueError("Expanded evidence exceeds limit")
    return expanded({"version": version, "protocol": PROTOCOL_ID,
                     "contract_sha256": digest(), "expanded_bytes": len(raw),
                     "content_sha256": hashlib.sha256(raw).hexdigest(),
                     "body": base64.b64encode(zlib.compress(raw)).decode("ascii")})


def _unique(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError("Duplicate JSON field")
        out[key] = value
    return out


def _json(raw):
    return json.loads(raw, object_pairs_hook=_unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Nonfinite JSON")))


def decode(wire):
    if not isinstance(wire, bytes) or len(wire) > MAX_WIRE:
        raise ValueError("Wire evidence exceeds limit")
    try:
        env = _json(wire)
        fields = {"version", "protocol", "contract_sha256", "expanded_bytes", "content_sha256", "body"}
        if not isinstance(env, dict) or set(env) != fields:
            raise ValueError("Unexpected envelope fields")
        if (env["version"] != "evidence-zlib-v1" or env["protocol"] != PROTOCOL_ID
                or env["contract_sha256"] != digest()):
            raise ValueError("Unsupported evidence contract")
        size = env["expanded_bytes"]
        if type(size) is not int or not 0 <= size <= MAX_EXPANDED:
            raise ValueError("Invalid expanded size")
        compressed = base64.b64decode(env["body"], validate=True)
        inflater = zlib.decompressobj()
        raw = inflater.decompress(compressed, size + 1)
        if (len(raw) != size or not inflater.eof or inflater.unused_data
                or inflater.unconsumed_tail or hashlib.sha256(raw).hexdigest() != env["content_sha256"]):
            raise ValueError("Evidence content mismatch or expansion limit")
        value = _json(raw)
        if expanded(value) != raw:
            raise ValueError("Noncanonical expanded evidence")
        return value
    except (TypeError, KeyError, zlib.error, UnicodeError) as exc:
        raise ValueError("Invalid evidence envelope") from exc
