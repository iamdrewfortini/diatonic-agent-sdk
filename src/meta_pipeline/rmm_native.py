"""Authenticated, bounded, read-only transport for the native Diatonic RMM wall API."""
from __future__ import annotations

import hashlib
import json
import math
import re
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

import httpx

from .rmm import Observation, RMMProjection

MAX_RESPONSE_BYTES = 262144
MAX_OBSERVATION_AGE = 60.0
MAX_FUTURE_SKEW = 5.0
_TOKEN = re.compile(r"[A-Za-z0-9_-]{40,128}\Z")
_SCOPE = "wall.snapshot.read"


@dataclass(frozen=True, repr=False)
class RMMReadGrant:
    """Explicit local binding for one host and the snapshot read scope only."""
    endpoint: str
    host: str
    scopes: frozenset[str]

    def __post_init__(self) -> None:
        if not isinstance(self.endpoint, str) or not isinstance(self.host, str):
            raise ValueError("Malformed RMM grant")
        try:
            parsed = urlsplit(self.endpoint)
            port = parsed.port
        except ValueError:
            raise ValueError("Malformed RMM grant endpoint") from None
        if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None
                or parsed.password is not None or parsed.query or parsed.fragment
                or parsed.path not in ("", "/") or port is None):
            raise ValueError("RMM grant requires a pinned HTTPS origin")
        if parsed.hostname.lower() != self.host.lower():
            raise ValueError("RMM grant host does not match endpoint")
        if type(self.scopes) is not frozenset or self.scopes != frozenset({_SCOPE}):
            raise ValueError("RMM grant must contain only wall.snapshot.read")


class NativeRMMTransport:
    """Fetch one fresh native snapshot. This client exposes no write operation."""

    def __init__(self, grant: RMMReadGrant, bearer_token: str, *, ca_file: str,
                 timeout: float = 5.0, transport: httpx.BaseTransport | None = None):
        if not isinstance(grant, RMMReadGrant):
            raise ValueError("Validated RMM read grant required")
        if not isinstance(bearer_token, str) or not _TOKEN.fullmatch(bearer_token):
            raise ValueError("Valid RMM bearer credential required")
        if not isinstance(ca_file, str) or not ca_file:
            raise ValueError("RMM CA file required")
        if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= 30:
            raise ValueError("Bounded positive timeout required")
        self._grant = grant
        self._token = bearer_token
        self._client = httpx.Client(verify=ca_file, timeout=timeout, follow_redirects=False,
                                    trust_env=False, transport=transport)

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> NativeRMMTransport:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def observe(self, *, now: float | None = None) -> list[Observation]:
        """GET /api/wall/snapshot and return the existing provenance-bearing projection."""
        parsed = urlsplit(self._grant.endpoint)
        if parsed.hostname is None or parsed.hostname.lower() != self._grant.host.lower():
            raise ValueError("RMM grant host binding changed")
        url = self._grant.endpoint.rstrip("/") + "/api/wall/snapshot"
        expected_url = httpx.URL(url)
        try:
            with self._client.stream("GET", expected_url, headers={
                    "Authorization": "Bearer " + self._token,
                    "Accept": "application/json",
                    "Accept-Encoding": "identity"}) as response:
                if response.status_code != 200:
                    raise ValueError("RMM snapshot request failed")
                _require_response_url(response, expected_url)
                if response.headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json":
                    raise ValueError("RMM returned a non-JSON snapshot")
                encodings = response.headers.get_list("content-encoding")
                if len(encodings) > 1 or (encodings and encodings[0].strip().lower() not in ("", "identity")):
                    raise ValueError("RMM response content encoding is not allowed")
                lengths = response.headers.get_list("content-length")
                if len(lengths) > 1:
                    raise ValueError("RMM response length is ambiguous")
                if lengths:
                    length = lengths[0]
                    if not re.fullmatch(r"[0-9]+", length) or int(length) > MAX_RESPONSE_BYTES:
                        raise ValueError("RMM response length is invalid or oversized")
                raw = bytearray()
                for chunk in response.iter_bytes():
                    raw.extend(chunk)
                    if len(raw) > MAX_RESPONSE_BYTES:
                        raise ValueError("RMM snapshot exceeds response bound")
                if lengths and len(raw) != int(lengths[0]):
                    raise ValueError("RMM response length does not match its framing")
        except httpx.HTTPError:
            raise ValueError("RMM snapshot transport failed") from None
        try:
            envelope = json.loads(bytes(raw), object_pairs_hook=_unique_object,
                                  parse_constant=_reject_constant)
        except (UnicodeError, json.JSONDecodeError, ValueError, TypeError):
            raise ValueError("RMM snapshot JSON is malformed") from None
        if not isinstance(envelope, dict) or set(envelope) != {"snapshot", "cursor"}:
            raise ValueError("RMM snapshot envelope is malformed")
        if not isinstance(envelope["cursor"], str) or not re.fullmatch(r'"[0-9a-f]{64}"', envelope["cursor"]):
            raise ValueError("RMM snapshot cursor is malformed")
        snapshot = envelope["snapshot"]
        if not isinstance(snapshot, dict):
            raise ValueError("RMM snapshot projection is malformed")
        observed_at = snapshot.get("utc")
        current = time.time() if now is None else now
        if (type(observed_at) not in (int, float) or not math.isfinite(observed_at)
                or type(current) not in (int, float) or not math.isfinite(current)
                or observed_at > current + MAX_FUTURE_SKEW
                or current - observed_at > MAX_OBSERVATION_AGE):
            raise ValueError("RMM snapshot is stale or future dated")
        if snapshot.get("allowed_actions") != [] or snapshot.get("allowed_guests") != []:
            raise ValueError("RMM snapshot contains an execution grant")
        computed_cursor = _native_cursor(snapshot)
        if envelope["cursor"] != computed_cursor:
            raise ValueError("RMM snapshot cursor does not match its projection")
        etags = response.headers.get_list("etag")
        if len(etags) > 1 or (etags and etags[0] != computed_cursor):
            raise ValueError("RMM snapshot ETag does not match its cursor")
        return RMMProjection(source_ref=self._grant.endpoint.rstrip("/")).ingest_wall(snapshot)


def _require_response_url(response: httpx.Response, expected_url: httpx.URL) -> None:
    if response.url != expected_url:
        raise ValueError("RMM response URL does not match the grant")


def _native_cursor(snapshot: dict[str, Any]) -> str:
    """Match api.projections.cursor: SHA-256 of compact insertion-ordered JSON."""
    payload = json.dumps(snapshot, separators=(",", ":"), allow_nan=False).encode()
    return '"' + hashlib.sha256(payload).hexdigest() + '"'


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


def _reject_constant(_: str) -> None:
    raise ValueError("non-finite JSON number")
