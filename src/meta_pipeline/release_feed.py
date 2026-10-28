"""Download a coordinator's pinned signed release into the local admission spool.

This module only stages verified bytes. It never installs, activates, or starts a
service. A caller must provide an explicit trusted HTTPS profile and public key.
"""
from __future__ import annotations

import hashlib
import math
import os
import ssl
from pathlib import Path
from urllib.parse import urlsplit

import httpx
from pydantic import SecretStr

from .secret_broker import BootstrapTokenSource

from .release_manager import (MAX_FILE, MAX_MANIFEST, MAX_TOTAL, SSD_RESERVE_BYTES,
                              UpdateBlocked, ReleaseManager, _read, _secure_path, _sync_directory,
                              _validate_wheel, verify_envelope)


class CoordinatorProfile:
    """Fixed HTTPS release directory, e.g. https://updates.example/releases/stable/."""

    def __init__(self, base_url: str):
        if not isinstance(base_url, str):
            raise UpdateBlocked("explicit_coordinator_profile_required")
        parsed = urlsplit(base_url)
        if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
                or parsed.query or parsed.fragment or not parsed.path.startswith("/")
                or not parsed.path.endswith("/")):
            raise UpdateBlocked("pinned_https_coordinator_profile_required")
        try:
            port = parsed.port or 443
        except ValueError:
            raise UpdateBlocked("invalid_coordinator_profile") from None
        self.base_url = base_url
        self.origin = (parsed.scheme, parsed.hostname.lower(), port)
        self.path = parsed.path

    def url(self, name: str) -> str:
        if name != "update.json" and (not name.endswith(".whl") or "/" in name or "\\" in name or name in {".", ".."}):
            raise UpdateBlocked("unsafe_coordinator_object_name")
        return self.base_url + name


class SignedReleaseDownloader:
    """Fetch and stage one signed feed entry using a caller-supplied HTTPX transport."""

    AUTH_HEADERS = {"PRIVATE-TOKEN", "DEPLOY-TOKEN", "JOB-TOKEN", "Authorization"}

    def __init__(self, profile: CoordinatorProfile, public_key: Path, spool: Path, *,
                 trusted_uid: int = 0, transport=None, timeout: float = 20.0,
                 token_source: BootstrapTokenSource | None = None,
                 management_token: SecretStr | None = None,
                 token_header: str | None = None, total_staged_bytes: int = 64 * 1024 ** 2,
                 capacity_reader=None, ssl_context: ssl.SSLContext | None = None):
        if not isinstance(profile, CoordinatorProfile):
            raise UpdateBlocked("explicit_coordinator_profile_required")
        if ((token_source is not None and management_token is not None)
                or (token_header is not None and (not isinstance(token_header, str) or token_header not in self.AUTH_HEADERS))
                or ((token_source is not None or management_token is not None) != (token_header is not None))):
            raise UpdateBlocked("invalid_management_credential_configuration")
        if management_token is not None and not isinstance(management_token, SecretStr):
            raise UpdateBlocked("secretstr_management_credential_required")
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or not 0 < timeout <= 60:
            raise UpdateBlocked("bounded_finite_timeout_required")
        if type(total_staged_bytes) is not int or not 1 <= total_staged_bytes <= MAX_TOTAL:
            raise UpdateBlocked("bounded_staging_budget_required")
        if ssl_context is not None and (not isinstance(ssl_context, ssl.SSLContext)
                or ssl_context.verify_mode != ssl.CERT_REQUIRED or not ssl_context.check_hostname):
            raise UpdateBlocked("verified_tls_context_required")
        self.profile, self.public_key, self.spool = profile, Path(public_key), Path(spool)
        self.uid, self.transport, self.timeout = trusted_uid, transport, float(timeout)
        self.token_source, self.management_token, self.token_header = token_source, management_token, token_header
        self.total_staged_bytes = total_staged_bytes
        self.capacity_reader = capacity_reader or ReleaseManager._free_bytes
        self.ssl_context = ssl_context or ssl.create_default_context()

    def _fetch(self, client: httpx.Client, name: str, maximum: int) -> bytearray:
        url = self.profile.url(name)
        try:
            with client.stream("GET", url, headers={"Accept": "application/octet-stream"}) as response:
                if response.status_code != 200 or str(response.url) != url:
                    raise UpdateBlocked("coordinator_response_rejected")
                if response.headers.get("content-encoding", "identity").lower() not in {"", "identity"}:
                    raise UpdateBlocked("encoded_coordinator_response_rejected")
                length = response.headers.get("content-length")
                if length is not None:
                    try:
                        if int(length) < 0 or int(length) > maximum:
                            raise UpdateBlocked("coordinator_object_size_limit")
                    except ValueError:
                        raise UpdateBlocked("invalid_coordinator_content_length") from None
                data = bytearray()
                for chunk in response.iter_bytes():
                    data.extend(chunk)
                    if len(data) > maximum:
                        raise UpdateBlocked("coordinator_object_size_limit")
            return data
        except httpx.HTTPError:
            raise UpdateBlocked("coordinator_transport_failed") from None

    def _publish(self, name: str, data: bytes | bytearray, *, mode: int) -> bool:
        target = self.spool / name
        if target.exists() or target.is_symlink():
            existing = _read(target, maximum=max(len(data), MAX_MANIFEST), uid=self.uid)
            if existing != data:
                raise UpdateBlocked("spool_artifact_conflict")
            return False
        temporary = self.spool / (".feed-" + hashlib.sha256(name.encode()).hexdigest() + ".tmp")
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(temporary, mode)
            try:
                os.link(temporary, target, follow_symlinks=False)
                published = True
            except FileExistsError:
                existing = _read(target, maximum=max(len(data), MAX_MANIFEST), uid=self.uid)
                if existing != data:
                    raise UpdateBlocked("spool_artifact_conflict")
                published = False
            return published
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
            if "published" in locals() and published:
                _sync_directory(self.spool)

    def stage(self) -> dict:
        _secure_path(self.spool, directory=True, uid=self.uid)
        public = _read(self.public_key, maximum=16384, uid=self.uid)
        update_path = self.spool / "update.json"
        existing_envelope = _read(update_path, maximum=MAX_MANIFEST, uid=self.uid) if update_path.exists() or update_path.is_symlink() else None
        token = self.management_token
        if self.token_source is not None:
            # Resolve the existing management credential exactly once per stage call.
            token = self.token_source.load()
            if not isinstance(token, SecretStr):
                raise UpdateBlocked("secretstr_management_credential_required")
        request_headers = {}
        if token is not None:
            value = token.get_secret_value()
            if (not isinstance(value, str) or not value or len(value) > 16384
                    or value != value.strip()
                    or any(not 0x20 <= ord(char) <= 0x7e for char in value)):
                raise UpdateBlocked("invalid_management_credential")
            request_headers[self.token_header] = value
        with httpx.Client(transport=self.transport, verify=self.ssl_context, timeout=self.timeout,
                          follow_redirects=False, trust_env=False, proxy=None,
                          headers=request_headers) as client:
            envelope = self._fetch(client, "update.json", MAX_MANIFEST)
            manifest = verify_envelope(envelope, public)
            if existing_envelope is not None and existing_envelope != envelope:
                raise UpdateBlocked("existing_update_envelope_conflict")
            processed = self.spool / ("applied-" + hashlib.sha256(envelope).hexdigest() + ".json")
            if processed.exists() or processed.is_symlink():
                if _read(processed, maximum=MAX_MANIFEST, uid=self.uid) != envelope:
                    raise UpdateBlocked("processed_envelope_conflict")
                raise UpdateBlocked("release_already_applied")
            items = (manifest.wheel, *manifest.dependencies)
            incoming_bytes = sum(item.size_bytes for item in items)
            if incoming_bytes > self.total_staged_bytes:
                raise UpdateBlocked("staged_release_budget_exceeded")
            free_bytes = self.capacity_reader(self.spool)
            if type(free_bytes) is not int or free_bytes < SSD_RESERVE_BYTES + incoming_bytes:
                raise UpdateBlocked("ssd_reserve_or_staging_capacity_denied")
            staged = []
            for item in items:
                data = self._fetch(client, item.filename, item.size_bytes)
                if len(data) != item.size_bytes or hashlib.sha256(data).hexdigest() != item.sha256:
                    raise UpdateBlocked("artifact_size_or_hash_mismatch")
                target = self.spool / item.filename
                if target.exists() or target.is_symlink():
                    if _read(target, maximum=MAX_FILE, uid=self.uid) != data:
                        raise UpdateBlocked("spool_artifact_conflict")
                    _validate_wheel(target)
                else:
                    temp = self.spool / (".validate-" + hashlib.sha256(item.filename.encode()).hexdigest() + ".whl")
                    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                    try:
                        with os.fdopen(fd, "wb") as stream:
                            stream.write(data); stream.flush(); os.fsync(stream.fileno())
                        _validate_wheel(temp)
                    finally:
                        try: temp.unlink()
                        except FileNotFoundError: pass
                staged.append((item.filename, data))
            for filename, data in staged:
                self._publish(filename, data, mode=0o644)
            created = self._publish("update.json", envelope, mode=0o644)
            return {"status": "staged" if created else "already_staged",
                    "version": manifest.version, "artifacts": len(items)}
