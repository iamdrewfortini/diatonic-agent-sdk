"""Unattended 1Password SDK broker; workers receive scoped Bifrost keys only.

The privileged broker owns SDK authentication. Its bootstrap credential is an
existing systemd/Kubernetes-injected private file, never a model/worker argument.
No CLI, desktop authentication, account password, shell, secret cache or logging.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
import hashlib
import os
from pathlib import Path
import re
import stat
from typing import Literal, Protocol
from urllib.parse import unquote, urlsplit

from pydantic import SecretStr

IDENTIFIER = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
MAX_SECRET_BYTES = 16384


class SecretUnavailable(RuntimeError):
    """Only stable reason codes cross the broker boundary."""
    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


def validate_reference(reference: str) -> str:
    """Accept a single exact field reference, never a query/template/listing."""
    if not isinstance(reference, str) or not reference.startswith("op://") or len(reference) > 2048:
        raise ValueError("exact_secret_reference_required")
    if (any(ord(c) < 32 or ord(c) == 127 for c in reference)
            or any(c in reference for c in "?#") or re.search(r"%(?![0-9A-Fa-f]{2})", reference)):
        raise ValueError("invalid_secret_reference")
    parsed = urlsplit(reference)
    if parsed.scheme != "op" or parsed.query or parsed.fragment or not parsed.netloc:
        raise ValueError("invalid_secret_reference")
    segments = [parsed.netloc, *parsed.path.split("/")[1:]]
    if len(segments) not in {3, 4}:
        raise ValueError("exact_field_reference_required")
    for segment in segments:
        if (not segment or len(segment) > 255 or unquote(segment) in {".", ".."}
                or any(ord(c) < 32 or ord(c) == 127 for c in unquote(segment))
                or any(c in unquote(segment) for c in ("/", "\\", "\x00", "*", "?", "#", "{", "}"))):
            raise ValueError("invalid_secret_reference")
    return reference


def _bounded_value(value, *, scoped_key=False) -> SecretStr:
    if isinstance(value, SecretStr):
        value = value.get_secret_value()
    if (not isinstance(value, str) or not value or len(value.encode("utf-8")) > MAX_SECRET_BYTES
            or any(ord(c) < 33 or ord(c) > 126 for c in value)):
        raise SecretUnavailable("invalid_secret_value")
    if scoped_key and not value.startswith("sk-bf-"):
        raise SecretUnavailable("not_a_bifrost_virtual_key")
    return SecretStr(value)


@dataclass(frozen=True)
class SecretBinding:
    binding_id: str
    reference: str = field(repr=False)
    purpose: Literal["gateway_virtual_key", "provider_upstream", "gateway_admin"]
    gateway_id: str
    tenant: str
    scope_verified: bool = False

    def __post_init__(self):
        validate_reference(self.reference)
        if (not all(isinstance(s, str) and IDENTIFIER.fullmatch(s)
                    for s in (self.binding_id, self.gateway_id, self.tenant))
                or self.purpose not in {"gateway_virtual_key", "provider_upstream", "gateway_admin"}
                or type(self.scope_verified) is not bool):
            raise ValueError("invalid_secret_binding")

    @property
    def opaque_id(self):
        return hashlib.sha256(self.binding_id.encode()).hexdigest()


class BootstrapTokenSource(Protocol):
    def load(self) -> SecretStr: ...
    def available(self) -> bool: ...


@dataclass(frozen=True)
class InjectedCredentialFile:
    """Existing injection only; no token creation, environment export or writes."""
    path: Path = field(repr=False)

    def __post_init__(self):
        object.__setattr__(self, "path", Path(self.path))

    def load(self) -> SecretStr:
        try:
            fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd, "rb") as stream:
                info = os.fstat(stream.fileno())
                if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) & 0o077
                        or info.st_uid not in {os.geteuid(), 0} or info.st_size > MAX_SECRET_BYTES):
                    raise SecretUnavailable("bootstrap_file_not_private_regular")
                raw = stream.read(MAX_SECRET_BYTES + 1)
            if len(raw) > MAX_SECRET_BYTES:
                raise SecretUnavailable("bootstrap_too_large")
            # Service managers often supply one final LF; embedded whitespace is
            # forbidden and no token is normalized beyond that file terminator.
            text = raw.decode("utf-8")
            if text.endswith("\n"):
                text = text[:-1]
            return _bounded_value(text)
        except SecretUnavailable:
            raise
        except (OSError, UnicodeError, ValueError):
            raise SecretUnavailable("bootstrap_unavailable") from None

    def available(self) -> bool:
        # Status checks metadata only, never read/authenticate/reveal a token.
        try:
            info = self.path.lstat()
            return (stat.S_ISREG(info.st_mode) and not stat.S_IMODE(info.st_mode) & 0o077
                    and info.st_uid in {os.geteuid(), 0} and 0 < info.st_size <= MAX_SECRET_BYTES)
        except OSError:
            return False


@dataclass(frozen=True)
class SystemdCredentialToken:
    credential_name: str = field(repr=False)

    def __post_init__(self):
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", self.credential_name) or self.credential_name in {".", ".."}:
            raise ValueError("invalid_credential_name")

    def _source(self):
        directory = os.environ.get("CREDENTIALS_DIRECTORY")
        if not directory or not Path(directory).is_absolute():
            raise SecretUnavailable("systemd_credential_not_injected")
        return InjectedCredentialFile(Path(directory) / self.credential_name)

    def load(self):
        source=self._source()
        try:
            return source.load()
        except SecretUnavailable:
            from .systemd_credentials import read
            try:
                return read(self.credential_name)
            except (OSError,ValueError):
                raise SecretUnavailable("bootstrap_file_not_private_regular") from None

    def available(self):
        try:
            from .systemd_credentials import available
            return self._source().available() or available(self.credential_name)
        except SecretUnavailable:
            return False


class SDKResolver(Protocol):
    async def resolve(self, reference: str) -> str: ...


class OfficialSDKResolver:
    """Official onepassword-sdk API, service account authentication exclusively."""
    def __init__(self, client):
        self._client = client

    @classmethod
    async def authenticate(cls, token: SecretStr, *, timeout_seconds=15):
        if not isinstance(token, SecretStr):
            raise SecretUnavailable("service_account_injection_required")
        try:
            from onepassword.client import Client
        except ImportError:
            raise SecretUnavailable("onepassword_sdk_not_installed") from None
        try:
            async with asyncio.timeout(timeout_seconds):
                client = await Client.authenticate(auth=token.get_secret_value(),
                    integration_name="Diatonic credential broker", integration_version="1.0.0")
            return cls(client)
        except Exception:
            raise SecretUnavailable("sdk_authentication_pending") from None

    async def resolve(self, reference):
        return await self._client.secrets.resolve(reference)


class OnePasswordBroker:
    """Trusted broker service object; do not give SDK/bootstrap to agent workers."""
    def __init__(self, bindings: list[SecretBinding], *, resolver: SDKResolver | None = None,
                 timeout_seconds: float = 15):
        if type(timeout_seconds) not in (int, float) or not 0 < timeout_seconds <= 60:
            raise ValueError("bounded_sdk_timeout_required")
        self._bindings = {binding.binding_id: binding for binding in bindings}
        if len(self._bindings) != len(bindings):
            raise ValueError("duplicate_secret_binding")
        self._resolver = resolver
        self.timeout_seconds = timeout_seconds

    @classmethod
    async def from_service_account(cls, bindings: list[SecretBinding], *,
                                   token_source: BootstrapTokenSource,
                                   timeout_seconds=15, authenticate=None):
        # authenticate injection exists for deterministic tests; production uses
        # only the official SDK, with no interactive fallback.
        broker = cls(bindings, timeout_seconds=timeout_seconds)
        token = token_source.load()
        try:
            factory = authenticate or OfficialSDKResolver.authenticate
            async with asyncio.timeout(timeout_seconds):
                resolver = await factory(token, timeout_seconds=timeout_seconds)
        except SecretUnavailable:
            raise
        except Exception:
            raise SecretUnavailable("sdk_authentication_pending") from None
        finally:
            token = None
        broker._resolver = resolver
        return broker

    def _worker_binding(self, binding_id, gateway_id, tenant):
        binding = self._bindings.get(binding_id)
        if (binding is None or binding.purpose != "gateway_virtual_key" or not binding.scope_verified
                or binding.gateway_id != gateway_id or binding.tenant != tenant):
            raise SecretUnavailable("worker_scope_denied")
        return binding

    async def resolve_worker_key(self, binding_id: str, *, gateway_id: str, tenant: str) -> SecretStr:
        binding = self._worker_binding(binding_id, gateway_id, tenant)
        if self._resolver is None:
            raise SecretUnavailable("sdk_bootstrap_pending")
        try:
            async with asyncio.timeout(self.timeout_seconds):
                raw = await self._resolver.resolve(binding.reference)
            return _bounded_value(raw, scoped_key=True)
        except SecretUnavailable:
            raise
        except Exception:
            # SDK errors can contain values, vault/item names and request bodies.
            raise SecretUnavailable("sdk_resolution_pending") from None

    async def probe_worker_binding(self, binding_id, *, gateway_id, tenant):
        try:
            await self.resolve_worker_key(binding_id, gateway_id=gateway_id, tenant=tenant)
            return {"status": "resolved_scoped_key", "secret_disclosed": False}
        except SecretUnavailable as error:
            return {"status": "pending", "reason": error.reason, "secret_disclosed": False}

    def status(self):
        return {"mode": "unattended_official_sdk", "sdk_authenticated": self._resolver is not None,
                "configured_bindings": len(self._bindings),
                "bindings": [{"opaque_id": b.opaque_id,
                    "worker_eligible": b.purpose == "gateway_virtual_key" and b.scope_verified}
                    for b in self._bindings.values()],
                "interactive_authentication": False, "cli_dependency": False,
                "scope": "configuration/authentication status; no provider entitlement or inference acceptance"}
