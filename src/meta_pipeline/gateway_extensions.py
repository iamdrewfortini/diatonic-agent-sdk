"""Static review of Bifrost Go shared-object extensions; never loads code.

Local review schema versions are not a native Bifrost ABI guarantee. Go plugin
loading runs initializers, including through Bifrost VerifyBasePlugin; do not use
that function to inspect an untrusted .so or add a disabled plugin to production.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import stat
import struct
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

SHA = r"^[0-9a-f]{64}$"
REVIEW_VERSION = "bifrost-plugin-review-v1"
ABI_PROFILE = "bifrost-go-so-v1"
UPSTREAM_TRANSPORT_TAG = "transports/v1.5.13"
UPSTREAM_SOURCE_COMMIT = "6fc36e7d3c3ee3355f0d081001e34a1886abae7f"
UPSTREAM_LOADER_SHA256 = "56bba2e89c01bd21f2054c9201b427c47659c97e0b0df264040b303285c2d7d5"
REQUIRED_SYMBOLS = frozenset({"GetName", "Cleanup"})
OPTIONAL_SYMBOLS = frozenset({"Init", "HTTPTransportPreHook", "HTTPTransportPostHook",
    "HTTPTransportStreamChunkHook", "PreRequestHook", "PreLLMHook", "PreHook",
    "PostLLMHook", "PostHook", "PreMCPHook", "PostMCPHook", "PreMCPConnectionHook",
    "PostMCPConnectionHook", "Inject"})
MAX_PLUGIN_BYTES = 64 * 1024 * 1024


class Record(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class BuildProfile(Record):
    abi_profile: Literal["bifrost-go-so-v1"] = ABI_PROFILE
    bifrost_version: str = Field(min_length=1, max_length=64)
    source_commit: str = Field(pattern=r"^[0-9a-f]{40}$")
    go_version: str = Field(pattern=r"^go[0-9]+\.[0-9]+\.[0-9]+$")
    goos: Literal["linux"] = "linux"
    goarch: Literal["amd64", "arm64"]
    cgo_enabled: bool
    race_enabled: bool
    build_tags: tuple[str, ...] = Field(default=(), max_length=32)
    compiler_flags: tuple[str, ...] = Field(default=(), max_length=32)
    shared_dependencies_sha256: str = Field(pattern=SHA)


class PluginManifest(Record):
    schema_version: Literal["bifrost-plugin-review-v1"] = REVIEW_VERSION
    name: str = Field(pattern=r"^[a-z][a-z0-9_-]{0,63}$")
    version: str = Field(min_length=1, max_length=64)
    artifact_sha256: str = Field(pattern=SHA)
    source_sha256: str = Field(pattern=SHA)
    reviewed_source_sha256: str = Field(pattern=SHA)
    build: BuildProfile
    hooks: tuple[str, ...] = Field(max_length=32)
    permissions: tuple[str, ...] = Field(default=(), max_length=16)


class Inspection(Record):
    schema_version: Literal["bifrost-plugin-review-v1"] = REVIEW_VERSION
    status: Literal["blocked", "pending_runtime_build_evidence", "ready_for_isolated_abi_probe"]
    reasons: tuple[str, ...]
    artifact_sha256: str | None
    elf_arch: str | None
    symbols: tuple[str, ...]
    native_code_loaded: Literal[False] = False
    production_registration: Literal["pending"] = "pending"
    scope: str = "Static bytes/manifest comparison; symbol names do not prove Go function signatures, initialization safety or runtime ABI compatibility"


def _read_elf(path: Path):
    if path.suffix != ".so" or not path.is_absolute():
        raise ValueError("absolute_local_shared_object_required")
    # Pin the opened inode. No dlopen/plugin.Open/subprocess/import of library.
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or not 64 <= before.st_size <= MAX_PLUGIN_BYTES:
            raise ValueError("bounded_regular_plugin_required")
        data = stream.read(MAX_PLUGIN_BYTES + 1)
        after = os.fstat(stream.fileno())
    if ((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            or len(data) != before.st_size):
        raise ValueError("plugin_changed_during_inspection")
    if data[:7] != b"\x7fELF\x02\x01\x01":
        raise ValueError("supported_64bit_little_endian_ELF_required")
    e_type, machine = struct.unpack_from("<HH", data, 16)
    if e_type != 3 or machine not in {62, 183}:
        raise ValueError("supported_ELF_shared_object_required")
    architecture = {62: "amd64", 183: "arm64"}[machine]
    # Parse bounded static/dynamic symbol tables. Names alone never prove type
    # signatures; an isolated exact-build native ABI probe is still required.
    section_offset = struct.unpack_from("<Q", data, 40)[0]
    section_size, section_count = struct.unpack_from("<HH", data, 58)
    if section_count == 0 or section_count > 4096 or section_size < 64:
        raise ValueError("bounded_ELF_section_table_required")
    if section_offset + section_size * section_count > len(data):
        raise ValueError("truncated_ELF_section_table")
    sections = []
    for i in range(section_count):
        row = struct.unpack_from("<IIQQQQIIQQ", data, section_offset + i * section_size)
        if row[1] != 8 and row[4] + row[5] > len(data):  # NOBITS has no stored body
            raise ValueError("truncated_ELF_section")
        sections.append(row)
    names = set()
    for row in sections:
        if row[1] not in {2, 11}:
            continue
        offset, size, linked, entry_size = row[4], row[5], row[6], row[9]
        if entry_size < 24 or size % entry_size or linked >= len(sections) or size // entry_size > 1000000:
            raise ValueError("invalid_ELF_symbol_table")
        strings = sections[linked]
        table = data[strings[4]:strings[4] + strings[5]]
        for pos in range(offset, offset + size, entry_size):
            name_offset, info, _, index = struct.unpack_from("<IBBH", data, pos)
            if name_offset >= len(table) or index == 0 or info >> 4 not in {1, 2} or info & 15 != 2:
                continue
            end = table.find(b"\0", name_offset, min(len(table), name_offset + 1024))
            if end < 0:
                continue
            name = table[name_offset:end].decode("utf-8", errors="replace")
            short = name.rsplit(".", 1)[-1]
            if short in REQUIRED_SYMBOLS | OPTIONAL_SYMBOLS:
                names.add(short)
    return data, architecture, tuple(sorted(names))


class PluginInspector:
    """Coordinator-owned allowlists; registration plans never apply themselves."""
    def __init__(self, *, allowed_hooks: frozenset[str] = frozenset(),
                 approved_source_hashes: frozenset[str] = frozenset()):
        if not allowed_hooks.issubset(OPTIONAL_SYMBOLS):
            raise ValueError("unsupported_hook_profile")
        import re
        if any(not re.fullmatch(SHA, value) for value in approved_source_hashes):
            raise ValueError("approved_source_hash_required")
        self.allowed_hooks = frozenset(allowed_hooks)
        self.approved_source_hashes = frozenset(approved_source_hashes)

    def inspect(self, path: Path, manifest: PluginManifest, *, runtime: BuildProfile | None):
        # Revalidate nested collections so callers cannot mutate a frozen record's
        # mutable internals to bypass the manifest schema.
        manifest = PluginManifest.model_validate(manifest.model_dump())
        if runtime is not None:
            runtime = BuildProfile.model_validate(runtime.model_dump())
        try:
            data, architecture, symbols = _read_elf(Path(path))
        except (OSError, ValueError, struct.error):
            return Inspection(status="blocked", reasons=("invalid_or_unavailable_plugin_artifact",),
                              artifact_sha256=None, elf_arch=None, symbols=())
        digest = hashlib.sha256(data).hexdigest()
        reasons = []
        if digest != manifest.artifact_sha256:
            reasons.append("artifact_hash_mismatch")
        if (manifest.source_sha256 != manifest.reviewed_source_sha256
                or manifest.source_sha256 not in self.approved_source_hashes):
            reasons.append("source_not_independently_reviewed")
        if architecture != manifest.build.goarch:
            reasons.append("artifact_platform_mismatch")
        if not REQUIRED_SYMBOLS.issubset(symbols):
            reasons.append("required_export_symbols_missing")
        declared = set(manifest.hooks)
        found = set(symbols) - REQUIRED_SYMBOLS
        if len(declared) != len(manifest.hooks) or declared != found:
            reasons.append("declared_export_hooks_mismatch")
        if not declared.issubset(self.allowed_hooks):
            reasons.append("hook_not_authorized")
        # Extension code gets no additional authority. Permissions beyond the
        # reviewed in-process postprocessing capability stay blocked.
        if manifest.permissions:
            reasons.append("plugin_permissions_not_granted")
        if runtime is not None and runtime != manifest.build:
            reasons.append("runtime_build_ABI_mismatch")
        status = "blocked" if reasons else "pending_runtime_build_evidence" if runtime is None else "ready_for_isolated_abi_probe"
        if runtime is None and not reasons:
            reasons.append("exact_deployed_Go_build_and_shared_dependency_evidence_required")
        return Inspection(status=status, reasons=tuple(reasons), artifact_sha256=digest,
                          elf_arch=architecture, symbols=symbols)

    def registration_plan(self, path: Path, manifest: PluginManifest, *, runtime: BuildProfile | None):
        inspection = self.inspect(path, manifest, runtime=runtime)
        return {"apply": False, "inspection": inspection.model_dump(mode="json"),
                "registration_candidate": {"name": manifest.name, "path": str(path),
                                           "enabled": False, "config": {}},
                "warning": "Render only. Even a disabled Bifrost plugin may invoke plugin.Open and execute initializers. Do not add to a live config before isolated ABI/security validation and existing rollout authorization.",
                "preserve_native_governance": True, "provider_or_budget_changes": False}

    def build_plan(self, *, source_dir: Path, source_sha256: str, profile: BuildProfile):
        if source_sha256 not in self.approved_source_hashes:
            raise ValueError("source_not_independently_reviewed")
        if not source_dir.is_absolute():
            raise ValueError("absolute_reviewed_source_directory_required")
        # A plan is deliberately not a code compiler/installer. No user supplied
        # source is executed, no module dependency downloads or hooks are run.
        return {"execute": False, "source_sha256": source_sha256,
                "argv": ["go", "build", "-buildmode=plugin", "-o", "reviewed-plugin.so", "."],
                "working_directory": str(source_dir), "required_exact_build": profile.model_dump(mode="json"),
                "pending": ["reviewed complete pinned source tree and module lock", "exact deployed Go toolchain and shared package build identity", "isolated build and native ABI/security tests"],
                "production_registration": "pending"}
