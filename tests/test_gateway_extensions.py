"""Synthetic ELF records only; these fixtures contain no executable plugin code."""
import hashlib
from pathlib import Path
import struct

import pytest
from pydantic import ValidationError

from meta_pipeline.gateway_extensions import (BuildProfile, PluginInspector,
    PluginManifest, REQUIRED_SYMBOLS, REVIEW_VERSION)


SOURCE = "a"*64


def elf_fixture(path, symbols=("GetName", "Cleanup", "PostLLMHook"), machine=62):
    names = b"\0"; offsets = []
    for name in symbols:
        offsets.append(len(names)); names += ("fixture."+name).encode()+b"\0"
    symbol_bytes = b"\0"*24
    for offset in offsets:
        symbol_bytes += struct.pack("<IBBHQQ", offset, 0x12, 0, 1, 0, 0)
    string_offset = 64
    symbol_offset = string_offset + len(names)
    sections_offset = symbol_offset + len(symbol_bytes)
    ident = b"\x7fELF\x02\x01\x01" + b"\0"*9
    header = ident + struct.pack("<HHIQQQIHHHHHH", 3, machine, 1, 0, 0, sections_offset, 0, 64, 0, 0, 64, 3, 0)
    sections = b"\0"*64
    sections += struct.pack("<IIQQQQIIQQ", 0, 3, 0, 0, string_offset, len(names), 0, 0, 1, 0)
    sections += struct.pack("<IIQQQQIIQQ", 0, 2, 0, 0, symbol_offset, len(symbol_bytes), 1, 0, 8, 24)
    data = header + names + symbol_bytes + sections
    path.write_bytes(data)
    return hashlib.sha256(data).hexdigest()


def profile(**changes):
    return BuildProfile(**{**dict(bifrost_version="fixture-v1.5.13", source_commit="b"*40,
        go_version="go1.24.3", goarch="amd64", cgo_enabled=True, race_enabled=False,
        shared_dependencies_sha256="c"*64), **changes})


def manifest(digest, **changes):
    return PluginManifest(**{**dict(name="fixture-postprocessor", version="1.0.0",
        artifact_sha256=digest, source_sha256=SOURCE, reviewed_source_sha256=SOURCE,
        build=profile(), hooks=("PostLLMHook",)), **changes})


def inspector():
    return PluginInspector(allowed_hooks=frozenset({"PostLLMHook"}), approved_source_hashes=frozenset({SOURCE}))


def test_static_artifact_review_is_never_native_activation(tmp_path):
    path = tmp_path / "reviewed.so"; digest = elf_fixture(path)
    result = inspector().inspect(path, manifest(digest), runtime=profile())
    assert result.status == "ready_for_isolated_abi_probe"
    assert REQUIRED_SYMBOLS.issubset(result.symbols)
    assert not result.native_code_loaded and result.production_registration == "pending"
    plan = inspector().registration_plan(path, manifest(digest), runtime=profile())
    assert not plan["apply"] and not plan["registration_candidate"]["enabled"]
    assert "initializers" in plan["warning"]
    assert not plan["provider_or_budget_changes"] and plan["preserve_native_governance"]


def test_missing_exact_runtime_build_evidence_remains_pending(tmp_path):
    path = tmp_path / "reviewed.so"; digest = elf_fixture(path)
    result = inspector().inspect(path, manifest(digest), runtime=None)
    assert result.status == "pending_runtime_build_evidence" and not result.native_code_loaded


@pytest.mark.parametrize("change", [
    {"go_version": "go1.24.4"}, {"bifrost_version": "different"},
    {"source_commit": "d"*40}, {"goarch": "arm64"}, {"cgo_enabled": False},
    {"race_enabled": True}, {"build_tags": ("extra",)},
    {"compiler_flags": ("-trimpath",)}, {"shared_dependencies_sha256": "d"*64}])
def test_exact_abi_profile_mismatch_blocks(tmp_path, change):
    path = tmp_path / "reviewed.so"; digest = elf_fixture(path)
    result = inspector().inspect(path, manifest(digest), runtime=profile(**change))
    assert result.status == "blocked" and "runtime_build_ABI_mismatch" in result.reasons


@pytest.mark.parametrize("change,reason", [
    ({"artifact_sha256": "d"*64}, "artifact_hash_mismatch"),
    ({"reviewed_source_sha256": "d"*64}, "source_not_independently_reviewed"),
    ({"source_sha256": "d"*64, "reviewed_source_sha256": "d"*64}, "source_not_independently_reviewed"),
    ({"hooks": ()}, "declared_export_hooks_mismatch"),
    ({"hooks": ("PostLLMHook", "PostLLMHook")}, "declared_export_hooks_mismatch"),
    ({"permissions": ("provider_secret_read",)}, "plugin_permissions_not_granted")])
def test_hash_source_hooks_and_permissions_fail_closed(tmp_path, change, reason):
    path = tmp_path / "reviewed.so"; digest = elf_fixture(path)
    result = inspector().inspect(path, manifest(digest, **change), runtime=profile())
    assert result.status == "blocked" and reason in result.reasons


def test_undeclared_routing_hook_and_missing_base_symbols_rejected(tmp_path):
    path = tmp_path / "routing.so"; digest = elf_fixture(path, ("GetName", "Cleanup", "PreRequestHook"))
    result = inspector().inspect(path, manifest(digest, hooks=("PreRequestHook",)), runtime=profile())
    assert "hook_not_authorized" in result.reasons
    digest = elf_fixture(path, ("GetName", "PostLLMHook"))
    result = inspector().inspect(path, manifest(digest), runtime=profile())
    assert "required_export_symbols_missing" in result.reasons


@pytest.mark.parametrize("data", [b"not executable", b"\x7fELF"+b"\0"*100, b"\x7fELF\x02\x01\x01"+b"\0"*57])
def test_malformed_hostile_artifacts_block_without_loading(tmp_path, data):
    path = tmp_path / "bad.so"; path.write_bytes(data)
    result = inspector().inspect(path, manifest("a"*64), runtime=profile())
    assert result.status == "blocked" and not result.native_code_loaded


def test_symlink_truncation_and_platform_mismatch(tmp_path):
    path = tmp_path / "original.so"; digest = elf_fixture(path)
    alias = tmp_path / "alias.so"; alias.symlink_to(path)
    assert inspector().inspect(alias, manifest(digest), runtime=profile()).status == "blocked"
    damaged = bytearray(path.read_bytes()); struct.pack_into("<Q", damaged, 40, 2**63)
    path.write_bytes(damaged)
    assert inspector().inspect(path, manifest(digest), runtime=profile()).status == "blocked"
    digest = elf_fixture(path, machine=183)
    assert "artifact_platform_mismatch" in inspector().inspect(path, manifest(digest), runtime=profile()).reasons


def test_versions_and_build_plan_no_compilation_or_registration(tmp_path):
    with pytest.raises(ValidationError):
        manifest("a"*64, schema_version="unknown")
    plan = inspector().build_plan(source_dir=tmp_path, source_sha256=SOURCE, profile=profile())
    assert not plan["execute"] and plan["production_registration"] == "pending"
    assert plan["argv"] == ["go", "build", "-buildmode=plugin", "-o", "reviewed-plugin.so", "."]
    with pytest.raises(ValueError, match="reviewed"):
        inspector().build_plan(source_dir=tmp_path, source_sha256="d"*64, profile=profile())
