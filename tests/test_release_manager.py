import base64
import hashlib
import json
from pathlib import Path
import os
import stat
import zipfile

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
import pytest

from meta_pipeline.release_manager import (ReleaseManager, ReleaseManifest,
    WheelArtifact, UpdateBlocked, canonical_manifest, sign_manifest, verify_envelope, main)


def keypair():
    private = Ed25519PrivateKey.generate()
    return (private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()),
            private.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))


def wheel(path, *, dangerous=False):
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("../escape" if dangerous else "fixture/record.txt", "retained wheel fixture")
    data = path.read_bytes()
    return WheelArtifact(filename=path.name, sha256=hashlib.sha256(data).hexdigest(), size_bytes=len(data))


def setup(tmp_path, *, runner=None, health=None, version="0.3.1", legacy=False):
    root = tmp_path / "installation"; root.mkdir()
    releases = root / "releases"; releases.mkdir()
    incumbent = releases / "0.3.0-incumbent"; incumbent.mkdir()
    info = {"version": "0.3.0", "wheel_sha256": "a"*64} if legacy else {"version": "0.3.0", "wheel": {"sha256": "a"*64}}
    (incumbent / "release.json").write_text(json.dumps(info))
    (root / "current").symlink_to("releases/0.3.0-incumbent")
    spool = tmp_path / "spool"; spool.mkdir()
    application = wheel(spool / f"diatonic_meta_pipeline-{version}-py3-none-any.whl")
    dependency = wheel(spool / "dependency-1.0.0-py3-none-any.whl")
    manifest = ReleaseManifest(version=version, expected_incumbent_sha256="a"*64, wheel=application, dependencies=(dependency,))
    private, public = keypair()
    trust = tmp_path / "release-signing.pub"; trust.write_bytes(public)
    (spool / "update.json").write_bytes(sign_manifest(manifest, private))
    calls = []
    def execute(argv, *, timeout):
        calls.append((argv, timeout))
        return 0
    manager = ReleaseManager(root, trust, spool, runner=runner or execute, health_check=health or (lambda: True),
                             capacity_reader=lambda path: 128 * 1024 ** 3)  # simulated SSD capacity for lifecycle fixtures
    return manager, manifest, private, calls


def test_signed_canonical_manifest_and_wrong_key_fail_closed(tmp_path):
    manager, manifest, private, _ = setup(tmp_path)
    envelope = sign_manifest(manifest, private)
    assert verify_envelope(envelope, manager.public_key.read_bytes()) == manifest
    assert canonical_manifest(manifest) == canonical_manifest(ReleaseManifest.model_validate_json(manifest.model_dump_json()))
    with pytest.raises(UpdateBlocked, match="verification"):
        verify_envelope(envelope, keypair()[1])
    raw = json.loads(envelope); raw["manifest"]["version"] = "0.3.2"
    with pytest.raises(UpdateBlocked):
        verify_envelope(json.dumps(raw).encode(), manager.public_key.read_bytes())


def test_duplicate_json_fields_and_unknown_schema_or_commands_rejected(tmp_path):
    manager, manifest, private, _ = setup(tmp_path)
    raw = sign_manifest(manifest, private)
    with pytest.raises(UpdateBlocked, match="duplicate_json"):
        verify_envelope(b'{"manifest":{},"manifest":{},"signature":"x"}', manager.public_key.read_bytes())
    for change in ({"schema_version": "future"}, {"post_install": "shell-command"}):
        data = json.loads(raw); data["manifest"].update(change)
        with pytest.raises(UpdateBlocked):
            verify_envelope(json.dumps(data).encode(), manager.public_key.read_bytes())


def test_empty_spool_no_update_without_reading_signing_key(tmp_path, capsys):
    manager, _, _, _ = setup(tmp_path)
    (manager.spool / "update.json").unlink()
    manager.public_key.unlink()
    assert manager.update(apply=True)["status"] == "no_update"
    assert main(["--root", str(manager.root), "--public-key", str(manager.public_key), "--spool", str(manager.spool), "--check", "--apply"]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "no_update"


def test_check_verifies_signed_artifacts_without_activation(tmp_path):
    manager, manifest, _, calls = setup(tmp_path)
    result = manager.update()
    assert result["status"] == "verified_update_available" and result["artifacts_verified"] == 2
    assert manager._current()[1] == "0.3.0" and calls == []
    assert (manager.spool / "update.json").exists()


def test_update_incremental_cache_reuse_atomic_activation_and_history(tmp_path):
    manager, manifest, _, calls = setup(tmp_path, legacy=True)
    cache = manager.root / "wheelhouse"; cache.mkdir()
    dependency = manifest.dependencies[0]
    source = manager.spool / dependency.filename
    (cache / dependency.filename).write_bytes(source.read_bytes()); source.unlink()
    result = manager.update(apply=True)
    assert result["status"] == "updated"
    assert manager._current()[1:] == ("0.3.1", manifest.wheel.sha256)
    assert Path(result["rollback_pointer"]).exists()
    assert not (manager.spool / "update.json").exists()
    assert list(manager.spool.glob("applied-*.json"))
    assert manager.update(apply=True)["status"] == "no_update"
    assert any("--no-index" in args and "--no-deps" in args for args, _ in calls)
    assert any(args[-1] == "check" for args, _ in calls)
    events = [json.loads(line) for path in (manager.root / "trials").glob("*.jsonl") for line in path.read_text().splitlines()]
    assert any(row["phase"] == "artifact_reused" for row in events)
    assert any(row["phase"] == "completed" for row in events)


@pytest.mark.parametrize("mode", ["bad_signature", "stale", "downgrade", "tamper", "symlink", "writable", "unsafe_wheel"])
def test_failed_checks_preserved_without_activation(tmp_path, mode):
    manager, manifest, private, calls = setup(tmp_path, version="0.2.9" if mode == "downgrade" else "0.3.1")
    envelope = manager.spool / "update.json"
    if mode == "bad_signature":
        raw = json.loads(envelope.read_text()); raw["signature"] = base64.b64encode(b"x"*64).decode(); envelope.write_text(json.dumps(raw))
    if mode == "stale":
        manifest = manifest.model_copy(update={"expected_incumbent_sha256": "b"*64}); envelope.write_bytes(sign_manifest(manifest, private))
    wheel_path = manager.spool / manifest.wheel.filename
    if mode == "tamper": wheel_path.write_bytes(b"tampered")
    if mode == "symlink":
        alternate = manager.spool / "untrusted-target"; alternate.write_bytes(wheel_path.read_bytes()); wheel_path.unlink(); wheel_path.symlink_to(alternate)
    if mode == "writable": wheel_path.chmod(0o666)
    if mode == "unsafe_wheel":
        artifact = wheel(wheel_path, dangerous=True); manifest = manifest.model_copy(update={"wheel": artifact}); envelope.write_bytes(sign_manifest(manifest, private))
    with pytest.raises((UpdateBlocked, OSError)):
        manager.update(apply=True)
    assert manager._current()[1] == "0.3.0" and not any(args[0] == "/usr/bin/systemctl" for args, _ in calls)
    trials = list((manager.root / "trials").glob("*.jsonl"))
    assert trials and any(json.loads(line)["phase"] == "failure" for line in trials[0].read_text().splitlines())
    assert envelope.exists()


def test_health_failure_rolls_back_and_retains_failed_release(tmp_path):
    results = iter([False, True])
    manager, manifest, _, calls = setup(tmp_path, health=lambda: next(results))
    with pytest.raises(UpdateBlocked, match="health_failed"):
        manager.update(apply=True)
    assert manager._current()[1] == "0.3.0"
    assert (manager.root / "releases" / ("0.3.1-"+manifest.wheel.sha256[:12])).exists()
    assert json.loads((manager.root / "update-state.json").read_text())["phase"] == "rolled_back"
    assert sum(args == ["/usr/bin/systemctl", "restart", "diatonic-meta.service"] for args, _ in calls) == 2


def test_rollback_unknown_blocks_further_updates_and_preserves_original(tmp_path):
    manager, _, _, _ = setup(tmp_path, health=lambda: False)
    with pytest.raises(UpdateBlocked):
        manager.update(apply=True)
    assert manager._current()[1] == "0.3.0"
    assert json.loads((manager.root / "update-state.json").read_text())["phase"] == "unresolved"
    with pytest.raises(UpdateBlocked, match="unresolved"):
        manager.update(apply=True)


def test_restart_unknown_duplicate_concurrency_and_outside_pointer(tmp_path):
    manager, manifest, _, _ = setup(tmp_path)
    with manager._lock():
        with pytest.raises(UpdateBlocked, match="concurrent"):
            manager.update(apply=True)
    state = manager.root / "update-state.json"; state.write_text(json.dumps({"phase": "switching"}))
    with pytest.raises(UpdateBlocked, match="unresolved"):
        manager.update(apply=True)
    state.unlink()
    pointer = manager.root / "current"; pointer.unlink(); pointer.symlink_to(tmp_path)
    with pytest.raises(UpdateBlocked, match="outside"):
        manager.update(apply=True)


def test_fixed_preflight_failure_preserves_incumbent_and_release(tmp_path):
    def failing(argv, timeout):
        return 3 if "check" in argv else 0
    manager, _, _, _ = setup(tmp_path, runner=failing)
    with pytest.raises(UpdateBlocked, match="command_failed"):
        manager.update(apply=True)
    assert manager._current()[1] == "0.3.0"
    assert json.loads((manager.root / "update-state.json").read_text())["phase"] == "failed"


def test_repeated_signed_manifest_cannot_reapply_current_release(tmp_path):
    manager, _, _, _ = setup(tmp_path)
    signed = (manager.spool / "update.json").read_bytes()
    manager.update(apply=True)
    (manager.spool / "update.json").write_bytes(signed)
    with pytest.raises(UpdateBlocked, match="duplicate"):
        manager.update(apply=True)


def test_capacity_reserve_not_relaxed_and_no_effect_on_denial(tmp_path):
    from meta_pipeline.release_manager import SSD_RESERVE_BYTES
    manager, _, _, calls = setup(tmp_path)
    manager.capacity_reader = lambda path: SSD_RESERVE_BYTES
    with pytest.raises(UpdateBlocked, match="capacity_denied"):
        manager.update(apply=True)
    assert manager._current()[1] == "0.3.0" and not calls
    assert list((manager.root / "wheelhouse").glob("*.whl")) == []


def test_normalized_duplicate_zip_paths_rejected(tmp_path):
    from meta_pipeline.release_manager import _validate_wheel
    path = tmp_path / "unsafe.whl"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("fixture/record.txt", "first")
        archive.writestr("fixture//record.txt", "second")
    with pytest.raises(UpdateBlocked, match="duplicate"):
        _validate_wheel(path)


def test_aggregate_expansion_bound_across_wheels(tmp_path, monkeypatch):
    import meta_pipeline.release_manager as releases
    manager, _, _, calls = setup(tmp_path)
    actual = releases._validate_wheel
    def pretend_large(path):
        actual(path)
        return releases.MAX_TOTAL // 2 + 1
    monkeypatch.setattr(releases, "_validate_wheel", pretend_large)
    with pytest.raises(UpdateBlocked, match="aggregate_release_expansion"):
        manager.update(apply=True)
    assert not calls and manager._current()[1] == "0.3.0"


def test_publish_error_after_pointer_effect_rolls_back(tmp_path, monkeypatch):
    manager, _, _, _ = setup(tmp_path)
    real = manager._publish
    def uncertain(target, attempt):
        real(target, attempt)
        if not attempt.endswith("-rollback"):
            raise OSError("directory fsync failed after pointer replacement")
    monkeypatch.setattr(manager, "_publish", uncertain)
    with pytest.raises(OSError):
        manager.update(apply=True)
    assert manager._current()[1] == "0.3.0"
    assert json.loads((manager.root / "update-state.json").read_text())["phase"] == "rolled_back"


@pytest.mark.parametrize("private_updater_mask",[False,True])
def test_real_offline_venv_install_of_signed_disposable_fixture(tmp_path,private_updater_mask):
    """Runs actual venv/pip/import/protocol/version checks, no native service effect."""
    import subprocess
    manager, manifest, private, _ = setup(tmp_path)
    package = manager.spool / manifest.wheel.filename
    info = "diatonic_meta_pipeline-0.3.1.dist-info"
    files = {
        "meta_pipeline/__init__.py": "",
        "meta_pipeline/protocol.py": "def document(): return {'id':'diatonic-13-v1'}\n",
        "meta_pipeline/cli.py": "from .protocol import document\nimport json\nprint(json.dumps(document()))\n",
        info+"/METADATA": "Metadata-Version: 2.1\nName: diatonic-meta-pipeline\nVersion: 0.3.1\n",
        info+"/WHEEL": "Wheel-Version: 1.0\nGenerator: disposable-fixture\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
    }
    files[info+"/RECORD"] = "".join(name+",,\n" for name in [*files, info+"/RECORD"])
    with zipfile.ZipFile(package, "w") as archive:
        for name, text in files.items(): archive.writestr(name, text)
    data = package.read_bytes()
    artifact = WheelArtifact(filename=package.name, sha256=hashlib.sha256(data).hexdigest(), size_bytes=len(data))
    manifest = manifest.model_copy(update={"wheel": artifact, "dependencies": ()})
    (manager.spool / "update.json").write_bytes(sign_manifest(manifest, private))
    def actual_local(argv, *, timeout):
        if argv[0] == "/usr/bin/systemctl":
            return 0  # fixture boundary: never restart the real host service
        return ReleaseManager._run(argv, timeout=timeout)
    manager.runner = actual_local
    def independently_observe_install():
        python = manager.root / "current" / "venv" / "bin" / "python"
        result = subprocess.run([str(python), "-I", "-c", "import importlib.metadata; print(importlib.metadata.version('diatonic-meta-pipeline'))"], capture_output=True, text=True, timeout=10)
        return result.returncode == 0 and result.stdout.strip() == "0.3.1"
    manager.health_check = independently_observe_install
    previous_mask=os.umask(0o077) if private_updater_mask else None
    try:
        assert manager.update(apply=True)["status"] == "updated"
    finally:
        if previous_mask is not None:os.umask(previous_mask)
    published=(manager.root/"current").resolve()
    assert stat.S_IMODE(published.stat().st_mode)&0o055==0o055
    assert stat.S_IMODE((published/"release.json").stat().st_mode)&0o044==0o044
    assert stat.S_IMODE((published/"venv").stat().st_mode)&0o055==0o055
    assert stat.S_IMODE((published/"venv/lib").stat().st_mode)&0o055==0o055
    assert stat.S_IMODE((manager.root/"update-state.json").stat().st_mode)==0o600
