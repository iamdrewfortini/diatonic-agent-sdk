"""Offline signed release staging and fail-closed RHEL service updates.

Only locally staged Ed25519-signed wheels are admitted by the updater. The
separate release_feed module can download from an explicitly configured pinned
HTTPS coordinator into that spool; it never installs or activates releases.
"""
from __future__ import annotations

import argparse
import base64
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import struct
import subprocess
import sys
import time
import uuid
import zipfile

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field, model_validator

SCHEMA = "diatonic-release-v1"
MAX_TOTAL = 1024 * 1024 * 1024
MAX_FILE = 256 * 1024 * 1024
MAX_MANIFEST = 128 * 1024
SSD_RESERVE_BYTES = 64 * 1024 ** 3
VENV_OVERHEAD_BYTES = 64 * 1024 ** 2
SERVICE = "diatonic-meta.service"
TERMINAL = {"completed", "failed", "rolled_back"}


class UpdateBlocked(RuntimeError):
    pass


class StrictRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class WheelArtifact(StrictRecord):
    filename: str = Field(pattern=r"^[A-Za-z0-9_][A-Za-z0-9_.+\-]{0,180}\.whl$")
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    size_bytes: int = Field(ge=1, le=MAX_FILE)


class ReleaseManifest(StrictRecord):
    schema_version: str = Field(default=SCHEMA, pattern=r"^diatonic-release-v1$")
    version: str = Field(pattern=r"^(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})$")
    expected_incumbent_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    wheel: WheelArtifact
    dependencies: tuple[WheelArtifact, ...] = Field(max_length=128)

    @model_validator(mode="after")
    def validate_artifacts(self):
        if self.wheel.filename != f"diatonic_meta_pipeline-{self.version}-py3-none-any.whl":
            raise ValueError("Application wheel identity/version mismatch")
        all_wheels = (self.wheel, *self.dependencies)
        names = [item.filename for item in all_wheels]
        if len(names) != len(set(names)) or sum(item.size_bytes for item in all_wheels) > MAX_TOTAL:
            raise ValueError("Duplicate artifact or release size limit")
        return self


def _json_pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise UpdateBlocked("duplicate_json_field")
        result[key] = value
    return result


def _json(data):
    def invalid_constant(value):
        raise UpdateBlocked("nonfinite_json")
    return json.loads(data, object_pairs_hook=_json_pairs, parse_constant=invalid_constant)


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()


def canonical_manifest(manifest: ReleaseManifest) -> bytes:
    manifest = ReleaseManifest.model_validate_json(manifest.model_dump_json())
    return _canonical(manifest.model_dump(mode="json"))


def sign_manifest(manifest: ReleaseManifest, private_key_pem: bytes) -> bytes:
    """Build-host helper only. Never called by an updater or a worker."""
    key = serialization.load_pem_private_key(private_key_pem, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("Ed25519 build-host signing key required")
    signature = key.sign(canonical_manifest(manifest))
    return _canonical({"manifest": manifest.model_dump(mode="json"),
                       "signature": base64.b64encode(signature).decode("ascii")})


def verify_envelope(data: bytes, public_key_pem: bytes) -> ReleaseManifest:
    if len(data) > MAX_MANIFEST or len(public_key_pem) > 16384:
        raise UpdateBlocked("bounded_manifest_and_public_key_required")
    try:
        envelope = _json(data)
        if not isinstance(envelope, dict) or set(envelope) != {"manifest", "signature"}:
            raise UpdateBlocked("strict_signed_envelope_required")
        manifest = ReleaseManifest.model_validate_json(_canonical(envelope["manifest"]))
        signature = base64.b64decode(envelope["signature"], validate=True)
        if len(signature) != 64:
            raise UpdateBlocked("invalid_ed25519_signature")
        key = serialization.load_pem_public_key(public_key_pem)
        if not isinstance(key, Ed25519PublicKey):
            raise UpdateBlocked("pinned_ed25519_public_key_required")
        key.verify(signature, canonical_manifest(manifest))
        return manifest
    except UpdateBlocked:
        raise
    except (InvalidSignature, ValueError, TypeError, KeyError):
        raise UpdateBlocked("signature_or_manifest_verification_failed") from None


def _secure_path(path: Path, *, directory=False, uid=0):
    path = Path(path)
    if not path.is_absolute() or ".." in path.parts:
        raise UpdateBlocked("absolute_nontraversing_path_required")
    for parent in reversed(path.parents):
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != uid:
            raise UpdateBlocked("untrusted_path_ancestor")
        # Standard root-owned sticky /tmp is safe for an already root-owned
        # private child; its sticky bit prevents another user replacing it.
        if stat.S_IMODE(info.st_mode) & 0o022 and not info.st_mode & stat.S_ISVTX:
            raise UpdateBlocked("writable_path_ancestor")
    info = path.lstat()
    if info.st_uid != uid or stat.S_IMODE(info.st_mode) & 0o022:
        raise UpdateBlocked("untrusted_owner_or_writable_path")
    if not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)):
        raise UpdateBlocked("regular_nonsymlink_path_required")
    return info


def _read(path: Path, *, maximum=MAX_FILE, uid=0):
    _secure_path(path, uid=uid)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if (before.st_uid != uid or stat.S_IMODE(before.st_mode) & 0o022
                or not stat.S_ISREG(before.st_mode) or before.st_size > maximum):
            raise UpdateBlocked("untrusted_or_oversized_file")
        data = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
    if (len(data) > maximum or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)):
        raise UpdateBlocked("file_changed_or_limit_exceeded")
    return data


def _atomic_json(path, value):
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(_canonical(value)); stream.flush(); os.fsync(stream.fileno())
    os.replace(temporary, path)
    _sync_directory(path.parent)


def _sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _validate_wheel(path):
    # Count central-directory records before ZipFile allocates its full index.
    # ZIP64/multidisk are intentionally unsupported for these bounded wheels.
    with path.open("rb") as stream:
        size = stream.seek(0, 2)
        stream.seek(max(0, size - 65557)); tail = stream.read(65557)
        end = tail.rfind(b"PK\x05\x06")
        if end < 0 or len(tail) - end < 22:
            raise UpdateBlocked("wheel_end_record_missing")
        _, disk, directory_disk, disk_entries, entries, directory_size, directory_offset, comment = struct.unpack_from("<4s4H2IH", tail, end)
        if disk or directory_disk or disk_entries != entries or not 1 <= entries <= 20000 or directory_offset + directory_size > size:
            raise UpdateBlocked("wheel_central_directory_limit")
        position, counted = directory_offset, 0
        while position < directory_offset + directory_size:
            stream.seek(position); header = stream.read(46)
            if len(header) != 46 or header[:4] != b"PK\x01\x02":
                raise UpdateBlocked("invalid_wheel_central_record")
            name_size, extra_size, comment_size = struct.unpack_from("<3H", header, 28)
            if name_size > 4096:
                raise UpdateBlocked("wheel_member_name_limit")
            position += 46 + name_size + extra_size + comment_size
            counted += 1
            if counted > 20000 or position > directory_offset + directory_size:
                raise UpdateBlocked("wheel_entry_limit")
        if counted != entries:
            raise UpdateBlocked("wheel_entry_count_mismatch")
    expanded = 0
    with zipfile.ZipFile(path) as wheel:
        entries = wheel.infolist()
        if not 1 <= len(entries) <= 20000:
            raise UpdateBlocked("wheel_entry_limit")
        names = set()
        for entry in entries:
            parts = PurePosixPath(entry.filename).parts
            normalized = "/".join(parts)
            if normalized in names:
                raise UpdateBlocked("duplicate_wheel_member")
            names.add(normalized)
            mode = entry.external_attr >> 16
            if (entry.filename.startswith(("/", "\\")) or "\\" in entry.filename
                    or not parts or any(part in {".", ".."} for part in parts)
                    or stat.S_IFMT(mode) not in {0, stat.S_IFREG, stat.S_IFDIR}
                    or entry.flag_bits & 1):
                raise UpdateBlocked("unsafe_wheel_member")
            expanded += entry.file_size
            if expanded > MAX_TOTAL or entry.file_size > MAX_FILE:
                raise UpdateBlocked("wheel_expansion_limit")
    return expanded


class ReleaseManager:
    def __init__(self, root: Path, public_key: Path, spool: Path, *,
                 runner=None, health_check=None, trusted_uid=0, capacity_reader=None):
        self.root, self.public_key, self.spool = map(Path, (root, public_key, spool))
        self.uid = trusted_uid
        self.runner = runner or self._run
        self.health_check = health_check or self._health
        self.capacity_reader = capacity_reader or self._free_bytes
        self._trial = None

    @staticmethod
    def _run(argv, *, timeout):
        env = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8",
               "PYTHONNOUSERSITE": "1", "PYTHONDONTWRITEBYTECODE": "1",
               "PIP_CONFIG_FILE": os.devnull, "PIP_NO_INDEX": "1",
               "PIP_NO_CACHE_DIR": "1", "PIP_DISABLE_PIP_VERSION_CHECK": "1"}
        # Fixed argv only. Signed releases may execute only the fixed import,
        # protocol and pip checks below; no manifest commands or shell hooks.
        result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, env=env, timeout=timeout, check=False,umask=0o022)
        return result.returncode

    def _command(self, argv, timeout=120):
        started = time.monotonic()
        code = self.runner(argv, timeout=timeout)
        operation=("pip_install" if "install" in argv and "pip" in argv else
                   "pip_check" if "check" in argv and "pip" in argv else
                   "create_venv" if "venv" in argv else
                   "protocol_check" if "meta_pipeline.cli" in argv else
                   "service_control" if Path(argv[0]).name=="systemctl" else
                   "fixed_python_check")
        self._event("command", {"operation": operation,"argv_sha256":hashlib.sha256(_canonical(argv)).hexdigest(), "exit_code": code,
                                "elapsed_seconds": time.monotonic() - started})
        if type(code) is not int or code != 0:
            raise UpdateBlocked("fixed_release_command_failed")

    def _event(self, phase, detail=None):
        if self._trial is None:
            return
        fd = os.open(self._trial, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW)
        with os.fdopen(fd, "ab") as stream:
            stream.write(_canonical({"utc": datetime.now(timezone.utc).isoformat(), "phase": phase,
                                     **(detail or {})}) + b"\n")
            stream.flush(); os.fsync(stream.fileno())

    def _journal(self, phase, **extra):
        _atomic_json(self.root / "update-state.json", {"phase": phase, **extra})
        self._event(phase, extra)

    @contextmanager
    def _lock(self):
        path = self.root / "update.lock"
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(fd)
            if info.st_uid != self.uid or not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) & 0o022:
                raise UpdateBlocked("unsafe_update_lock")
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise UpdateBlocked("concurrent_update") from None
            yield
        finally:
            os.close(fd)

    def _current(self):
        pointer = self.root / "current"
        info = pointer.lstat()
        if not stat.S_ISLNK(info.st_mode) or info.st_uid != self.uid:
            raise UpdateBlocked("managed_current_symlink_required")
        target = pointer.readlink()
        if not target.is_absolute():
            target = self.root / target
        if ".." in target.parts or not target.is_relative_to(self.root / "releases"):
            raise UpdateBlocked("current_target_outside_releases")
        _secure_path(target, directory=True, uid=self.uid)
        record = _json(_read(target / "release.json", maximum=MAX_MANIFEST, uid=self.uid))
        nested = record.get("wheel", {}).get("sha256")
        legacy = record.get("wheel_sha256")
        if nested is not None and legacy is not None and nested != legacy:
            raise UpdateBlocked("conflicting_incumbent_hash_records")
        version, wheel_hash = record.get("version"), nested or legacy
        if not isinstance(version, str) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version) or not isinstance(wheel_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", wheel_hash):
            raise UpdateBlocked("incumbent_record_invalid")
        return target, version, wheel_hash

    def _publish(self, target, attempt):
        temporary = self.root / (".current-" + attempt)
        os.symlink(str(target.relative_to(self.root)), temporary)
        os.replace(temporary, self.root / "current")
        _sync_directory(self.root)

    def _artifact(self, item, *, stage=True):
        cache = self.root / "wheelhouse" / item.filename
        for candidate in (cache, self.spool / item.filename):
            if not candidate.exists() and not candidate.is_symlink():
                continue
            data = _read(candidate, maximum=MAX_FILE, uid=self.uid)
            if len(data) != item.size_bytes or hashlib.sha256(data).hexdigest() != item.sha256:
                # An existing conflicting cache is never silently overwritten.
                raise UpdateBlocked("artifact_size_or_hash_mismatch")
            _validate_wheel(candidate)
            if candidate == cache or not stage:
                self._event("artifact_reused" if candidate == cache else "artifact_checked", {"sha256": item.sha256, "bytes": len(data)})
                return candidate
            fd = os.open(cache, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
            with os.fdopen(fd, "wb") as stream:
                stream.write(data); stream.flush(); os.fsync(stream.fileno())
            self._event("artifact_staged", {"sha256": item.sha256, "bytes": len(data)})
            return cache
        raise UpdateBlocked("signed_artifact_missing")

    @staticmethod
    def _free_bytes(path):
        info = os.statvfs(path)
        return info.f_bavail * info.f_frsize

    def _admit_storage(self, manifest):
        items = (manifest.wheel, *manifest.dependencies)
        paths = [self._artifact(item, stage=False) for item in items]
        expanded = sum(_validate_wheel(path) for path in paths)
        if expanded > MAX_TOTAL:
            raise UpdateBlocked("aggregate_release_expansion_limit")
        root_device = self.root.stat().st_dev
        if any((self.root / name).stat().st_dev != root_device for name in ("wheelhouse", "releases", "trials")):
            raise UpdateBlocked("cross_filesystem_release_storage_unverified")
        cache_needed = sum(item.size_bytes for item in items if not (self.root / "wheelhouse" / item.filename).exists())
        peak = cache_needed + 2 * expanded + VENV_OVERHEAD_BYTES
        free = self.capacity_reader(self.root)
        self._event("storage_admission", {"free_bytes": free, "ssd_reserve_bytes": SSD_RESERVE_BYTES,
                    "expanded_release_bytes": expanded, "peak_incremental_bytes": peak})
        if type(free) is not int or free < SSD_RESERVE_BYTES + peak:
            raise UpdateBlocked("ssd_reserve_or_release_capacity_denied")
        return {"expanded_bytes": expanded, "peak_incremental_bytes": peak}

    def _prepare(self, manifest, release):
        self._admit_storage(manifest)
        files = [self._artifact(item) for item in (manifest.wheel, *manifest.dependencies)]
        python = release / "venv" / "bin" / "python"
        self._command([sys.executable, "-I", "-m", "venv", "--copies", str(release / "venv")])
        self._command([str(python), "-I", "-m", "pip", "install", "--no-index", "--no-deps", "--no-cache-dir",
                       "--find-links", str(self.root / "wheelhouse"), *map(str, files)], timeout=300)
        self._command([str(python), "-I", "-c", "import meta_pipeline; from meta_pipeline.protocol import document; assert document()['id'] == 'diatonic-13-v1'"])
        self._command([str(python), "-I", "-m", "meta_pipeline.cli", "protocol"])
        self._command([str(python), "-I", "-m", "pip", "check"])
        self._command([str(python), "-I", "-c", "import importlib.metadata,sys; assert importlib.metadata.version('diatonic-meta-pipeline') == sys.argv[1]", manifest.version])

    def _health(self):
        import urllib.request
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *args, **kwargs):
                return None
        credential = Path("/etc/diatonic-meta/monitor-key")
        try:
            key = _read(credential, maximum=16384, uid=self.uid).decode().strip()
            if not key or any(c in key for c in "\r\n"):
                return False
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
            req = urllib.request.Request("http://127.0.0.1:9189/api/protocol", headers={"Authorization": "Bearer " + key})
            for attempt in range(1, 6):
                active = self.runner(["/usr/bin/systemctl", "is-active", "--quiet", SERVICE], timeout=10)
                self._event("health_probe", {"attempt": attempt, "service_exit_code": active})
                if active == 0:
                    try:
                        pid_query = subprocess.run(["/usr/bin/systemctl", "show", SERVICE, "--property", "MainPID", "--value"],
                            stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=10,
                            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"})
                        pid = pid_query.stdout.strip()
                        if pid_query.returncode or not re.fullmatch(r"[1-9][0-9]{0,9}", pid):
                            raise UpdateBlocked("service_main_pid_unavailable")
                        with opener.open(req, timeout=3) as response:
                            data = response.read(MAX_MANIFEST + 1)
                        if len(data) > MAX_MANIFEST:
                            raise UpdateBlocked("bounded_monitor_health_required")
                        body = _json(data)
                        observed = body.get("runtime")
                        _, expected_version, expected_hash = self._current()
                        matched = (isinstance(observed, dict)
                                   and observed.get("wheel_sha256") == expected_hash
                                   and observed.get("version") == expected_version
                                   and body.get("contract", {}).get("id") == "diatonic-13-v1")
                        self._event("health_identity_receipt", {"attempt": attempt, "main_pid": int(pid),
                                    "expected_version": expected_version, "expected_wheel_sha256": expected_hash,
                                    "startup_identity_matched": matched})
                        if matched:
                            return True
                    except Exception as error:
                        self._event("health_probe_failed", {"attempt": attempt, "reason_class": type(error).__name__})
                time.sleep(1)
            return False
        except Exception as error:
            self._event("health_unavailable", {"reason_class": type(error).__name__})
            return False

    def update(self, *, apply=False):
        _secure_path(self.root, directory=True, uid=self.uid)
        _secure_path(self.spool, directory=True, uid=self.uid)
        with self._lock():
            journal = self.root / "update-state.json"
            if journal.exists() or journal.is_symlink():
                previous = _json(_read(journal, maximum=MAX_MANIFEST, uid=self.uid))
                if previous.get("phase") not in TERMINAL:
                    raise UpdateBlocked("previous_update_unresolved_reconcile_before_retry")
            envelope_path = self.spool / "update.json"
            if not envelope_path.exists() and not envelope_path.is_symlink():
                return {"status": "no_update", "production_feed": "local signed spool only"}
            for directory in ("trials", "wheelhouse", "releases"):
                path = self.root / directory
                path.mkdir(mode=0o755, exist_ok=True)
                _secure_path(path, directory=True, uid=self.uid)
            attempt = uuid.uuid4().hex
            self._trial = self.root / "trials" / (attempt + ".jsonl")
            fd = os.open(self._trial, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600); os.close(fd)
            switched = False
            incumbent = None
            try:
                envelope = _read(envelope_path, maximum=MAX_MANIFEST, uid=self.uid)
                public = _read(self.public_key, maximum=16384, uid=self.uid)
                manifest = verify_envelope(envelope, public)
                incumbent, version, incumbent_hash = self._current()
                if manifest.wheel.sha256 == incumbent_hash or tuple(map(int, manifest.version.split('.'))) <= tuple(map(int, version.split('.'))):
                    raise UpdateBlocked("duplicate_or_downgrade_release")
                if manifest.expected_incumbent_sha256 != incumbent_hash:
                    raise UpdateBlocked("stale_incumbent_precondition")
                self._event("verified", {"version": manifest.version, "wheel_sha256": manifest.wheel.sha256,
                                         "incumbent_sha256": incumbent_hash, "envelope_sha256": hashlib.sha256(envelope).hexdigest()})
                if not apply:
                    self._admit_storage(manifest)
                    self._event("check_completed", {"artifacts_verified": len(manifest.dependencies) + 1})
                    return {"status": "verified_update_available", "version": manifest.version, "applied": False,
                            "artifacts_verified": len(manifest.dependencies) + 1}
                release = self.root / "releases" / (manifest.version + "-" + manifest.wheel.sha256[:12])
                if release.exists() or release.is_symlink():
                    raise UpdateBlocked("existing_release_requires_reconciliation")
                self._journal("preparing", attempt=attempt, version=manifest.version)
                release.mkdir(mode=0o755)
                # The updater's private0077 mask protects its journals. Published
                # immutable code must remain readable by the dedicated service.
                os.chmod(release,0o755)
                _atomic_json(release / "release.json", manifest.model_dump(mode="json"))
                os.chmod(release / "release.json",0o644)
                signed = release / "signed-envelope.json"
                fd = os.open(signed, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
                with os.fdopen(fd, "wb") as stream:
                    stream.write(envelope); stream.flush(); os.fsync(stream.fileno())
                os.chmod(signed,0o644)
                self._prepare(manifest, release)
                if self._current() != (incumbent, version, incumbent_hash):
                    raise UpdateBlocked("incumbent_changed_before_activation")
                self._journal("switching", attempt=attempt, incumbent=str(incumbent), candidate=str(release))
                switched = True  # publication may take effect before fsync reports an error
                self._publish(release, attempt)
                self._journal("verifying", attempt=attempt, incumbent=str(incumbent), candidate=str(release))
                self._command(["/usr/bin/systemctl", "restart", SERVICE], timeout=60)
                if self.health_check() is not True:
                    raise UpdateBlocked("post_update_health_failed")
                self._journal("completed", attempt=attempt, version=manifest.version,
                              wheel_sha256=manifest.wheel.sha256, rollback_pointer=str(incumbent))
                self._event("completed", {"rollback_pointer": str(incumbent)})
                # Retain the signed feed entry in release evidence. Move the
                # admission envelope to an append-only processed-name location.
                processed = self.spool / ("applied-" + hashlib.sha256(envelope).hexdigest() + ".json")
                if processed.exists() or processed.is_symlink():
                    raise UpdateBlocked("processed_envelope_collision")
                os.link(envelope_path, processed, follow_symlinks=False)
                if _read(envelope_path, maximum=MAX_MANIFEST, uid=self.uid) != envelope:
                    raise UpdateBlocked("spool_changed_after_activation")
                envelope_path.unlink()
                _sync_directory(self.spool)
                return {"status": "updated", "version": manifest.version, "attempt": attempt,
                        "wheel_sha256": manifest.wheel.sha256, "rollback_pointer": str(incumbent)}
            except Exception as error:
                self._event("failure", {"reason": str(error) if isinstance(error, UpdateBlocked) else type(error).__name__, "switched": switched})
                if switched and incumbent is not None:
                    try:
                        self._publish(incumbent, attempt + "-rollback")
                        self._command(["/usr/bin/systemctl", "restart", SERVICE], timeout=60)
                        if self.health_check() is not True:
                            raise UpdateBlocked("rollback_health_unresolved")
                        self._journal("rolled_back", attempt=attempt, restored=str(incumbent), reason=type(error).__name__)
                    except Exception:
                        self._journal("unresolved", attempt=attempt, restored_pointer=str(incumbent), reason="rollback_requires_native_reconciliation")
                elif apply:
                    self._journal("failed", attempt=attempt, reason=type(error).__name__)
                raise
            finally:
                self._trial = None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--public-key", type=Path, required=True)
    parser.add_argument("--spool", type=Path, required=True)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args(argv)
    try:
        if os.geteuid() != 0:
            raise UpdateBlocked("root_owned_update_service_required")
        result = ReleaseManager(args.root, args.public_key, args.spool).update(apply=args.apply)
        print(json.dumps(result, sort_keys=True))
        return 0
    except Exception as error:
        print(json.dumps({"status": "blocked", "reason": str(error) if isinstance(error, UpdateBlocked) else type(error).__name__}, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
