"""Immutable content-addressed prompt versions, separate from native cache.

Place this private SSD store beside the worker or a sanctioned gateway-side
mount. It is a library of trusted instructions, never a model-writable policy
store or a replacement response cache. Bifrost owns response caching.
"""
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat

from .provider_contracts import PromptBinding


class PromptLibrary:
    def __init__(self, path):
        self.path = Path(path)
        if not self.path.is_absolute() or self.path.parent.is_symlink():
            raise ValueError("Private absolute prompt store required")
        parent = self.path.parent.stat()
        if stat.S_IMODE(parent.st_mode) & 0o022:
            raise ValueError("Prompt store parent is writable by others")
        fd = os.open(self.path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        os.chmod(self.path, 0o600)
        with self.connect() as db:
            db.execute("CREATE TABLE IF NOT EXISTS prompts(id TEXT,version TEXT,digest TEXT UNIQUE,document TEXT,PRIMARY KEY(id,version))")
            db.execute("CREATE TABLE IF NOT EXISTS prompt_active(id TEXT PRIMARY KEY,version TEXT NOT NULL)")

    def connect(self):
        return sqlite3.connect(self.path, timeout=30)

    def put(self, binding: PromptBinding):
        binding = PromptBinding.model_validate(binding.model_dump())
        document = binding.model_dump_json()
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            old = db.execute("SELECT document FROM prompts WHERE id=? AND version=?", (binding.id, binding.version)).fetchone()
            if old and old[0] != document:
                raise ValueError("Immutable prompt changed; version it")
            db.execute("INSERT OR IGNORE INTO prompts VALUES(?,?,?,?)", (binding.id, binding.version, binding.digest, document))
            db.execute("INSERT OR IGNORE INTO prompt_active VALUES(?,?)", (binding.id, binding.version))
        return binding.digest

    def get(self, id, version=None):
        with self.connect() as db:
            if version is None:
                row = db.execute("SELECT version FROM prompt_active WHERE id=?", (id,)).fetchone()
                if not row:
                    raise ValueError("Unknown prompt")
                version = row[0]
            row = db.execute("SELECT document,digest FROM prompts WHERE id=? AND version=?", (id, version)).fetchone()
        if not row:
            raise ValueError("Unknown prompt version")
        binding = PromptBinding.model_validate_json(row[0])
        if binding.digest != row[1]:
            raise ValueError("Prompt identity mismatch")
        return binding

    def activate(self, id, version, *, expected_version):
        self.get(id, version)
        if version == expected_version:
            raise ValueError("Duplicate prompt activation")
        with self.connect() as db:
            changed = db.execute("UPDATE prompt_active SET version=? WHERE id=? AND version=?", (version, id, expected_version)).rowcount
            if changed != 1:
                raise ValueError("Stale prompt activation")

    def gateway_storage_plan(self, id, version=None):
        binding = self.get(id, version)
        return {"prompt_id": binding.id, "version": binding.version, "content_sha256": binding.digest,
            "expanded_utf8_bytes": len(binding.template.encode()), "native_activation": "pending_gateway_storage_binding",
            "storage_role": "immutable prompt artifact; Bifrost remains response-cache authority",
            "sensitive_content_exported": False}
