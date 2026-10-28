"""Privileged one-time Hostinger-key enrollment; absent from worker tool ports.

The key is retrieved once through an independently authorized source and supplied
in memory/private pipe. This helper never contacts Hostinger. Runtime reads use
the existing 1Password SDK only. No account/vault/bootstrap identity is invented.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import os
import re
import stat
from typing import Literal

from pydantic import BaseModel, ConfigDict, SecretStr

from .secret_broker import MAX_SECRET_BYTES, _bounded_value

ID = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
ENROLLMENT_ID = "hostinger-api-once-v1"


class EnrollmentPending(RuntimeError):
    pass


class EnrollmentResult(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    status: Literal["enrolled_and_independently_verified", "already_enrolled"]
    reference: SecretStr
    secret_disclosed: Literal[False] = False
    scope: str = "Privileged one-time SDK enrollment; grants no worker upstream/admin access"


def read_private_pipe(fd: int, *, trusted_uid=0) -> SecretStr:
    """Read an already passed private pipe descriptor; never a pathname/argv key."""
    info = os.fstat(fd)
    if (not stat.S_ISFIFO(info.st_mode) or info.st_uid != trusted_uid
            or stat.S_IMODE(info.st_mode) & 0o077):
        raise EnrollmentPending("private_authorized_pipe_required")
    # Nonblocking ensures an absent sender cannot hang a privileged enrollment.
    os.set_blocking(fd, False)
    chunks, length = [], 0
    while True:
        try:
            part = os.read(fd, MAX_SECRET_BYTES + 1 - length)
        except BlockingIOError:
            # A writer must close its frame. Never silently enroll an incomplete
            # prefix when a pipe write arrives in more than one chunk.
            raise EnrollmentPending("one_time_key_frame_incomplete") from None
        if not part:
            break
        chunks.append(part); length += len(part)
        if length > MAX_SECRET_BYTES:
            raise EnrollmentPending("one_time_key_too_large")
    raw = b"".join(chunks)
    try:
        return _bounded_value(raw.decode("utf-8"))
    except Exception:
        raise EnrollmentPending("invalid_one_time_key") from None


class OneTimeCredentialEnrollment:
    """Only a separately authorized privileged control-plane client may use this."""
    def __init__(self, sdk_client, audit, *, authorized_vault_id: str,
                 authorized_actor: str, timeout_seconds: float = 15):
        if (not ID.fullmatch(authorized_vault_id) or not ID.fullmatch(authorized_actor)
                or not 0 < timeout_seconds <= 60):
            raise ValueError("explicit_authorized_vault_actor_and_bound_required")
        self._client, self.audit = sdk_client, audit
        self._vault, self._actor = authorized_vault_id, authorized_actor
        self.timeout_seconds = timeout_seconds
        with audit.connect() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS one_time_credentials(
                enrollment TEXT PRIMARY KEY, actor TEXT NOT NULL, vault TEXT NOT NULL,
                request TEXT NOT NULL, state TEXT NOT NULL, item_id TEXT, reference TEXT)""")

    def _authorize(self, actor, vault_id, request_id):
        if actor != self._actor or vault_id != self._vault or not ID.fullmatch(request_id):
            raise EnrollmentPending("enrollment_authorization_denied")

    def _emit(self, request_id, state):
        # No key, key fingerprint, vault/item names or references enter ordinary
        # audit/SSE. The private table retains only native correlation identities.
        self.audit.emit("credential-enrollment", "privileged-enrollment", "credential.enrollment."+state,
                        {"request_sha256": hashlib.sha256(request_id.encode()).hexdigest(), "secret_disclosed": False})

    async def enroll(self, key: SecretStr, *, actor: str, vault_id: str, request_id: str):
        self._authorize(actor, vault_id, request_id)
        if not isinstance(key, SecretStr):
            raise EnrollmentPending("in_memory_concealed_key_required")
        try:
            key = _bounded_value(key)
        except Exception:
            raise EnrollmentPending("invalid_one_time_key") from None
        existing = None
        with self.audit.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            previous = db.execute("SELECT actor,vault,request,state,reference,item_id FROM one_time_credentials WHERE enrollment=?", (ENROLLMENT_ID,)).fetchone()
            if previous:
                if previous[:3] == (actor, vault_id, request_id) and previous[3] == "verified":
                    existing = (previous[4], previous[5])
                else:
                    raise EnrollmentPending("enrollment_already_attempted_reconcile_native_item")
            else:
                db.execute("INSERT INTO one_time_credentials VALUES(?,?,?,?,'admitted',NULL,NULL)",
                           (ENROLLMENT_ID, actor, vault_id, request_id))
        if existing:
            # No raw key/fingerprint is persisted for deduplication. Revalidate
            # the native concealed field to reject changed-key request reuse.
            try:
                async with asyncio.timeout(self.timeout_seconds):
                    observed = await self._client.items.get(vault_id, existing[1])
                if not self._matches(observed, vault_id, existing[1], key):
                    raise EnrollmentPending("idempotency_key_conflict")
                self._emit(request_id, "duplicate_verified")
                return EnrollmentResult(status="already_enrolled", reference=SecretStr(existing[0]))
            except asyncio.CancelledError:
                self._emit(request_id, "duplicate_read_unresolved")
                raise
            except Exception:
                self._emit(request_id, "duplicate_read_unresolved")
                raise EnrollmentPending("duplicate_key_requires_native_reconciliation") from None
        self._emit(request_id, "admitted")
        try:
            # Official SDK signatures/types verified against installed 0.4.2 and
            # its upstream primary source. No item listing or account login.
            from onepassword.types import ItemCreateParams, ItemCategory, ItemField, ItemFieldType
            params = ItemCreateParams(category=ItemCategory.APICREDENTIALS, vault_id=vault_id,
                title="Hostinger API credential", fields=[ItemField(id="credential", title="credential",
                field_type=ItemFieldType.CONCEALED, value=key.get_secret_value())])
            async with asyncio.timeout(self.timeout_seconds):
                created = await self._client.items.create(params)
            item_id = created.id
            if not isinstance(item_id, str) or not ID.fullmatch(item_id) or created.vault_id != vault_id:
                raise EnrollmentPending("native_item_identity_unverified")
            reference = f"op://{vault_id}/{item_id}/credential"
            with self.audit.connect() as db:
                db.execute("UPDATE one_time_credentials SET item_id=?,reference=? WHERE enrollment=? AND state='admitted'", (item_id, reference, ENROLLMENT_ID))
            async with asyncio.timeout(self.timeout_seconds):
                observed = await self._client.items.get(vault_id, item_id)
            if not self._matches(observed, vault_id, item_id, key):
                raise EnrollmentPending("native_item_postcondition_unverified")
            with self.audit.connect() as db:
                db.execute("UPDATE one_time_credentials SET state='verified' WHERE enrollment=? AND state='admitted'", (ENROLLMENT_ID,))
            self._emit(request_id, "verified")
            return EnrollmentResult(status="enrolled_and_independently_verified", reference=SecretStr(reference))
        except asyncio.CancelledError:
            self._unresolved(request_id)
            raise
        except Exception:
            self._unresolved(request_id)
            raise EnrollmentPending("enrollment_unresolved_no_automatic_retry") from None

    @staticmethod
    def _matches(observed, vault_id, item_id, key):
        from onepassword.types import ItemCategory, ItemFieldType
        fields = [field for field in observed.fields if field.id == "credential"]
        return (observed.id == item_id and observed.vault_id == vault_id
                and observed.category == ItemCategory.APICREDENTIALS and len(fields) == 1
                and fields[0].field_type == ItemFieldType.CONCEALED
                and hmac.compare_digest(fields[0].value, key.get_secret_value()))

    def _unresolved(self, request_id):
        with self.audit.connect() as db:
            db.execute("UPDATE one_time_credentials SET state='unresolved' WHERE enrollment=? AND state='admitted'", (ENROLLMENT_ID,))
        self._emit(request_id, "unresolved")

    def status(self):
        with self.audit.connect() as db:
            row = db.execute("SELECT state FROM one_time_credentials WHERE enrollment=?", (ENROLLMENT_ID,)).fetchone()
        return {"status": row[0] if row else "not_attempted", "runtime_source": "1Password SDK only",
                "hostinger_retrieval": "never invoked by this helper", "secret_disclosed": False}
