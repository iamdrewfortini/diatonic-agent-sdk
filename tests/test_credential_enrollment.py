import asyncio
import json
import os
from types import SimpleNamespace

from onepassword.types import ItemCategory, ItemFieldType
from pydantic import SecretStr
import pytest

from meta_pipeline.audit import Audit
from meta_pipeline.credential_enrollment import (EnrollmentPending,
    OneTimeCredentialEnrollment, read_private_pipe)
from meta_pipeline.secret_broker import OnePasswordBroker, SecretBinding, SecretUnavailable


class FixtureItems:
    def __init__(self, *, mode="valid"):
        self.mode, self.creates, self.gets = mode, [], []
    async def create(self, params):
        self.creates.append(params)
        if self.mode == "disconnect":
            raise OSError("PRIVATEKEY_IN_UPSTREAM_ERROR")
        if self.mode in {"timeout", "cancel"}:
            await asyncio.sleep(10)
        self.item = SimpleNamespace(id="item-native", vault_id=params.vault_id,
                                   fields=params.fields, category=params.category)
        return self.item
    async def get(self, vault, item):
        self.gets.append((vault, item))
        if self.mode == "wrong":
            self.item.fields[0].value = "different-key"
        return self.item


def setup(tmp_path, *, mode="valid", timeout=1):
    items = FixtureItems(mode=mode)
    audit = Audit(tmp_path / "private-audit.db")
    enrollment = OneTimeCredentialEnrollment(SimpleNamespace(items=items), audit,
                        authorized_vault_id="explicit-vault", authorized_actor="authorized-operator", timeout_seconds=timeout)
    return enrollment, items, audit


@pytest.mark.asyncio
async def test_one_create_concealed_native_get_verification_and_idempotency(tmp_path, capsys):
    helper, items, audit = setup(tmp_path)
    args = dict(actor="authorized-operator", vault_id="explicit-vault", request_id="once")
    key = SecretStr("HOSTINGER_PRIVATE_KEY_FIXTURE")
    result = await helper.enroll(key, **args)
    assert result.status == "enrolled_and_independently_verified"
    assert result.reference.get_secret_value() == "op://explicit-vault/item-native/credential"
    assert len(items.creates) == 1 and items.gets == [("explicit-vault", "item-native")]
    params = items.creates[0]
    assert params.category == ItemCategory.APICREDENTIALS
    assert len(params.fields) == 1 and params.fields[0].field_type == ItemFieldType.CONCEALED
    assert (await helper.enroll(key, **args)).status == "already_enrolled"
    assert len(items.creates) == 1
    assert "HOSTINGER_PRIVATE_KEY_FIXTURE" not in json.dumps(audit.events())
    assert "explicit-vault" not in json.dumps(audit.events())
    assert "HOSTINGER_PRIVATE_KEY_FIXTURE" not in repr(result)
    assert capsys.readouterr().out == ""
    assert helper.status()["status"] == "verified"


@pytest.mark.asyncio
@pytest.mark.parametrize("args", [dict(actor="worker", vault_id="explicit-vault", request_id="once"),
                                  dict(actor="authorized-operator", vault_id="other-vault", request_id="once")])
async def test_worker_or_other_vault_denied_without_create(tmp_path, args):
    helper, items, _ = setup(tmp_path)
    with pytest.raises(EnrollmentPending, match="authorization"):
        await helper.enroll(SecretStr("private-key"), **args)
    assert not items.creates


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["wrong", "disconnect", "timeout"])
async def test_unknown_native_create_no_repeat_or_key_error_leak(tmp_path, mode):
    helper, items, audit = setup(tmp_path, mode=mode, timeout=.001 if mode == "timeout" else 1)
    args = dict(actor="authorized-operator", vault_id="explicit-vault", request_id="once")
    with pytest.raises(EnrollmentPending, match="unresolved") as error:
        await helper.enroll(SecretStr("private-key"), **args)
    assert "PRIVATEKEY_IN_UPSTREAM_ERROR" not in str(error.value)
    assert helper.status()["status"] == "unresolved"
    with pytest.raises(EnrollmentPending, match="already_attempted"):
        await helper.enroll(SecretStr("private-key"), **args)
    assert len(items.creates) == 1
    assert "private-key" not in json.dumps(audit.events())


@pytest.mark.asyncio
async def test_cancellation_retains_unknown_create(tmp_path):
    helper, items, _ = setup(tmp_path, mode="cancel")
    task = asyncio.create_task(helper.enroll(SecretStr("private-key"), actor="authorized-operator", vault_id="explicit-vault", request_id="once"))
    while not items.creates:
        await asyncio.sleep(0)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert helper.status()["status"] == "unresolved"


def test_private_pipe_and_regular_file_denial(tmp_path):
    reader, writer = os.pipe()
    try:
        os.write(writer, b"PRIVATE_PIPE_KEY")
        os.close(writer); writer = None
        assert read_private_pipe(reader).get_secret_value() == "PRIVATE_PIPE_KEY"
    finally:
        os.close(reader)
        if writer is not None: os.close(writer)
    path = tmp_path / "key"; path.write_text("private-key")
    with path.open("rb") as stream:
        with pytest.raises(EnrollmentPending, match="pipe"):
            read_private_pipe(stream.fileno())


@pytest.mark.asyncio
async def test_enrolled_upstream_reference_never_becomes_worker_access(tmp_path):
    helper, _, _ = setup(tmp_path)
    result = await helper.enroll(SecretStr("private-key"), actor="authorized-operator", vault_id="explicit-vault", request_id="once")
    binding = SecretBinding("opaque", result.reference.get_secret_value(), "provider_upstream", "gateway", "tenant", True)
    broker = OnePasswordBroker([binding])
    with pytest.raises(SecretUnavailable, match="worker_scope_denied"):
        await broker.resolve_worker_key("opaque", gateway_id="gateway", tenant="tenant")


def test_partial_private_pipe_never_enrolls_a_prefix():
    reader, writer = os.pipe()
    try:
        os.write(writer, b"prefix")
        with pytest.raises(EnrollmentPending, match="incomplete"):
            read_private_pipe(reader)
    finally:
        os.close(reader); os.close(writer)


@pytest.mark.asyncio
async def test_changed_key_same_request_cannot_return_cached_success(tmp_path):
    helper, items, audit = setup(tmp_path)
    args = dict(actor="authorized-operator", vault_id="explicit-vault", request_id="once")
    await helper.enroll(SecretStr("original-private-key"), **args)
    with pytest.raises(EnrollmentPending, match="reconciliation"):
        await helper.enroll(SecretStr("different-private-key"), **args)
    assert len(items.creates) == 1 and len(items.gets) == 2
    assert "different-private-key" not in json.dumps(audit.events())
