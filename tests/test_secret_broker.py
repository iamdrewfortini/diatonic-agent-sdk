import asyncio
from dataclasses import replace
import json
import os
from pathlib import Path
import traceback
import types
import sys

import pytest
from pydantic import SecretStr

from meta_pipeline.secret_broker import (InjectedCredentialFile, OfficialSDKResolver,
    OnePasswordBroker, SecretBinding, SecretUnavailable, SystemdCredentialToken,
    validate_reference)


def binding(**changes):
    return SecretBinding(**{**dict(binding_id="opaque-worker", reference="op://vault-id/item-id/credential",
        purpose="gateway_virtual_key", gateway_id="existing-bifrost", tenant="tenant-a", scope_verified=True), **changes})


class FakeSDK:
    def __init__(self, value="sk-bf-disposable-fixture", error=None):
        self.value, self.error, self.calls = value, error, []
    async def resolve(self, reference):
        self.calls.append(reference)
        if self.error:
            raise RuntimeError(self.error)
        return self.value


@pytest.mark.asyncio
async def test_sdk_resolution_scoped_key_only_and_redacted_status(capsys):
    sdk = FakeSDK()
    broker = OnePasswordBroker([binding()], resolver=sdk)
    key = await broker.resolve_worker_key("opaque-worker", gateway_id="existing-bifrost", tenant="tenant-a")
    assert isinstance(key, SecretStr) and key.get_secret_value() == sdk.value
    assert sdk.value not in repr(key)
    assert sdk.calls == [binding().reference]
    status = json.dumps(broker.status())
    assert "vault-id" not in status and "item-id" not in status and sdk.value not in status
    assert broker.status()["mode"] == "unattended_official_sdk"
    assert not broker.status()["cli_dependency"] and not broker.status()["interactive_authentication"]
    assert capsys.readouterr().out == ""


@pytest.mark.asyncio
@pytest.mark.parametrize("changes,request_scope", [
    ({"purpose": "provider_upstream"}, {}), ({"purpose": "gateway_admin"}, {}),
    ({"scope_verified": False}, {}), ({}, {"tenant": "other"}),
    ({}, {"gateway_id": "other"})])
async def test_worker_cannot_obtain_upstream_admin_or_cross_scope(changes, request_scope):
    sdk = FakeSDK()
    broker = OnePasswordBroker([binding(**changes)], resolver=sdk)
    args = {"gateway_id": "existing-bifrost", "tenant": "tenant-a", **request_scope}
    with pytest.raises(SecretUnavailable, match="worker_scope_denied"):
        await broker.resolve_worker_key("opaque-worker", **args)
    assert sdk.calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize("value", ["", "not-a-virtual-key", "sk-bf-key\nsecond", "sk-bf-"+"a"*16384, "sk-bf-key with space"])
async def test_invalid_secret_value_rejected_without_output(value, capsys):
    broker = OnePasswordBroker([binding()], resolver=FakeSDK(value))
    with pytest.raises(SecretUnavailable) as error:
        await broker.resolve_worker_key("opaque-worker", gateway_id="existing-bifrost", tenant="tenant-a")
    assert "sk-bf-" not in str(error.value)
    assert capsys.readouterr().out == ""


@pytest.mark.asyncio
async def test_sdk_error_body_never_appears_in_error_or_probe(capsys):
    sentinel = "UPSTREAM_SECRET_AND_PRIVATE_ITEM_NAME"
    broker = OnePasswordBroker([binding()], resolver=FakeSDK(error=sentinel))
    try:
        await broker.resolve_worker_key("opaque-worker", gateway_id="existing-bifrost", tenant="tenant-a")
    except SecretUnavailable as error:
        assert sentinel not in "".join(traceback.format_exception(error))
    result = await broker.probe_worker_binding("opaque-worker", gateway_id="existing-bifrost", tenant="tenant-a")
    assert result == {"status": "pending", "reason": "sdk_resolution_pending", "secret_disclosed": False}
    assert sentinel not in repr(result) and capsys.readouterr().out == ""


@pytest.mark.asyncio
async def test_timeout_no_retry_and_missing_bootstrap_pending():
    class Slow:
        calls = 0
        async def resolve(self, ref):
            self.calls += 1
            await asyncio.sleep(1)
    slow = Slow()
    broker = OnePasswordBroker([binding()], resolver=slow, timeout_seconds=.001)
    assert (await broker.probe_worker_binding("opaque-worker", gateway_id="existing-bifrost", tenant="tenant-a"))["reason"] == "sdk_resolution_pending"
    assert slow.calls == 1
    missing = OnePasswordBroker([binding()])
    assert (await missing.probe_worker_binding("opaque-worker", gateway_id="existing-bifrost", tenant="tenant-a"))["reason"] == "sdk_bootstrap_pending"


@pytest.mark.parametrize("ref", ["env:TOKEN", "op://vault/item", "op://vault/*/field", "op://vault/item/field?attribute=other", "op://vault/item/field#part", "op://vault/../field", "op://vault/item/%2fescape", "op://vault/item/field\n", "op://vault//field"])
def test_only_exact_reference_accepted(ref):
    with pytest.raises(ValueError):
        validate_reference(ref)


def test_reference_literal_names_no_shell_and_hidden_repr():
    ref = "op://vault/item $(false); with spaces/field"
    assert validate_reference(ref) == ref
    assert ref not in repr(binding(reference=ref))


def test_systemd_existing_private_credential_no_environment_token(tmp_path, monkeypatch):
    monkeypatch.delenv("CREDENTIALS_DIRECTORY", raising=False)
    source = SystemdCredentialToken("sdk-bootstrap")
    assert not source.available()
    with pytest.raises(SecretUnavailable, match="not_injected"):
        source.load()
    token = tmp_path / "sdk-bootstrap"
    token.write_text("disposable-service-account-token\n"); token.chmod(0o400)
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(tmp_path))
    assert source.available()
    assert source.load().get_secret_value() == "disposable-service-account-token"
    assert "disposable-service-account-token" not in repr(source)
    token.chmod(0o644)
    assert not source.available()
    with pytest.raises(SecretUnavailable, match="not_private"):
        source.load()


def test_credential_symlink_and_oversized_file_rejected(tmp_path):
    real = tmp_path / "real"; real.write_text("private-token"); real.chmod(0o600)
    link = tmp_path / "link"; link.symlink_to(real)
    with pytest.raises(SecretUnavailable):
        InjectedCredentialFile(link).load()
    real.write_bytes(b"x"*17000)
    with pytest.raises(SecretUnavailable):
        InjectedCredentialFile(real).load()


@pytest.mark.asyncio
async def test_official_sdk_service_auth_and_resolution_no_cli(tmp_path, monkeypatch):
    calls = []
    sdk = types.SimpleNamespace(secrets=types.SimpleNamespace(resolve=None))
    async def resolve(ref):
        calls.append(("resolve", ref)); return "sk-bf-fixture-key"
    sdk.secrets.resolve = resolve
    class Client:
        @classmethod
        async def authenticate(cls, **kwargs):
            calls.append(("authenticate", kwargs))
            return sdk
    parent = types.ModuleType("onepassword")
    child = types.ModuleType("onepassword.client"); child.Client = Client
    monkeypatch.setitem(sys.modules, "onepassword", parent)
    monkeypatch.setitem(sys.modules, "onepassword.client", child)
    injected = tmp_path / "bootstrap"; injected.write_text("service-token-fixture"); injected.chmod(0o400)
    broker = await OnePasswordBroker.from_service_account([binding()], token_source=InjectedCredentialFile(injected))
    key = await broker.resolve_worker_key("opaque-worker", gateway_id="existing-bifrost", tenant="tenant-a")
    assert key.get_secret_value() == "sk-bf-fixture-key"
    assert calls[0][0] == "authenticate" and calls[0][1]["auth"] == "service-token-fixture"
    assert calls[0][1]["integration_name"] == "Diatonic credential broker"
    assert calls[1] == ("resolve", binding().reference)
    assert "service-token-fixture" not in json.dumps(broker.status())


def test_duplicate_binding_rejected():
    with pytest.raises(ValueError, match="duplicate"):
        OnePasswordBroker([binding(), binding()])
