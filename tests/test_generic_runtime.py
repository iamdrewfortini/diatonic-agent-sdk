import asyncio
import hashlib
import json

import httpx
import pytest
from pydantic import SecretStr

from meta_pipeline.audit import Audit
from meta_pipeline.gateway import GatewayConfig
from meta_pipeline.generic_gateway import GenericGateway, SDKPorts
from meta_pipeline.ledger import Ledger
from meta_pipeline.model_routing import RouteSelector, RouteAbstention
from meta_pipeline.provider_contracts import ChatShapeAdapter, SDKBinding, UsageBound, BrokerMessage, PromptBinding
from meta_pipeline.prompt_library import PromptLibrary
from test_provider_contracts import request
from test_model_routing import registry, NOW


class FixtureSecrets:
    async def resolve_worker_key(self, binding_id, *, gateway_id, tenant):
        assert (binding_id, gateway_id, tenant) == ("worker-key", "bifrost", "fixture")
        return SecretStr("private-fixture-virtual-key")


def setup(tmp_path, handler, *, broker=None, enabled=True):
    r = registry(provider="independent-provider")
    selector = RouteSelector(r, gateway_id="bifrost", gateway_attempts=3, now=lambda: NOW)
    ports = SDKPorts(); ports.register("chat", "1", "chat-completions-v1", ChatShapeAdapter())
    ledger = Ledger(str(tmp_path / "usage"), 100000, 50000)
    audit = Audit(tmp_path / "audit")
    config = GatewayConfig(base_url="http://localhost:8080/openai", allowed_hosts=["localhost"],gateway_attempts=3)
    gateway = GenericGateway(config, ledger, audit, selector=selector, sdk_ports=ports,
        secret_broker=broker or FixtureSecrets(), tenant="fixture", transport=httpx.MockTransport(handler), enabled=enabled)
    return gateway, ledger, audit, r


def response(req, *, usage=True, headers=None, model="model-any-version"):
    body = {"model": model, "choices": [{"finish_reason": "stop", "message": {"content": "fixture proposal"}}]}
    if usage:
        body["usage"] = {"prompt_tokens": 10, "completion_tokens": 5, "cost_nusd": 0}
    return httpx.Response(200, json=body, headers=headers or {})


@pytest.mark.asyncio
async def test_provider_neutral_runtime_bifrost_identity_budget_and_no_secret_logging(tmp_path):
    calls = []
    def handler(req):
        calls.append(req)
        assert str(req.url) == "http://localhost:8080/openai/chat/completions"
        assert req.headers["x-bf-vk"] == "private-fixture-virtual-key"
        assert "api_key" not in req.content.decode()
        assert json.loads(req.content)["model"] == "independent-provider/model-any-version"
        return response(req)
    gateway, ledger, audit, _ = setup(tmp_path, handler)
    try:
        out = await gateway.generate(request())
        assert out.status == "proposed" and not out.execution_verified
        assert out.provider_id == "independent-provider" and out.usage.cost_nusd == 40
        summary = ledger.summary()["by_model"]["independent-provider/model-any-version"]
        assert summary["input_tokens"] == 10 and summary["output_tokens"] == 5
        assert summary["retry_allowance_held_nusd"] == (4096*2+16*4)*2
        assert "private-fixture-virtual-key" not in json.dumps(audit.events())
        assert len(calls) == 1 and audit.verify()["valid"]
    finally:
        await gateway.close()


@pytest.mark.asyncio
async def test_unknown_usage_preserved_as_unknown_and_no_automatic_retry(tmp_path):
    calls = []
    gateway, ledger, _, _ = setup(tmp_path, lambda req: (calls.append(req), response(req, usage=False))[1])
    try:
        out = await gateway.generate(request())
        assert out.status == "unresolved" and out.usage.input_tokens is None
        summary = ledger.summary()["by_model"]["independent-provider/model-any-version"]
        assert summary["unknown_usage_calls"] == 1
        assert summary["unresolved_reservation_nusd"] == (4096*2+16*4)*3
        assert len(calls) == 1
    finally:
        await gateway.close()


@pytest.mark.asyncio
async def test_trusted_response_cache_replay_not_counted_as_new_provider_tokens(tmp_path):
    gateway, ledger, _, _ = setup(tmp_path, lambda req: response(req, headers={"x-bifrost-cache-hit": "true", "x-bifrost-cache-hit-type": "direct"}))
    try:
        out = await gateway.generate(request())
        assert out.usage.input_tokens == out.usage.output_tokens == out.usage.cost_nusd == 0
        row = ledger.summary()["by_model"]["independent-provider/model-any-version"]
        assert row["input_tokens"] == row["known_derived_cost_nusd"] == 0
        assert row["direct_cache_hits"] == 1
        with ledger.connect() as db:
            detail = json.loads(db.execute("SELECT detail FROM calls").fetchone()[0])
        assert detail["replayed_usage"]["input_tokens"] == 10
    finally:
        await gateway.close()


@pytest.mark.asyncio
async def test_stale_route_during_async_secret_resolution_abstains_before_network(tmp_path):
    calls = []
    class MutatingSecrets(FixtureSecrets):
        async def resolve_worker_key(self, *args, **kwargs):
            old = r.active(SDKBinding)[0]
            r.register(old.model_copy(update={"version":"2"}))
            r.activate(SDKBinding, old.id, "2", expected_version="1")
            return await super().resolve_worker_key(*args, **kwargs)
    gateway, ledger, _, r = setup(tmp_path, lambda req: calls.append(req), broker=MutatingSecrets())
    try:
        out = await gateway.generate(request())
        assert isinstance(out, RouteAbstention) and calls == []
        assert ledger.summary()["states"] == []
    finally:
        await gateway.close()


@pytest.mark.asyncio
async def test_disabled_runtime_and_understated_input_bound_never_make_paid_call(tmp_path):
    calls = []
    gateway, ledger, _, _ = setup(tmp_path, lambda req: calls.append(req), enabled=False)
    try:
        assert isinstance(await gateway.generate(request()), RouteAbstention)
        gateway.enabled = True
        req = request(messages=(BrokerMessage(role="user",content="x"*10000),),
            usage_bounds=(UsageBound(unit="input_tokens",quantity=1),UsageBound(unit="output_tokens",quantity=16)))
        assert isinstance(await gateway.generate(req), RouteAbstention)
        assert calls == [] and ledger.summary()["states"] == []
    finally:
        await gateway.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["disconnect", "redirect", "malformed", "cancel"])
async def test_failures_retain_reservation_without_fallback_or_retry(tmp_path, failure):
    calls = []
    def handler(req):
        calls.append(req)
        if failure == "disconnect": raise httpx.ReadError("sensitive fixture body")
        if failure == "cancel": raise asyncio.CancelledError()
        if failure == "redirect": return httpx.Response(302, headers={"location":"https://api.anthropic.com/v1/messages"})
        return httpx.Response(200, text="not JSON")
    gateway, ledger, audit, _ = setup(tmp_path, handler)
    try:
        with pytest.raises((httpx.ReadError, ValueError, asyncio.CancelledError)):
            await gateway.generate(request())
        row = ledger.summary()["by_model"]["independent-provider/model-any-version"]
        assert row["unresolved_reservation_nusd"] > 0 and len(calls) == 1
        assert "sensitive fixture body" not in json.dumps(audit.events())
    finally:
        await gateway.close()


def test_private_immutable_prompt_store_version_switch_and_source_hash(tmp_path):
    p = PromptLibrary(tmp_path / "prompts")
    binding = PromptBinding(id="prompt",version="1",source_sha256="a"*64,template="Trusted instructions")
    digest = p.put(binding)
    assert p.put(binding) == digest == p.get("prompt").digest
    with pytest.raises(ValueError): p.put(binding.model_copy(update={"template":"changed"}))
    p.put(binding.model_copy(update={"version":"2", "template":"Reviewed new instructions"}))
    p.activate("prompt","2",expected_version="1")
    assert p.get("prompt").version == "2" and p.get("prompt","1").template == "Trusted instructions"
    with pytest.raises(ValueError): p.activate("prompt","1",expected_version="1")
    assert p.gateway_storage_plan("prompt")["native_activation"].startswith("pending")
    assert not p.gateway_storage_plan("prompt")["sensitive_content_exported"]
