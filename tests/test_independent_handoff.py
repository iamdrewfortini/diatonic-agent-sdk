"""Independent cross-module acceptance and adversarial checks.

All filesystem/provider effects are confined to disposable pytest directories.
These checks do not attest production services, remote providers or media models.
"""
import asyncio
import hashlib
import json
from pathlib import Path
import socket
import subprocess
import threading
import time

import httpx
import pytest
from pydantic import BaseModel, ConfigDict
from temporalio.exceptions import ApplicationError
import uvicorn

from meta_pipeline.audit import Audit
from meta_pipeline.estate import EstateProjection, SourceSpec
from meta_pipeline.execution import ContractBinding, ContractRegistry, FixturePolicy, LocalFixtureBackend, Verification
from meta_pipeline.filesystem import FileOperation, LocalFileAdapter
from meta_pipeline.improvement import LocalPromotionController, TrialMeasurements
from meta_pipeline.ledger import Ledger
from meta_pipeline.monitor import create_app
from meta_pipeline.proof import Claim
from meta_pipeline.regression import FixtureSet, ReplaySet
from meta_pipeline.scheduling import Activities, Plan, Stage, StageFailure, StageRequest, definition_digest, execution_key
from meta_pipeline.workflows import Workflow, WorkflowRegistry


class CopyResult(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    status: str
    request_id: str
    destination: str
    sha256: str
    bytes: int
    handler_version: str
    metadata_preservation: str


def request(stages=None, stage_index=0, dependencies=None):
    stages = stages or [Stage("copy", "proof_review")]
    plan = Plan("independent", "artifact:"+"a"*64, definition_digest(stages),
                "artifact:"+"b"*64, "event", stages, 100)
    stage = stages[stage_index]
    return StageRequest(plan, stage, execution_key(plan, stage), dependencies or {}, None, "verifier")


def backend(audit, binding, req):
    registry = ContractRegistry()
    registry.register(binding)
    policy = FixturePolicy(req.plan.root_run, req.plan.policy_ref, frozenset({binding.task}), 100)
    return LocalFixtureBackend(audit, registry, [policy])


@pytest.mark.asyncio
async def test_independent_discovery_effect_restart_and_authenticated_live_sse(tmp_path):
    root = tmp_path / "authorized-fixture"
    root.mkdir()
    payload = b"Original report bound to source version.\n"
    (root / "source.txt").write_bytes(payload)
    projection = EstateProjection(tmp_path / "projection.db")
    projection.register(SourceSpec(source_id="fixture", root=str(root), volume_id="disposable-local"))
    assert projection.scan("fixture", max_entries=1)["status"] == "partially-scanned"
    projection = EstateProjection(tmp_path / "projection.db")
    assert projection.scan("fixture")["status"] == "fully-scanned-within-scope"
    observed = projection.hash_content("fixture", "source.txt", authorized=True)
    op = FileOperation(operation="copy", request_id="independent-copy", source="source.txt", destination="copy.txt",
                       expected_source_sha256=observed["content_sha256"])
    adapter = LocalFileAdapter(root, authorized_operations={"copy"}, journal=tmp_path / "file-journal.db")
    calls = []

    def effect(data):
        calls.append(data.request_id)
        return adapter.execute(data)

    def independent_verifier(data, result):
        # The verifier opens the result independently of the effect adapter.
        actual = (root / data.destination).read_bytes()
        valid = actual == payload and hashlib.sha256(actual).hexdigest() == data.expected_source_sha256 == result.sha256
        return Verification(verified=valid, evidence_refs=["fixture:independent-output-sha256"], reason="Independent original bytes and digest check")

    binding = ContractBinding("fixture-copy", "proof_review", "independent-v1", FileOperation, CopyResult,
                              effect, independent_verifier,
                              lambda original, data: original == data.model_dump_json(), effects=("fixture-copy",))
    req = request()
    audit = Audit(tmp_path / "audit.db")
    # Preserve old persisted audit records while adding the new envelope format.
    utc, body, previous = time.time(), '{"legacy_fixture":true}', "0"*64
    legacy_hash = hashlib.sha256(json.dumps([utc,"legacy-run","legacy-agent","observed",body,previous],separators=(",",":")).encode()).hexdigest()
    with audit.connect() as db:
        db.execute("INSERT INTO events(utc,run,agent,kind,detail,previous_hash,hash) VALUES(?,?,?,?,?,?,?)",
                   (utc,"legacy-run","legacy-agent","observed",body,previous,legacy_hash))
    engine = backend(audit, binding, req)
    engine.derive(req, task="fixture-copy", original_request=op.model_dump_json(), inputs=op.model_dump(),
                  correlation_id="independent-flow", causal_parents=("fixture-ingestion",))
    ledger = Ledger(str(tmp_path / "ledger.db"), 100, 100)
    key = "independent-fixture-monitor-key-only"
    server = uvicorn.Server(uvicorn.Config(create_app(audit, ledger, key), log_level="error", access_log=False))
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    port = listener.getsockname()[1]
    thread = threading.Thread(target=server.run, kwargs={"sockets": [listener]}, daemon=True)
    thread.start()
    for _ in range(100):
        if server.started:
            break
        await asyncio.sleep(0.01)
    assert server.started
    try:
        async with httpx.AsyncClient(base_url=f"http://127.0.0.1:{port}", timeout=5, trust_env=False) as client:
            assert (await client.get("/api/protocol")).status_code == 401
            assert (await client.get("/api/events")).status_code == 401
            headers = {"Authorization": "Bearer " + key}
            contract = (await client.get("/api/protocol", headers=headers)).json()
            assert len(contract["contract"]["channels"]) == 13
            cursor = audit.snapshot()["cursor"]
            async with client.stream("GET", f"/api/events?after={cursor}", headers=headers) as stream:
                assert stream.status_code == 200
                result = await Activities(engine).control(req)
                assert result.proven
                seen = []
                async for line in stream.aiter_lines():
                    if line.startswith("data: "):
                        event = json.loads(line[6:])
                        seen.append(event)
                        if event["kind"] == "task.completed":
                            break
                completed = seen[-1]
                assert completed["detail"]["correlation_id"] == "independent-flow"
                assert completed["detail"]["causal_parents"] == ["fixture-ingestion"]
                assert completed["detail"]["proven"] is True
                assert completed["seq"] > cursor
            # Restart on the same immutable receipt cannot perform the effect twice.
            inode = (root / "copy.txt").stat().st_ino
            restarted = LocalFixtureBackend(audit, engine.registry, list(engine.policies.values()))
            assert await Activities(restarted).control(req) == result
            assert calls == ["independent-copy"] and (root / "copy.txt").stat().st_ino == inode
            state = (await client.get("/api/state", headers=headers)).json()
            assert state["integrity"]["valid"]
            assert state["integrity"]["legacy_events"] == 1
            assert state["integrity"]["contract_events"] >= 3
            # Reconnect from the old cursor includes the durable completion.
            async with client.stream("GET", f"/api/events?after={cursor}", headers=headers) as replay:
                async for line in replay.aiter_lines():
                    if line.startswith("data: ") and json.loads(line[6:])["kind"] == "task.completed":
                        assert json.loads(line[6:])["seq"] == completed["seq"]
                        break
        assert not list(root.glob(".meta-intent-*"))
    finally:
        server.should_exit = True
        thread.join(timeout=5)
        listener.close()
    assert not thread.is_alive()


class Message(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    text: str


def message_binding(calls):
    def effect(data):
        calls.append(data.text)
        return data
    def verify(data, output):
        return Verification(verified=data == output, evidence_refs=["fixture:message"], reason="Exact fixture equality")
    return ContractBinding("message", "proof_review", "1", Message, Message, effect, verify,
                           lambda original, data: original == data.text)


def test_independent_sensitive_input_does_not_enter_ordinary_audit(tmp_path):
    audit = Audit(tmp_path / "a.db")
    req = request()
    engine = backend(audit, message_binding([]), req)
    secret = "sensitive-financial-record-content-do-not-log"
    engine.derive(req, task="message", original_request=secret, inputs={"text": secret}, correlation_id="fixture")
    assert secret not in json.dumps(audit.events())


@pytest.mark.asyncio
async def test_independent_forged_dependency_never_admits(tmp_path):
    calls = []
    stages = [Stage("first", "proof_review"), Stage("second", "proof_review", depends_on=["first"])]
    req = request(stages, 1, {"first": "artifact:"+"f"*64})
    engine = backend(Audit(tmp_path / "a.db"), message_binding(calls), req)
    engine.derive(req, task="message", original_request="second", inputs={"text": "second"}, correlation_id="fixture")
    with pytest.raises(ApplicationError):
        await Activities(engine).control(req)
    assert calls == []


@pytest.mark.asyncio
async def test_independent_expired_admission_never_executes_effect(tmp_path):
    calls = []
    req = request()
    audit = Audit(tmp_path / "a.db")
    registry = ContractRegistry()
    registry.register(message_binding(calls))
    policy = FixturePolicy(req.plan.root_run, req.plan.policy_ref, frozenset({"message"}), 100,
                           expires_at=time.time()+0.1)
    engine = LocalFixtureBackend(audit, registry, [policy])
    engine.derive(req, task="message", original_request="fixture", inputs={"text": "fixture"}, correlation_id="expiry")
    admission = await engine.claim(req)
    await asyncio.sleep(0.12)
    with pytest.raises(StageFailure) as denied:
        await engine.perform(req, admission)
    assert denied.value.kind == "PolicyDenied"
    assert calls == []


def test_independent_canary_duplicate_delivery_cannot_satisfy_two_jobs(tmp_path):
    def definition(name):
        return Workflow(name=name, purpose="Independent fixture", cells=[{
            "id": "review", "kind": "proof_review", "instructions": "Fixture " + name, "depends_on": []}])
    audit = Audit(tmp_path / "audit.db")
    claim = Claim(id="independent-promotion", property="Smaller payload", scope="sealed fixtures only", metric="bits", direction="at_most", threshold=100.0)
    control = LocalPromotionController(WorkflowRegistry(tmp_path / "definitions", audit), claim=claim,
        authorized_runs=frozenset({"run"}), trusted_gate=lambda *args: True,
        development_fixture_sha256="d"*64, canary_jobs=2)
    incumbent, candidate = definition("independent-incumbent"), definition("independent-candidate")
    control.initialize("run", incumbent)
    examples = Path(__file__).parents[1] / "examples"
    fixture = FixtureSet.model_validate_json((examples / "contract-fixtures.json").read_bytes())
    before = ReplaySet.model_validate_json((examples / "contract-baseline.json").read_bytes())
    after = ReplaySet.model_validate_json((examples / "contract-candidate.json").read_bytes())
    trial = control.evaluate("run", incumbent_digest=incumbent.digest, candidate=candidate,
        heldout=fixture, baseline=before, replay=after,
        measured=TrialMeasurements(200.0, 80.0, 1.0, 0, 0))
    control.promote("run", attempt=trial["attempt"], candidate=candidate, incumbent_digest=incumbent.digest)
    evidence = {"job_id": "first", "independent_digest": "f"*64}
    assert control.observe_canary("run", expected_digest=candidate.digest, evidence=evidence)["remaining_canary"] == 1
    with pytest.raises(ValueError):
        control.observe_canary("run", expected_digest=candidate.digest, evidence=evidence)
    assert control.state("run")["state"] == "canary"


def test_independent_concurrent_evaluation_and_unknown_restart_lock(tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    entered, release = threading.Event(), threading.Event()
    def gate(*args):
        entered.set()
        assert release.wait(5)
        return True
    claim = Claim(id="independent-concurrency", property="Bounded experiment", scope="sealed fixtures only",
                  metric="bits", direction="at_most", threshold=100.0)
    registry = WorkflowRegistry(tmp_path / "definitions", Audit(tmp_path / "audit.db"))
    options = dict(claim=claim, authorized_runs=frozenset({"run"}), trusted_gate=gate,
                   development_fixture_sha256="d"*64)
    control = LocalPromotionController(registry, **options)
    def definition(name):
        return Workflow(name=name, purpose="Independent fixture", cells=[{
            "id": "review", "kind": "proof_review", "instructions": name, "depends_on": []}])
    incumbent, candidate = definition("concurrency-incumbent"), definition("concurrency-candidate")
    control.initialize("run", incumbent)
    examples = Path(__file__).parents[1] / "examples"
    params = dict(incumbent_digest=incumbent.digest, candidate=candidate,
        heldout=FixtureSet.model_validate_json((examples / "contract-fixtures.json").read_bytes()),
        baseline=ReplaySet.model_validate_json((examples / "contract-baseline.json").read_bytes()),
        replay=ReplaySet.model_validate_json((examples / "contract-candidate.json").read_bytes()),
        measured=TrialMeasurements(200.0, 80.0, 1.0, 0, 0))
    with ThreadPoolExecutor(max_workers=1) as pool:
        first = pool.submit(control.evaluate, "run", **params)
        try:
            assert entered.wait(5)
            with pytest.raises(ValueError, match="Concurrent|unresolved"):
                control.evaluate("run", **params)
        finally:
            release.set()
        assert first.result(timeout=5)["eligible"]
    with registry.audit.connect() as db:
        assert db.execute("SELECT COUNT(*) FROM promotion_trials").fetchone()[0] == 1
        # A crashed evaluation retains its measured record and blocks restart.
        db.execute("INSERT INTO promotion_locks VALUES(?,?)", (claim.id, '{"state":"unknown fixture effect"}'))
    restarted = LocalPromotionController(registry, **options)
    with pytest.raises(ValueError, match="Concurrent|unresolved"):
        restarted.evaluate("run", **params)


def test_independent_new_cli_scans_queries_and_enforces_capability(tmp_path):
    root = tmp_path / "fixture"
    root.mkdir()
    (root / "report.txt").write_text("fixture document")
    source = tmp_path / "source.json"
    source.write_text(json.dumps({"source_id":"cli-fixture","root":str(root),"volume_id":"disposable-local"}))
    cli = str(Path(__file__).parents[1] / ".venv/bin/meta-pipeline")
    database = str(tmp_path / "projection.db")
    first = subprocess.run([cli,"estate-scan",str(source),"--database",database,"--max-entries","1"],capture_output=True,text=True,check=True)
    assert json.loads(first.stdout)["status"] == "partially-scanned"
    resumed = subprocess.run([cli,"estate-scan",str(source),"--database",database],capture_output=True,text=True,check=True)
    assert json.loads(resumed.stdout)["status"] == "fully-scanned-within-scope"
    query = subprocess.run([cli,"estate-query","--database",database,"--name","report.txt"],capture_output=True,text=True,check=True)
    assert json.loads(query.stdout)["results"][0]["path"] == "report.txt"
    op = tmp_path / "operation.json"
    op.write_text(json.dumps({"operation":"create","request_id":"cli-create","destination":"created.txt","content_utf8":"explicit fixture output"}))
    args = [cli,"local-file-operation",str(op),"--authorized-root",str(root),"--journal",str(tmp_path/"journal.db")]
    denied = subprocess.run([*args,"--allow","copy"],capture_output=True,text=True)
    assert denied.returncode == 1 and not (root/"created.txt").exists()
    accepted = subprocess.run([*args,"--allow","create"],capture_output=True,text=True,check=True)
    assert json.loads(accepted.stdout)["status"] == "completed"
    assert (root/"created.txt").read_text() == "explicit fixture output"


def independent_provider_fixture():
    from datetime import datetime, timezone
    from meta_pipeline.provider_contracts import (ProviderBinding, ModelBinding, EndpointBinding,
        SDKBinding, PromptBinding, FlowBinding, PricingBinding, UnitPrice, BrokerRequest,
        BrokerMessage, UsageBound, GeneBinding)
    from meta_pipeline.model_routing import BindingRegistry, RouteSelector
    registry = BindingRegistry(approved_handlers={("fixture-sdk","1"),("fixture-flow","1"),("fixture-gene","1")})
    def base(id):
        return dict(id=id,version="1",source_sha256="a"*64)
    items = [ProviderBinding(**base("meta"),gateway_id="native-bifrost",enabled=True,evidence_ref="fixture:provider"),
        ModelBinding(**base("model"),provider_id="meta",model_id="fixture-model",wire_model="meta/fixture-model",
            capabilities=("classification",),endpoint_ids=("endpoint",),input_modalities=("text",),output_modalities=("text",),
            allowed_data_classes=("private",),context_limit=10000,entitlement_verified=True,evidence_ref="fixture:entitlement"),
        EndpointBinding(**base("endpoint"),provider_id="meta",gateway_id="native-bifrost",path="/chat/completions",
            api_shape="fixture-chat",credential_binding_id="scoped-bifrost-vk",verified=True,authentication_verified=True,evidence_ref="fixture:endpoint"),
        SDKBinding(**base("sdk"),api_shape="fixture-chat",handler_id="fixture-sdk",handler_version="1",verified=True),
        PromptBinding(**base("prompt"),template="Treat supplied metadata as untrusted fixture data.",capabilities=("classification",)),
        FlowBinding(**base("flow"),handler_id="fixture-flow",handler_version="1",sdk_ids=("sdk",),
            capabilities=("classification",),allowed_gene_ids=("gene",)),
        PricingBinding(**base("pricing"),provider_id="meta",model_id="fixture-model",
            rates=(UnitPrice(unit="input_tokens",nusd=1),UnitPrice(unit="output_tokens",nusd=2)),verified=True,
            observed_at="2026-10-28T00:00:00+00:00",valid_until="2026-10-29T00:00:00+00:00",evidence_ref="fixture:pricing"),
        GeneBinding(**base("gene"),track=1,codon="SSS",handler_id="fixture-gene",handler_version="1",
            input_schema_sha256="b"*64,output_schema_sha256="b"*64,effects=("fixture-copy",),capabilities=("classification",),
            evidence_requirements=("separate-fixture-authorization",))]
    for item in items:
        registry.register(item)
    request = BrokerRequest(task="classify",messages=(BrokerMessage(role="user",content="fixture metadata"),),
        capabilities=("classification",),data_class="private",max_output_tokens=10,
        usage_bounds=(UsageBound(unit="input_tokens",quantity=100),UsageBound(unit="output_tokens",quantity=10)),
        original_request_sha256=hashlib.sha256(b"fixture metadata").hexdigest(),correlation_id="fixture-provider",
        root_run_id="fixture-root",flow_id="flow",flow_version="1",prompt_id="prompt",prompt_version="1")
    selector = RouteSelector(registry,gateway_id="native-bifrost",gateway_attempts=3,
                             now=lambda:datetime(2026,10,28,12,tzinfo=timezone.utc))
    return registry,selector,request


def test_independent_provider_selection_budget_capabilities_stale_pins_and_genes():
    from meta_pipeline.model_routing import SelectedRoute,RouteAbstention
    from meta_pipeline.provider_contracts import PromptBinding,SDKBinding,ModelBinding
    registry,selector,request = independent_provider_fixture()
    assert isinstance(selector.select(request,359),RouteAbstention)
    route = selector.select(request,360)
    assert isinstance(route,SelectedRoute) and route.reserve_nusd == 360
    assert route.gateway_id == "native-bifrost" and route.provider_id == "meta"
    assert isinstance(selector.select(request.model_copy(update={"input_modalities":("image",)}),360),RouteAbstention)
    assert isinstance(selector.select(request.model_copy(update={"data_class":"restricted"}),360),RouteAbstention)
    plan = registry.derive(request,(("gene","1"),))
    assert not plan.grants_authority and plan.independent_verification_required
    assert plan.steps[0].evidence_requirements == ("separate-fixture-authorization",)
    assert isinstance(registry.derive(request,(("unbound","1"),)),RouteAbstention)
    with pytest.raises(ValueError,match="approved"):
        registry.register(SDKBinding(id="untrusted-sdk",version="1",source_sha256="a"*64,api_shape="fixture-chat",
                                     handler_id="execute-model-code",handler_version="1",verified=True))
    prior = registry.get(PromptBinding,"prompt")
    registry.register(prior.model_copy(update={"version":"2","template":"Updated trusted fixture prompt"}))
    registry.activate(PromptBinding,"prompt","2",expected_version="1")
    assert isinstance(selector.validate(request,route,360),RouteAbstention)
    assert registry.get(PromptBinding,"prompt","1") == prior
    assert isinstance(selector.select(request,360),RouteAbstention)
    current_request=request.model_copy(update={"prompt_version":"2"})
    assert isinstance(selector.select(current_request,360),SelectedRoute)
    model=registry.get(ModelBinding,"model")
    registry.register(model.model_copy(update={"version":"2","training_opt_in_required":True}))
    registry.activate(ModelBinding,"model","2",expected_version="1")
    assert isinstance(selector.select(current_request,360),RouteAbstention)


def test_independent_provider_endpoint_escape_and_untrusted_cost_rejected():
    from datetime import datetime, timezone
    from meta_pipeline.provider_contracts import EndpointBinding,BrokerUsage,REPORTED_CREDITS
    registry,selector,request = independent_provider_fixture()
    endpoint = registry.get(EndpointBinding,"endpoint")
    for path in ("https://api.anthropic.com/messages","//other-gateway/messages","/../admin",
                 "/%2fapi.anthropic.com/messages","/%252e%252e/admin","/messages?key=secret"):
        with pytest.raises(ValueError):
            EndpointBinding.model_validate({**endpoint.model_dump(),"path":path})
    route=selector.select(request,360)
    usage=BrokerUsage(input_tokens=10,output_tokens=2,cost_nusd=0,cache_state="bifrost_direct")
    assert registry.price_usage(route,usage,now=datetime(2026,10,28,12,tzinfo=timezone.utc)) == 14
    assert registry.price_usage(route,BrokerUsage(input_tokens=10),now=datetime(2026,10,28,12,tzinfo=timezone.utc)) is None
    assert registry.price_usage(route,usage,now=datetime(2026,10,30,12,tzinfo=timezone.utc)) is None
    assert all(not credit.spend_authority and credit.status=="user_reported_unverified" for credit in REPORTED_CREDITS)


@pytest.mark.asyncio
async def test_independent_sdk_secret_broker_scope_redaction_and_no_cli(monkeypatch):
    from meta_pipeline.secret_broker import OnePasswordBroker,SecretBinding,SecretUnavailable
    secret="sk-bf-sensitive-fixture-only-value"
    class Resolver:
        def __init__(self):self.calls=[]
        async def resolve(self,reference):
            self.calls.append(reference)
            return secret
    resolver=Resolver()
    monkeypatch.setattr(subprocess,"run",lambda *args,**kwargs: (_ for _ in ()).throw(AssertionError("CLI cannot be used")))
    bindings=[SecretBinding("worker","op://private-vault/private-item/worker-key","gateway_virtual_key","native-bifrost","tenant",True),
        SecretBinding("upstream","op://private-vault/private-item/provider-key","provider_upstream","native-bifrost","tenant",True),
        SecretBinding("admin","op://private-vault/private-item/admin-key","gateway_admin","native-bifrost","tenant",True),
        SecretBinding("unverified","op://private-vault/private-item/unverified-key","gateway_virtual_key","native-bifrost","tenant",False)]
    broker=OnePasswordBroker(bindings,resolver=resolver)
    key=await broker.resolve_worker_key("worker",gateway_id="native-bifrost",tenant="tenant")
    assert key.get_secret_value()==secret and secret not in str(key) and secret not in repr(key)
    status=json.dumps(broker.status())
    assert all(value not in status for value in [secret,"private-vault","private-item","op://"])
    assert not broker.status()["cli_dependency"] and not broker.status()["interactive_authentication"]
    for id,gateway,tenant in [("upstream","native-bifrost","tenant"),("admin","native-bifrost","tenant"),
        ("unverified","native-bifrost","tenant"),("worker","different","tenant"),("worker","native-bifrost","other")]:
        with pytest.raises(SecretUnavailable,match="worker_scope_denied"):
            await broker.resolve_worker_key(id,gateway_id=gateway,tenant=tenant)
    assert len(resolver.calls)==1
    pending=OnePasswordBroker(bindings)
    with pytest.raises(SecretUnavailable,match="sdk_bootstrap_pending"):
        await pending.resolve_worker_key("worker",gateway_id="native-bifrost",tenant="tenant")
    class FailingResolver:
        async def resolve(self,reference):raise RuntimeError("upstream raw "+secret)
    rejected=OnePasswordBroker(bindings,resolver=FailingResolver())
    with pytest.raises(SecretUnavailable) as error:
        await rejected.resolve_worker_key("worker",gateway_id="native-bifrost",tenant="tenant")
    assert secret not in str(error.value) and error.value.reason=="sdk_resolution_pending"


def test_independent_sdk_bootstrap_requires_private_injected_file(tmp_path,monkeypatch):
    import os
    from meta_pipeline.secret_broker import SystemdCredentialToken,SecretUnavailable
    key=tmp_path/"service-account"
    key.write_text("ops_fixture_private_token\n")
    key.chmod(0o600)
    monkeypatch.setenv("CREDENTIALS_DIRECTORY",str(tmp_path))
    source=SystemdCredentialToken("service-account")
    assert source.available() and source.load().get_secret_value()=="ops_fixture_private_token"
    key.chmod(0o644)
    assert not source.available()
    with pytest.raises(SecretUnavailable):source.load()
    key.chmod(0o600)
    alias=tmp_path/"linked-account"
    alias.symlink_to(key)
    with pytest.raises(SecretUnavailable):SystemdCredentialToken("linked-account").load()
    monkeypatch.delenv("CREDENTIALS_DIRECTORY")
    assert not source.available()
    with pytest.raises(SecretUnavailable,match="not_injected"):source.load()


@pytest.mark.asyncio
async def test_independent_generic_gateway_revalidates_after_secret_resolution(tmp_path):
    from pydantic import SecretStr
    from meta_pipeline.generic_gateway import GenericGateway,SDKPorts
    from meta_pipeline.gateway import GatewayConfig
    from meta_pipeline.model_routing import RouteAbstention
    from meta_pipeline.provider_contracts import PromptBinding,UsageBound,BrokerResult,BrokerUsage
    registry,selector,request=independent_provider_fixture()
    request=request.model_copy(update={"usage_bounds":(UsageBound(unit="input_tokens",quantity=5000),UsageBound(unit="output_tokens",quantity=10))})
    class Adapter:
        def encode(self,request,route):return {"model":route.wire_model,"messages":[{"role":"user","content":"fixture"}]}
        def decode(self,body,headers,request,route):
            return BrokerResult(status="proposed",text="fixture",usage=BrokerUsage(input_tokens=10,output_tokens=1),
                provider_id=route.provider_id,model_id=route.model_id,request_sha256=request.digest,reason="fixture proposal only")
    secret_calls=[]
    class ReplacingBroker:
        async def resolve_worker_key(self,*args,**kwargs):
            secret_calls.append((args,kwargs))
            prompt=registry.get(PromptBinding,"prompt")
            registry.register(prompt.model_copy(update={"version":"2","template":"New authorized prompt"}))
            registry.activate(PromptBinding,"prompt","2",expected_version="1")
            return SecretStr("sk-bf-private-fixture")
    calls=[]
    def network(req):
        calls.append(req)
        return httpx.Response(200,json={"fixture":True})
    ports=SDKPorts();ports.register("fixture-sdk","1","fixture-chat",Adapter())
    ledger=Ledger(str(tmp_path/"ledger.db"),20000,20000)
    config=GatewayConfig(base_url="http://localhost:8080/openai",allowed_hosts=["localhost"],gateway_attempts=3)
    gateway=GenericGateway(config,ledger,Audit(tmp_path/"audit.db"),selector=selector,sdk_ports=ports,
        secret_broker=ReplacingBroker(),tenant="tenant",allowed_paths=("/chat/completions",),transport=httpx.MockTransport(network),enabled=True)
    try:
        result=await gateway.generate(request)
        assert isinstance(result,RouteAbstention)
        assert len(secret_calls)==1
        assert calls==[] and ledger.summary()["states"]==[]
    finally:await gateway.close()


def test_independent_plugin_inspection_never_loads_code_or_grants_authority(tmp_path,monkeypatch):
    import ctypes
    import struct
    from meta_pipeline.gateway_extensions import BuildProfile,PluginManifest,PluginInspector
    # Build inert bytes with symbol names. This is not an executable ABI witness.
    data=bytearray(392)
    data[:7]=b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HH",data,16,3,62)
    struct.pack_into("<Q",data,40,64)
    struct.pack_into("<HH",data,58,64,3)
    strings=b"\0GetName\0Cleanup\0Init\0"
    data[256:256+len(strings)]=strings
    struct.pack_into("<IIQQQQIIQQ",data,128,0,3,0,0,256,len(strings),0,0,1,0)
    struct.pack_into("<IIQQQQIIQQ",data,192,0,2,0,0,320,72,1,0,8,24)
    for n,offset in enumerate((1,9,17)):
        struct.pack_into("<IBBHQQ",data,320+n*24,offset,0x12,0,1,0,0)
    path=tmp_path/"fixture.so"
    path.write_bytes(data)
    def forbidden(*args,**kwargs):raise AssertionError("Native code loading/CLI forbidden during inspection")
    monkeypatch.setattr(ctypes,"CDLL",forbidden)
    monkeypatch.setattr(subprocess,"run",forbidden)
    profile=BuildProfile(bifrost_version="fixture-only",source_commit="2"*40,go_version="go1.24.1",
        goarch="amd64",cgo_enabled=True,race_enabled=False,shared_dependencies_sha256="3"*64)
    manifest=PluginManifest(name="fixture",version="1",artifact_sha256=hashlib.sha256(data).hexdigest(),
        source_sha256="1"*64,reviewed_source_sha256="1"*64,build=profile,hooks=("Init",))
    inspector=PluginInspector(allowed_hooks=frozenset({"Init"}),approved_source_hashes=frozenset({"1"*64}))
    result=inspector.inspect(path,manifest,runtime=profile)
    assert result.status=="ready_for_isolated_abi_probe"
    assert not result.native_code_loaded and result.production_registration=="pending"
    assert inspector.inspect(path,manifest,runtime=None).status=="pending_runtime_build_evidence"
    plan=inspector.registration_plan(path,manifest,runtime=profile)
    assert not plan["apply"] and not plan["registration_candidate"]["enabled"]
    assert not plan["provider_or_budget_changes"]
    blocked=inspector.inspect(path,manifest.model_copy(update={"permissions":("gateway-admin",)}),runtime=profile)
    assert blocked.status=="blocked" and "plugin_permissions_not_granted" in blocked.reasons
    changed=profile.model_copy(update={"go_version":"go1.25.1"})
    assert inspector.inspect(path,manifest,runtime=changed).status=="blocked"


@pytest.mark.asyncio
@pytest.mark.parametrize("mode",["direct-cache","unknown-usage","redirect"])
async def test_independent_provider_transport_origin_accounting_no_fallback(tmp_path,mode):
    from pydantic import SecretStr
    from meta_pipeline.generic_gateway import GenericGateway,SDKPorts
    from meta_pipeline.gateway import GatewayConfig
    from meta_pipeline.provider_contracts import EndpointBinding,SDKBinding,UsageBound,ChatShapeAdapter
    registry,selector,request=independent_provider_fixture()
    for kind,changes in [(EndpointBinding,{"api_shape":"chat-completions-v1","path":"/openai/chat/completions"}),
                         (SDKBinding,{"api_shape":"chat-completions-v1"})]:
        old=registry.active(kind)[0]
        registry.register(old.model_copy(update={"version":"2",**changes}))
        registry.activate(kind,old.id,"2",expected_version="1")
    request=request.model_copy(update={"usage_bounds":(UsageBound(unit="input_tokens",quantity=5000),UsageBound(unit="output_tokens",quantity=10))})
    class Secrets:
        async def resolve_worker_key(self,binding_id,*,gateway_id,tenant):
            assert (binding_id,gateway_id,tenant)==("scoped-bifrost-vk","native-bifrost","tenant")
            return SecretStr("sk-bf-only-fixture-worker-key")
    calls=[]
    def network(req):
        calls.append(req)
        assert str(req.url)=="http://localhost:8080/openai/chat/completions"
        assert req.headers["x-bf-vk"]=="sk-bf-only-fixture-worker-key"
        assert not req.headers.get("Authorization")
        if mode=="redirect":return httpx.Response(302,headers={"Location":"https://api.anthropic.com/messages"})
        body={"model":"fixture-model","choices":[{"finish_reason":"stop","message":{"content":"private-result-do-not-log"}}]}
        headers={}
        if mode=="direct-cache":
            body["usage"]={"prompt_tokens":23,"completion_tokens":2,"cost_nusd":999999999}
            headers={"x-bifrost-cache-hit":"true","x-bifrost-cache-hit-type":"direct"}
        return httpx.Response(200,json=body,headers=headers)
    ports=SDKPorts();ports.register("fixture-sdk","1","chat-completions-v1",ChatShapeAdapter())
    ledger=Ledger(str(tmp_path/"ledger.db"),20000,20000)
    audit=Audit(tmp_path/"audit.db")
    config=GatewayConfig(base_url="http://localhost:8080/openai",allowed_hosts=["localhost"],gateway_attempts=3)
    gateway=GenericGateway(config,ledger,audit,selector=selector,sdk_ports=ports,secret_broker=Secrets(),tenant="tenant",
                           transport=httpx.MockTransport(network),enabled=True)
    try:
        if mode=="redirect":
            with pytest.raises(ValueError):await gateway.generate(request)
        else:result=await gateway.generate(request)
        assert len(calls)==1
        summary=ledger.summary()["by_model"]["meta/fixture-model"]
        if mode=="direct-cache":
            assert not result.execution_verified and result.status=="proposed"
            assert result.usage.input_tokens==result.usage.output_tokens==result.usage.cost_nusd==0
            assert summary["input_tokens"]==summary["output_tokens"]==summary["known_derived_cost_nusd"]==0
            with ledger.connect() as db:detail=json.loads(db.execute("SELECT detail FROM calls").fetchone()[0])
            assert detail["replayed_usage"]["input_tokens"]==23
        elif mode=="unknown-usage":
            assert result.status=="unresolved" and result.usage.input_tokens is None
            assert summary["unknown_usage_calls"]==1 and summary["unresolved_reservation_nusd"]==15060
        else:assert summary["unresolved_reservation_nusd"]==15060
        events=json.dumps(audit.events())
        assert "sk-bf-only-fixture-worker-key" not in events and "private-result-do-not-log" not in events
    finally:await gateway.close()


def test_independent_primary_broker_cli_planning_disabled_and_hostile_configuration(tmp_path):
    from meta_pipeline.gateway import GatewayConfig
    from meta_pipeline.model_routing import KINDS
    from meta_pipeline.provider_contracts import UsageBound
    registry,selector,request=independent_provider_fixture()
    rows=[]
    for kind in KINDS.values():
        for binding in registry.active(kind):
            if kind.__name__=="GeneBinding":continue
            data=binding.model_dump(mode="json")
            if kind.__name__=="SDKBinding":
                data.update(handler_id="chat",api_shape="chat-completions-v1")
            elif kind.__name__=="FlowBinding":data["handler_id"]="genetic-activities"
            elif kind.__name__=="EndpointBinding":
                data.update(api_shape="chat-completions-v1",path="/openai/chat/completions")
            rows.append({"kind":kind.__name__,"binding":data})
    bindings=tmp_path/"bindings.json"
    bindings.write_text(json.dumps({"version":"bindings-v1","bindings":rows}))
    request_file=tmp_path/"request.json"
    request=request.model_copy(update={"usage_bounds":(UsageBound(unit="input_tokens",quantity=5000),UsageBound(unit="output_tokens",quantity=10))})
    request_file.write_text(request.model_dump_json())
    config=tmp_path/"gateway.json"
    config.write_text(GatewayConfig(base_url="http://localhost:8080/openai",allowed_hosts=["localhost"],gateway_attempts=3).model_dump_json())
    broker_config=tmp_path/"broker.json"
    broker_config.write_text(json.dumps({"enabled":False,"gateway_id":"native-bifrost","tenant":"fixture"}))
    cli=str(Path(__file__).parents[1]/".venv/bin/meta-pipeline")
    plan=subprocess.run([cli,"--config",str(config),"broker-plan",str(bindings),str(request_file),
                         "--gateway-id","native-bifrost","--remaining-nusd","20000"],capture_output=True,text=True,check=True)
    result=json.loads(plan.stdout)
    assert result["model_id"]=="fixture-model" and result["provider_id"]=="meta" and not result["spend_admission"]
    run_args=[cli,"--config",str(config),"--ledger",str(tmp_path/"ledger.db"),"broker-run",str(bindings),str(request_file),
              "--broker-config",str(broker_config),"--audit",str(tmp_path/"audit.db")]
    disabled=subprocess.run(run_args,capture_output=True,text=True,check=True)
    assert json.loads(disabled.stdout)["status"]=="abstained"
    assert not (tmp_path/"ledger.db").exists()
    broker_config.write_text('{"enabled":false,"enabled":true,"gateway_id":"native-bifrost","tenant":"fixture"}')
    duplicate=subprocess.run(run_args,capture_output=True,text=True)
    assert duplicate.returncode==1 and json.loads(duplicate.stderr)["error_type"]=="ValueError"
    assert not (tmp_path/"ledger.db").exists()


def test_independent_release_signature_rejects_changed_source_and_hooks():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    from meta_pipeline.release_manager import ReleaseManifest,WheelArtifact,sign_manifest,verify_envelope,UpdateBlocked
    # Ephemeral fixture trust only: no production signing key or trust file changes.
    private=Ed25519PrivateKey.generate()
    pem=private.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())
    public=private.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo)
    manifest=ReleaseManifest(version="0.3.1",expected_incumbent_sha256="a"*64,
        wheel=WheelArtifact(filename="diatonic_meta_pipeline-0.3.1-py3-none-any.whl",sha256="b"*64,size_bytes=100),dependencies=())
    signed=sign_manifest(manifest,pem)
    assert verify_envelope(signed,public)==manifest
    wrong=Ed25519PrivateKey.generate().public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo)
    with pytest.raises(UpdateBlocked):verify_envelope(signed,wrong)
    tampered=json.loads(signed)
    tampered["manifest"]["wheel"]["sha256"]="c"*64
    with pytest.raises(UpdateBlocked):verify_envelope(json.dumps(tampered).encode(),public)
    tampered=json.loads(signed)
    tampered["manifest"]["post_install"]="run arbitrary model-supplied shell"
    with pytest.raises(UpdateBlocked):verify_envelope(json.dumps(tampered).encode(),public)
    with pytest.raises(UpdateBlocked):
        verify_envelope(b'{"manifest":{},"manifest":{},"signature":"x"}',public)


def test_independent_release_wheel_rejects_normalized_duplicates_and_escape(tmp_path):
    import zipfile
    from meta_pipeline.release_manager import _validate_wheel,UpdateBlocked
    for name,members in [("duplicates.whl",("package//module.py","package/module.py")),
                         ("escape.whl",("package/../outside.py",))]:
        path=tmp_path/name
        with zipfile.ZipFile(path,"w") as archive:
            for member in members:archive.writestr(member,"inert fixture text")
        with pytest.raises(UpdateBlocked):_validate_wheel(path)


def test_independent_maintenance_reserve_fifo_and_unknown_replacement_preserved(tmp_path,monkeypatch):
    import os
    from meta_pipeline.maintenance import maintain,validate_policy,_read_json
    with pytest.raises(ValueError):validate_policy({"version":"maintenance-v1","minimum_free_bytes":0})
    fifo=tmp_path/"not-a-policy"
    os.mkfifo(fifo)
    with pytest.raises(ValueError):_read_json(fifo)
    root=tmp_path/"runtime";root.mkdir(mode=0o700)
    scratch=root/"scratch";scratch.mkdir(mode=0o700)
    path=scratch/"completed.bin"
    approved=b"completed old fixture"
    unknown=b"new unapproved concurrent fixture"
    path.write_bytes(approved)
    policy={"version":"maintenance-v1","retention_seconds":0,"completed_files":[{
        "path":"scratch/completed.bin","sha256":hashlib.sha256(approved).hexdigest(),"bytes":len(approved),
        "completed_at":1.0,"state":"verified_complete","verification_ref":"fixture:independent-content-verifier"}]}
    real_rename=os.rename
    replaced=[]
    def concurrent_replace(source,destination,*args,**kwargs):
        if source=="completed.bin" and destination=="candidate" and not replaced:
            path.unlink();path.write_bytes(unknown);replaced.append(True)
        return real_rename(source,destination,*args,**kwargs)
    monkeypatch.setattr(os,"rename",concurrent_replace)
    result=maintain(root,policy,apply=True,now=100000.0)
    assert replaced and result["deleted_files"]==result["reclaimed_bytes"]==0
    assert result["status"]=="completed_with_pending"
    row=result["results"][0]
    assert row["status"]=="unresolved_quarantine"
    assert (root/row["quarantine_path"]).read_bytes()==unknown


@pytest.mark.asyncio
async def test_independent_credential_enrollment_once_unknown_and_no_worker_grant(tmp_path):
    from types import SimpleNamespace
    from pydantic import SecretStr
    from meta_pipeline.credential_enrollment import OneTimeCredentialEnrollment,EnrollmentPending
    from meta_pipeline.secret_broker import OnePasswordBroker,SecretBinding,SecretUnavailable
    class Items:
        def __init__(self):self.creates=0;self.gets=0
        async def create(self,params):
            self.creates+=1
            self.item=SimpleNamespace(id="fixture-native-item",vault_id=params.vault_id,category=params.category,fields=params.fields)
            return self.item
        async def get(self,vault,id):self.gets+=1;return self.item
    items=Items()
    audit=Audit(tmp_path/"audit.db")
    helper=OneTimeCredentialEnrollment(SimpleNamespace(items=items),audit,authorized_vault_id="explicit-vault",authorized_actor="operator")
    key=SecretStr("HOSTINGER_FIXTURE_PRIVATE_VALUE")
    args=dict(actor="operator",vault_id="explicit-vault",request_id="one-time-fixture")
    with pytest.raises(EnrollmentPending):await helper.enroll(key,**{**args,"actor":"worker"})
    assert items.creates==items.gets==0
    result=await helper.enroll(key,**args)
    assert result.status=="enrolled_and_independently_verified"
    with pytest.raises(EnrollmentPending):await helper.enroll(SecretStr("CHANGED_FIXTURE_VALUE"),**args)
    assert items.creates==1 and items.gets==2
    broker=OnePasswordBroker([SecretBinding("hostinger",result.reference.get_secret_value(),"provider_upstream","native-bifrost","tenant",True)])
    with pytest.raises(SecretUnavailable,match="worker_scope_denied"):
        await broker.resolve_worker_key("hostinger",gateway_id="native-bifrost",tenant="tenant")
    with audit.connect() as db:stored="\n".join(db.iterdump())
    assert "HOSTINGER_FIXTURE_PRIVATE_VALUE" not in stored and "CHANGED_FIXTURE_VALUE" not in stored
    assert "explicit-vault" not in json.dumps(audit.events())


def test_independent_credential_pipe_never_accepts_partial_frame():
    import os
    from meta_pipeline.credential_enrollment import read_private_pipe,EnrollmentPending
    reader,writer=os.pipe()
    try:
        os.write(writer,b"incomplete-private-prefix")
        with pytest.raises(EnrollmentPending,match="incomplete"):
            read_private_pipe(reader,trusted_uid=os.geteuid())
    finally:os.close(reader);os.close(writer)
    reader,writer=os.pipe()
    try:
        os.write(writer,b"complete-private-fixture")
        os.close(writer);writer=None
        assert read_private_pipe(reader,trusted_uid=os.geteuid()).get_secret_value()=="complete-private-fixture"
    finally:
        os.close(reader)
        if writer is not None:os.close(writer)


def test_independent_host_plan_unknown_reservations_and_native_label_cannot_bypass_gate():
    from datetime import datetime,timezone
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from meta_pipeline.host_packaging import (HostMeasurement,TrustedHostKey,sign_measurement,PackageArtifact,
        PackageCandidate,ArtifactCatalog,PackageRequest,HostPackagingPolicy,derive_package_plan)
    measurement=HostMeasurement(host_id="fixture-metal01",observer_id="fixture-observer",boot_id="fixture-boot",
        source_version="fixture-v1",source_sha256="a"*64,observed_at="2026-10-28T13:00:00+00:00",
        os_id="almalinux",os_version="10.2",architecture="x86_64",glibc_version="2.39",python_version="3.12.15",python_abi="cp312",
        cpu_affinity=(0,2),cpu_quota_cores=2.0,memory_available_bytes=12*1024**3,controller_memory_current_bytes=1024**3,
        controller_memory_high_bytes=8*1024**3,controller_memory_max_bytes=10*1024**3,
        resource_controller="/sys/fs/cgroup/aux.slice/aux-batch.slice",ssd_device_id="8:3",ssd_free_bytes=100*1024**3,
        hdd_device_id="8:17",hdd_free_bytes=150*1024**3,evidence_refs=("fixture:host",))
    private=Ed25519PrivateKey.generate()
    pem=private.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())
    trust=TrustedHostKey(host_id="fixture-metal01",key_id="fixture-key",
        public_key_pem=private.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo))
    py=PackageArtifact(id="python",sha256="b"*64,bytes=90000,version="1",kind="python",source_sha256="a"*64,evidence_ref="fixture:python")
    rust=PackageArtifact(id="native",sha256="c"*64,bytes=5000,version="1",kind="rust_cell",architecture="x86_64",
        source_sha256="a"*64,evidence_ref="fixture:native-unbenchmarked",cell_nonblank_lines=39,cell_public_ops=1,
        cell_direct_dependencies=0,stripped_library_bytes=5000)
    def variant(id,artifact):
        # Mislabel the native-containing variant as Python to test the other gate.
        return PackageCandidate(id=id,artifact_ids=(artifact,),capabilities=("classify",),independent_verifier_id="fixture-verifier",
            implementation="python",baseline_case_ids=("development","heldout"),expected_cpu_seconds=0.2,
            expected_peak_memory_bytes=10*1024**2,install_expansion_bytes=100000,forecast_evidence_refs=("fixture:forecast",))
    catalog=ArtifactCatalog(version="fixture-v1",source_sha256="a"*64,artifacts=(py,rust),
                            candidates=(variant("baseline","python"),variant("small-native","native")))
    request=PackageRequest(host_id="fixture-metal01",workload_sha256="d"*64,required_capabilities=("classify",),
        required_verifier_id="fixture-verifier",required_case_ids=("development","heldout"),max_payload_bytes=1000000,schedule_window_seconds=1.0)
    policy=HostPackagingPolicy()
    now=datetime(2026,10,28,13,0,1,tzinfo=timezone.utc)
    def derive(observed):
        return derive_package_plan(sign_measurement(observed,pem,"fixture-key"),catalog,request,policy,trusted_keys=(trust,),now=now,
                                   trusted_catalog_digests=(catalog.digest,))
    unpinned=derive_package_plan(sign_measurement(measurement.model_copy(update={"shared_reservations_verified":True}),pem,"fixture-key"),
        catalog,request,policy,trusted_keys=(trust,),now=now)
    assert unpinned.status=="blocked" and "artifact_catalog_not_pinned_by_coordinator" in unpinned.reasons
    unknown=derive(measurement)
    assert unknown.status=="blocked" and "shared_reservations_unknown" in unknown.reasons
    plan=derive(measurement.model_copy(update={"shared_reservations_verified":True}))
    assert plan.status=="reviewable" and plan.selected_candidate_id=="baseline"
    assert not plan.grants_install_authority and not plan.native_resource_policy_changed
    rejected=next(row for row in plan.candidates if row.id=="small-native")
    assert rejected.status=="rejected"
    assert "native_requires_exact_host_independent_same_coverage_heldout_improvement" in rejected.reasons
    stale=measurement.model_copy(update={"shared_reservations_verified":True,"observed_at":"2026-10-28T11:00:00+00:00"})
    assert derive(stale).status=="blocked"


def test_independent_confirmed_correction_does_not_migrate_to_reused_path(tmp_path):
    root=tmp_path/"estate";root.mkdir()
    original=root/"record.txt"
    original.write_text("original financial fixture")
    projection=EstateProjection(tmp_path/"projection.db")
    projection.register(SourceSpec(source_id="fixture",root=str(root),volume_id="fixture-local",reliable_file_ids=True))
    projection.scan("fixture")
    projection.correct("fixture","record.txt",["financial"])
    assert projection.query(label="financial")["results"][0]["path"]=="record.txt"
    original.rename(root/"retained-original.txt")
    original.write_text("unrelated creative fixture")
    projection.reconcile("fixture")
    projection.scan("fixture")
    new=projection.query(name="record.txt")["results"][0]
    assert "financial" not in new.get("user_labels",[])
