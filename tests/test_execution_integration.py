import asyncio
from dataclasses import replace
import json

import pytest
from pydantic import BaseModel, ConfigDict
from temporalio.exceptions import ApplicationError

from meta_pipeline.audit import Audit
from meta_pipeline.execution import (ContractBinding, ContractRegistry, FixturePolicy,
                                     LocalFixtureBackend, Verification)
from meta_pipeline.scheduling import (Activities, Plan, Stage, StageRequest, StageFailure,
                                     definition_digest, execution_key)


class Number(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    value: int


def request(*, stage_id="verify", event="event", reserve=0, root="run", kind="proof_review", budget=100):
    stage = Stage(stage_id, kind, reserve_nusd=reserve)
    plan = Plan(root, "artifact:"+"a"*64, definition_digest([stage]), "artifact:"+"b"*64,
                event, [stage], budget)
    return StageRequest(plan, stage, execution_key(plan, stage), {}, None, "verifier")


def setup(tmp_path, *, handler=None, verifier=None, timeout=1, exclusion=None, requires=(), budget=100):
    calls = []
    def effect(data):
        calls.append(data.value)
        return Number(value=data.value + 1)
    def verify(data, output):
        return Verification(verified=output.value == data.value + 1,
                            evidence_refs=["fixture:number"], reason="Independent arithmetic fixture")
    binding = ContractBinding("increment", "proof_review", "1", Number, Number,
                              handler or effect, verifier or verify,
                              lambda original, data: original == str(data.value),
                              requirements=requires, exclusion=exclusion, timeout_seconds=timeout)
    registry = ContractRegistry(); registry.register(binding)
    audit = Audit(tmp_path / "audit.db")
    policy = FixturePolicy("run", "artifact:"+"a"*64, frozenset({"increment"}), budget)
    backend = LocalFixtureBackend(audit, registry, [policy])
    return backend, calls


def derive(backend, req, value=1):
    return backend.derive(req, task="increment", original_request=str(value), inputs={"value": value}, correlation_id="correlation", causal_parents=("parent",))


@pytest.mark.asyncio
async def test_actual_activity_backend_verified_duplicate_and_monitor_audit(tmp_path):
    backend, calls = setup(tmp_path)
    req = request(); derive(backend, req)
    result = await Activities(backend).control(req)
    assert result.proven
    assert await Activities(backend).control(req) == result
    assert calls == [1]
    assert backend.records()[0]["state"] == "completed"
    events = backend.audit.events()
    assert {r["kind"] for r in events} >= {"task.derived", "task.admitted", "task.completed"}
    completed = next(r for r in events if r["kind"] == "task.completed")
    assert completed["detail"]["correlation_id"] == "correlation"
    assert completed["detail"]["causal_parents"] == ["parent"]
    assert backend.audit.verify()["valid"]


def test_registry_rejects_ambiguity_bad_schema_and_mistranslation(tmp_path):
    backend, _ = setup(tmp_path)
    req = request()
    with pytest.raises(ValueError, match="unbound_handler"):
        backend.registry.binding("shell")
    with pytest.raises(ValueError, match="Ambiguous"):
        backend.registry.register(backend.registry.binding("increment"))
    with pytest.raises(ValueError):
        backend.derive(req, task="increment", original_request="1", inputs={"value": "1"}, correlation_id="c")
    with pytest.raises(ValueError, match="fidelity"):
        backend.derive(req, task="increment", original_request="different request", inputs={"value": 1}, correlation_id="c")
    derive(backend, req)
    with pytest.raises(ValueError, match="Immutable"):
        derive(backend, req, 2)


@pytest.mark.asyncio
async def test_policy_and_budget_preserve_holds(tmp_path):
    backend, calls = setup(tmp_path, budget=100)
    req = request(reserve=70); derive(backend, req)
    await Activities(backend).control(req)
    req2 = request(event="next", reserve=40); derive(backend, req2)
    with pytest.raises(ApplicationError) as error:
        await Activities(backend).control(req2)
    assert error.value.type == "BudgetDenied"
    assert calls == [1]
    assert sum(r["reserved_nusd"] for r in backend.records()) == 70
    # New backend on restart cannot erase incurred reservation.
    again = LocalFixtureBackend(backend.audit, backend.registry, list(backend.policies.values()))
    with pytest.raises(StageFailure) as denied:
        await again.claim(req2)
    assert denied.value.kind == "BudgetDenied"


@pytest.mark.asyncio
async def test_missing_requirements_block_before_effect(tmp_path):
    backend, calls = setup(tmp_path, requires=("native_permission",))
    req = request(); derive(backend, req)
    with pytest.raises(ApplicationError) as error:
        await Activities(backend).control(req)
    assert error.value.type == "PolicyDenied"
    assert calls == [] and backend.records() == []


@pytest.mark.asyncio
async def test_crash_unknown_effect_never_replays_and_exclusion_retained(tmp_path):
    backend, calls = setup(tmp_path, exclusion="device")
    req = request(reserve=20); derive(backend, req)
    admission = await backend.claim(req)
    # Simulates process lost after durable admission, before any known output.
    again = LocalFixtureBackend(backend.audit, backend.registry, list(backend.policies.values()))
    with pytest.raises(StageFailure) as error:
        await again.claim(req)
    assert error.value.kind == "UnknownEffect"
    assert (await again.reconcile(req))["state"] == "unresolved"
    other = request(event="other"); derive(again, other)
    with pytest.raises(StageFailure) as blocked:
        await again.claim(other)
    assert blocked.value.kind == "PolicyDenied"
    assert calls == []
    assert backend.records()[0]["reserved_nusd"] == 20


@pytest.mark.asyncio
async def test_crash_after_durable_output_independently_reconciles(tmp_path):
    backend, calls = setup(tmp_path)
    req = request(); derive(backend, req)
    admission = await backend.claim(req)
    result = await backend.perform(req, admission)
    # No complete receipt before restart. Reconciliation invokes verifier only.
    again = LocalFixtureBackend(backend.audit, backend.registry, list(backend.policies.values()))
    assert (await again.reconcile(req))["state"] == "completed"
    replay = await Activities(again).control(req)
    assert replay.proven and calls == [1]
    assert result.artifact_ref == replay.artifact_ref


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["timeout", "cancel", "disconnect"])
async def test_uncertain_effects_preserved(tmp_path, mode):
    entered = asyncio.Event()
    async def effect(data):
        entered.set()
        if mode == "disconnect":
            raise OSError("sensitive host body")
        await asyncio.sleep(20)
    backend, _ = setup(tmp_path, handler=effect, timeout=0.01 if mode == "timeout" else 1)
    req = request(reserve=50); derive(backend, req)
    running = asyncio.create_task(Activities(backend).control(req))
    await entered.wait()
    if mode == "cancel":
        running.cancel()
        with pytest.raises(asyncio.CancelledError):
            await running
    else:
        with pytest.raises(ApplicationError) as error:
            await running
        assert error.value.type == "UnknownEffect"
        assert "sensitive" not in str(error.value)
    row = backend.records()[0]
    assert row["state"] == "unresolved" and row["reserved_nusd"] == 50
    with pytest.raises(ApplicationError) as retry:
        await Activities(backend).control(req)
    assert retry.value.type == "UnknownEffect"


@pytest.mark.asyncio
async def test_failed_independent_verification_is_never_success(tmp_path):
    backend, _ = setup(tmp_path, verifier=lambda *args: Verification(verified=False, evidence_refs=["fixture:failed"], reason="Wrong effect"))
    req = request(); derive(backend, req)
    result = await Activities(backend).control(req)
    assert not result.proven
    assert backend.records()[0]["state"] == "failed_verification"
    with pytest.raises(ApplicationError):
        await Activities(backend).control(req)


@pytest.mark.asyncio
async def test_stale_binding_rejected_and_role_isolation(tmp_path):
    backend, calls = setup(tmp_path)
    req = request(); derive(backend, req)
    with pytest.raises(ApplicationError):
        await Activities(backend).control(replace(req, role="native-operator"))
    binding = backend.registry.binding("increment")
    backend.registry.tasks["increment"] = replace(binding, handler_version="2")
    with pytest.raises(ApplicationError) as error:
        await Activities(backend).control(req)
    assert error.value.type == "SchemaFailure" and calls == []


def test_no_sensitive_input_in_ordinary_events(tmp_path):
    class PrivateInput(BaseModel):
        text: str
    backend, _ = setup(tmp_path)
    binding = replace(backend.registry.binding("increment"), input_model=PrivateInput,
                      fidelity=lambda *args: True)
    backend.registry.tasks["increment"] = binding
    req = request()
    backend.derive(req, task="increment", original_request="private request", inputs={"text": "PRIVATE_CONTENT_SENTINEL"}, correlation_id="correlation")
    assert "PRIVATE_CONTENT_SENTINEL" not in json.dumps(backend.audit.events())
    assert "private request" not in json.dumps(backend.audit.events())


@pytest.mark.asyncio
async def test_dependencies_require_exact_completed_proven_producer(tmp_path):
    backend, _ = setup(tmp_path)
    first = Stage("first", "proof_review")
    second = Stage("second", "proof_review", depends_on=["first"])
    plan = Plan("run", "artifact:"+"a"*64, definition_digest([first, second]),
                "artifact:"+"b"*64, "event", [first, second], 100)
    producer = StageRequest(plan, first, execution_key(plan, first), {}, None, "verifier")
    consumer = StageRequest(plan, second, execution_key(plan, second),
                            {"first": "artifact:"+"c"*64}, None, "verifier")
    derive(backend, producer); derive(backend, consumer)
    with pytest.raises(StageFailure) as missing:
        await backend.claim(consumer)
    assert missing.value.kind == "PolicyDenied"
    evidence = await Activities(backend).control(producer)
    with pytest.raises(StageFailure):
        await backend.claim(consumer)
    valid = replace(consumer, dependency_refs={"first": evidence.artifact_ref})
    assert (await Activities(backend).control(valid)).proven


def test_root_policy_cannot_expand_on_restart(tmp_path):
    backend, _ = setup(tmp_path)
    with pytest.raises(ValueError, match="immutable"):
        LocalFixtureBackend(backend.audit, backend.registry, [FixturePolicy("run", "artifact:"+"a"*64,
                            frozenset({"increment", "shell"}), 1000)])


@pytest.mark.asyncio
async def test_synchronous_handler_exceeding_deadline_never_reports_success(tmp_path):
    import time
    def slow_effect(data):
        time.sleep(0.02)
        return Number(value=data.value + 1)
    backend, _ = setup(tmp_path, handler=slow_effect, timeout=0.001)
    req = request(); derive(backend, req)
    with pytest.raises(ApplicationError) as error:
        await Activities(backend).control(req)
    assert error.value.type == "UnknownEffect"
    assert backend.records()[0]["state"] == "unresolved"
