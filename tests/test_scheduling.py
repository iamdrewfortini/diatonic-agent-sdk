"""Real Temporal local test-server proofs with synthetic backends, no Meta/estate I/O."""
import asyncio
from dataclasses import replace
from datetime import timedelta
import hashlib
import importlib.metadata

import pytest
import pytest_asyncio
from temporalio.client import Client, ScheduleOverlapPolicy, WorkflowFailureError
from temporalio.exceptions import ApplicationError
from temporalio.testing import ActivityEnvironment, WorkflowEnvironment
from temporalio.worker import Worker, Replayer

from meta_pipeline.scheduling import (
    Activities, Admission, AI_QUEUE, BatchWorkflow, CONTROL_QUEUE, EventDispatcher,
    EventPlan, HDD_LEASE, HDD_QUEUE, NO_RETRY, Plan, ScheduledTickWorkflow,
    ServerReadiness, Stage, StageFailure, StageRequest, StageResult, Trigger,
    definition_digest, deployment_plan, execution_key, paused_schedule,
    validate_plan, worker_options,
)

REF = "artifact:" + "a" * 64
POLICY = "artifact:" + "b" * 64


def plan(stages=None):
    stages = stages or [Stage("read", "catalog_read"), Stage("verify", "proof_review", ["read"])]
    return Plan("root_test", POLICY, definition_digest(stages), REF, "event_1", stages, 10000000)


def request(p, stage):
    mapping = {"classification": ("muse-spark-1.3", "classifier"), "planning": ("muse-wonder-1.0", "planner"),
               "catalog_read": (None, "observer"), "proof_review": (None, "verifier"),
               "staging_validation": (None, "file-verifier")}
    model, role = mapping[stage.kind]
    return StageRequest(p, stage, execution_key(p, stage), {d: REF for d in stage.depends_on},
                        model, role, HDD_LEASE if stage.kind == "staging_validation" else None)


class SyntheticBackend:
    """Test double only. This is not a globally durable admission service."""
    def __init__(self, *, failure=None, unproven=False, delay=0):
        self.calls = []
        self.failures = []
        self.completed = {}
        self.active = 0
        self.peak = 0
        self.failure = failure
        self.unproven = unproven
        self.delay = delay
        self.roots = set()

    async def claim(self, req):
        self.roots.add((req.plan.root_run, req.plan.root_budget_nusd, req.plan.policy_ref))
        return Admission("synthetic-private-receipt", self.completed.get(req.key))

    async def perform(self, req, admission):
        self.calls.append(req)
        self.active += 1
        self.peak = max(self.peak, self.active)
        try:
            if self.delay:
                await asyncio.sleep(self.delay)
            if self.failure:
                raise StageFailure(self.failure)
            return StageResult(req.key, "artifact:" + hashlib.sha256(req.key.encode()).hexdigest(),
                               not self.unproven, measured_input_bytes=32, measured_output_bytes=10)
        finally:
            self.active -= 1

    async def complete(self, req, admission, result):
        self.completed[req.key] = result

    async def failed(self, req, admission, kind):
        self.failures.append(kind)


@pytest_asyncio.fixture
async def temporal_env():
    try:
        env = await asyncio.wait_for(WorkflowEnvironment.start_time_skipping(), timeout=30)
    except Exception as exc:
        pytest.skip("Official Temporal local test server unavailable: " + type(exc).__name__)
    try:
        yield env
    finally:
        await env.shutdown()


def test_plan_binding_and_fixed_policy():
    p = plan()
    validate_plan(p)
    assert execution_key(p, p.stages[0]) == execution_key(p, p.stages[0])
    assert execution_key(replace(p, event_id="event_2"), p.stages[0]) != execution_key(p, p.stages[0])
    with pytest.raises(ApplicationError):
        validate_plan(replace(p, stages=[Stage("shell", "bash")]))
    with pytest.raises(ApplicationError):
        validate_plan(replace(p, evidence_ref="/srv/nas/global_sort"))
    with pytest.raises(ApplicationError):
        validate_plan(replace(p, root_budget_nusd=0))
    paid = [Stage("classify", "classification", reserve_nusd=20000000)]
    with pytest.raises(ApplicationError):
        validate_plan(replace(p, stages=paid, version=definition_digest(paid)))


def test_rejects_cycles_and_budget_free_paid_stages():
    p = plan()
    for stages in ([Stage("a", "catalog_read", ["b"]), Stage("b", "catalog_read", ["a"])],
                   [Stage("model", "classification")]):
        with pytest.raises(ApplicationError):
            validate_plan(replace(p, stages=stages, version=definition_digest(stages)))


def test_configuration_is_inert_and_namespaced():
    with pytest.raises(ValueError):
        ServerReadiness().require()
    flags = dict(address="candidate:7233", authenticated=True, namespace_provisioned=True,
                 capacity_reviewed=True, shared_admission_backend_verified=True,
                 worker_roles_verified=True, history_privacy_reviewed=True, readiness_evidence_ref=REF)
    ServerReadiness(**flags).require()
    with pytest.raises(ValueError):
        ServerReadiness(namespace="postiz", **flags).require()
    assert worker_options("hdd")["max_concurrent_activities"] == 1
    state = deployment_plan()
    assert state["active"] is False and state["new_server"] is False
    assert state["postiz_namespace_reused"] is False


def test_paused_native_schedule_has_no_auto_backfill_or_overlap():
    schedule = paused_schedule(plan())
    assert schedule.state.paused
    assert schedule.policy.overlap == ScheduleOverlapPolicy.SKIP
    assert schedule.policy.pause_on_failure
    assert schedule.policy.catchup_window == timedelta(minutes=5)
    assert schedule.action.retry_policy.maximum_attempts == 1
    with pytest.raises(ValueError):
        paused_schedule(plan(), every_seconds=1)


@pytest.mark.asyncio
async def test_activity_measurements_and_idempotent_completion():
    backend = SyntheticBackend()
    activities = Activities(backend)
    p = plan()
    req = request(p, p.stages[0])
    env = ActivityEnvironment()
    first = await env.run(activities.control, req)
    second = await env.run(activities.control, req)
    assert first == second
    assert first.measured_input_bytes == 32 and first.measured_output_bytes == 10
    assert first.elapsed_ms >= 0 and first.measured_read_bytes is None
    assert first.measured_energy_joules is None
    assert len(backend.calls) == 1
    assert backend.roots == {(p.root_run, p.root_budget_nusd, p.policy_ref)}


@pytest.mark.asyncio
async def test_paid_failure_is_nonretryable_and_recorded():
    backend = SyntheticBackend(failure="UnknownEffect")
    stages = [Stage("model", "classification", reserve_nusd=1000)]
    p = plan(stages)
    with pytest.raises(ApplicationError) as info:
        await ActivityEnvironment().run(Activities(backend).ai, request(p, stages[0]))
    assert info.value.non_retryable and info.value.type == "UnknownEffect"
    assert backend.failures == ["UnknownEffect"]


@pytest.mark.asyncio
async def test_activity_cannot_change_model_role_queue_or_disk_ownership():
    backend = SyntheticBackend()
    activities = Activities(backend)
    stages = [Stage("model", "classification", reserve_nusd=1000)]
    p = plan(stages)
    req = request(p, stages[0])
    for change in ({"model": "muse-wonder-1.0"}, {"role": "administrator"}, {"disk_lease": HDD_LEASE}):
        with pytest.raises(ApplicationError):
            await ActivityEnvironment().run(activities.ai, replace(req, **change))
    with pytest.raises(ApplicationError):
        await ActivityEnvironment().run(activities.control, req)
    assert not backend.calls


@pytest.mark.asyncio
async def test_native_workflow_dag_completes_and_replays(temporal_env):
    backend = SyntheticBackend()
    a = Activities(backend)
    async with Worker(temporal_env.client, task_queue=CONTROL_QUEUE,
                      workflows=[BatchWorkflow], activities=[a.control],
                      max_concurrent_activities=2):
        handle = await temporal_env.client.start_workflow(BatchWorkflow.run, plan(),
                    id="synthetic-batch", task_queue=CONTROL_QUEUE, retry_policy=NO_RETRY)
        result = await handle.result()
        history = await handle.fetch_history()
    assert result.status == "verified_in_declared_scope"
    assert list(result.completed) == ["read", "verify"]
    assert backend.calls[1].dependency_refs["read"] == result.completed["read"].artifact_ref
    await Replayer(workflows=[BatchWorkflow]).replay_workflow(history)
    # Temporal history stores immutable refs and measured results, no provider key.
    assert all(c.plan.root_run == "root_test" for c in backend.calls)


@pytest.mark.asyncio
async def test_native_signals_are_deduplicated_before_child_workflows(temporal_env):
    backend = SyntheticBackend()
    a = Activities(backend)
    async with Worker(temporal_env.client, task_queue=CONTROL_QUEUE,
                      workflows=[BatchWorkflow, EventDispatcher], activities=[a.control]):
        handle = await temporal_env.client.start_workflow(EventDispatcher.run,
                    EventPlan(plan(), maximum_events=1), id="synthetic-events",
                    task_queue=CONTROL_QUEUE, retry_policy=NO_RETRY)
        await handle.signal("trigger", Trigger("source_changed", REF))
        await handle.signal("trigger", Trigger("source_changed", REF))
        await handle.signal("stop")
        result = await handle.result()
    assert result["processed"] == 1 and result["duplicates"] == 1
    assert len(backend.calls) == 2  # exactly one two-stage batch
    assert all(c.plan.event_id == "source_changed" for c in backend.calls)


@pytest.mark.asyncio
async def test_paid_activity_is_not_silently_retried_by_temporal(temporal_env):
    backend = SyntheticBackend(failure="AuthenticationFailure")
    a = Activities(backend)
    p = plan([Stage("model", "classification", reserve_nusd=1000)])
    async with Worker(temporal_env.client, task_queue=CONTROL_QUEUE, workflows=[BatchWorkflow]), \
               Worker(temporal_env.client, task_queue=AI_QUEUE, activities=[a.ai]):
        with pytest.raises(WorkflowFailureError):
            await temporal_env.client.execute_workflow(BatchWorkflow.run, p,
                        id="synthetic-no-paid-retry", task_queue=CONTROL_QUEUE, retry_policy=NO_RETRY)
    assert len(backend.calls) == 1 and backend.failures == ["AuthenticationFailure"]


@pytest.mark.asyncio
async def test_missing_evidence_never_marks_workflow_complete(temporal_env):
    backend = SyntheticBackend(unproven=True)
    a = Activities(backend)
    async with Worker(temporal_env.client, task_queue=CONTROL_QUEUE,
                      workflows=[BatchWorkflow], activities=[a.control]):
        result = await temporal_env.client.execute_workflow(BatchWorkflow.run, plan(),
                    id="synthetic-unproven", task_queue=CONTROL_QUEUE, retry_policy=NO_RETRY)
    assert result.status == "needs_evidence"
    assert len(backend.calls) == 1


@pytest.mark.asyncio
async def test_metal01_disk_worker_concurrency_is_one(temporal_env):
    backend = SyntheticBackend(delay=0.02)
    a = Activities(backend)
    p = plan([Stage("disk_a", "staging_validation"), Stage("disk_b", "staging_validation")])
    async with Worker(temporal_env.client, task_queue=CONTROL_QUEUE, workflows=[BatchWorkflow]), \
               Worker(temporal_env.client, task_queue=HDD_QUEUE, activities=[a.hdd], max_concurrent_activities=1):
        result = await temporal_env.client.execute_workflow(BatchWorkflow.run, p,
                    id="synthetic-disk-serialization", task_queue=CONTROL_QUEUE, retry_policy=NO_RETRY)
    assert result.status == "verified_in_declared_scope" and backend.peak == 1
    assert all(c.disk_lease == HDD_LEASE for c in backend.calls)


@pytest.mark.asyncio
async def test_scheduled_ticks_have_distinct_event_keys_under_one_root_budget(temporal_env):
    backend = SyntheticBackend()
    a = Activities(backend)
    async with Worker(temporal_env.client, task_queue=CONTROL_QUEUE,
                      workflows=[BatchWorkflow, ScheduledTickWorkflow], activities=[a.control]):
        one = await temporal_env.client.execute_workflow(ScheduledTickWorkflow.run, plan(),
                    id="synthetic-tick-1", task_queue=CONTROL_QUEUE, retry_policy=NO_RETRY)
        two = await temporal_env.client.execute_workflow(ScheduledTickWorkflow.run, plan(),
                    id="synthetic-tick-2", task_queue=CONTROL_QUEUE, retry_policy=NO_RETRY)
    assert one.event_id != two.event_id
    assert len(backend.calls) == 4
    assert len(backend.roots) == 1


@pytest.mark.asyncio
async def test_only_explicitly_safe_reads_receive_bounded_native_retries(temporal_env):
    backend = SyntheticBackend(failure="TransientReadFailure")
    a = Activities(backend)
    async with Worker(temporal_env.client, task_queue=CONTROL_QUEUE,
                      workflows=[BatchWorkflow], activities=[a.control]):
        with pytest.raises(WorkflowFailureError):
            await temporal_env.client.execute_workflow(BatchWorkflow.run, plan(),
                    id="synthetic-read-retries", task_queue=CONTROL_QUEUE, retry_policy=NO_RETRY)
    assert len(backend.calls) == 3
    assert backend.failures == ["TransientReadFailure"] * 3


@pytest.mark.asyncio
async def test_unclassified_backend_application_error_is_not_retried():
    class Ambiguous(SyntheticBackend):
        async def perform(self, req, admission):
            raise ApplicationError("raw provider body must remain protected")
    backend = Ambiguous()
    p = plan()
    with pytest.raises(ApplicationError) as info:
        await ActivityEnvironment().run(Activities(backend).control, request(p, p.stages[0]))
    assert info.value.type == "UnknownEffect" and info.value.non_retryable
    assert "provider body" not in str(info.value)
    assert backend.failures == ["UnknownEffect"]
