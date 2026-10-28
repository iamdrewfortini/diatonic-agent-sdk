"""Upstream Temporal orchestration; no model, network or disk I/O in Workflows.

Production remains gated on a dedicated namespace, authenticated server and a
shared atomic policy/budget/idempotency backend. No schedules are created here.
Existing Agents SDK Assembly runs unchanged inside a non-retried Activity.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field, replace
from datetime import timedelta
import hashlib
import json
import re
import time
from typing import Protocol

from temporalio import activity, workflow
from temporalio.client import (
    Client, Schedule, ScheduleActionStartWorkflow, ScheduleIntervalSpec,
    ScheduleOverlapPolicy, SchedulePolicy, ScheduleSpec, ScheduleState,
)
from temporalio.common import RetryPolicy, WorkflowIDConflictPolicy, WorkflowIDReusePolicy
from temporalio.exceptions import ApplicationError
from temporalio.worker import Worker

NAMESPACE = "diatonic-rmm"
CONTROL_QUEUE = "diatonic-rmm-control-v1"
AI_QUEUE = "diatonic-rmm-ai-v1"
HDD_QUEUE = "diatonic-rmm-metal01-hdd-v1"
HDD_LEASE = "metal-01:/data:aux-batch.slice:flock"
# This allowlist is coordinator code, not a field a generated workflow can widen.
STAGES = {
    "catalog_read": ("control", None, "observer"),
    "native_rule_status": ("control", None, "observer"),
    "native_transfer_status": ("control", None, "observer"),
    "proof_review": ("control", None, "verifier"),
    "classification": ("ai", "muse-spark-1.3", "classifier"),
    "planning": ("ai", "muse-wonder-1.0", "planner"),
    "staging_validation": ("hdd", None, "file-verifier"),
    "request_rucio_rule": ("control", None, "native-operator"),
    "request_rucio_retirement": ("control", None, "native-operator"),
}
NONRETRYABLE = ["AuthenticationFailure", "SchemaFailure", "PolicyDenied", "UnknownEffect", "BudgetDenied"]
NO_RETRY = RetryPolicy(maximum_attempts=1, non_retryable_error_types=NONRETRYABLE)
READ_RETRY = RetryPolicy(initial_interval=timedelta(seconds=1), maximum_interval=timedelta(seconds=5),
                         maximum_attempts=3, non_retryable_error_types=NONRETRYABLE)
RETRY_SAFE_READS = {"catalog_read", "native_rule_status", "native_transfer_status"}
KEY = re.compile(r"^[A-Za-z0-9_-]{1,100}$")
DIGEST = re.compile(r"^[0-9a-f]{64}$")
ARTIFACT = re.compile(r"^artifact:[0-9a-f]{64}$")


def fail(message: str, kind: str = "SchemaFailure"):
    raise ApplicationError(message, type=kind, non_retryable=True)


@dataclass(frozen=True)
class Stage:
    id: str
    kind: str
    depends_on: list[str] = field(default_factory=list)
    # Reservation is a proposal; the trusted backend loads the root policy and
    # independently computes/adopts its real atomic shared spend reservation.
    reserve_nusd: int = 0
    forecast_input_bytes: int = 0
    forecast_output_bytes: int = 0


@dataclass(frozen=True)
class Plan:
    root_run: str
    policy_ref: str
    version: str
    evidence_ref: str
    event_id: str
    stages: list[Stage]
    root_budget_nusd: int
    max_parallel: int = 2


def definition_digest(stages: list[Stage]) -> str:
    values = [{"id": s.id, "kind": s.kind, "depends_on": s.depends_on,
               "reserve_nusd": s.reserve_nusd, "forecast_input_bytes": s.forecast_input_bytes,
               "forecast_output_bytes": s.forecast_output_bytes} for s in stages]
    return hashlib.sha256(json.dumps(values, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def validate_plan(plan: Plan):
    if not KEY.fullmatch(plan.root_run) or not KEY.fullmatch(plan.event_id):
        fail("Bounded root/event identity required")
    if not ARTIFACT.fullmatch(plan.evidence_ref) or not ARTIFACT.fullmatch(plan.policy_ref):
        fail("Inputs must be immutable artifact references, not paths, URLs or credentials")
    if not DIGEST.fullmatch(plan.version) or plan.version != definition_digest(plan.stages):
        fail("Workflow definition digest mismatch")
    if type(plan.root_budget_nusd) is not int or not 1 <= plan.root_budget_nusd <= 1000000000:
        fail("Invalid root budget proposal")
    if type(plan.max_parallel) is not int or not 1 <= plan.max_parallel <= 4 or not 1 <= len(plan.stages) <= 16:
        fail("Workflow bounds exceeded")
    known = {s.id: s for s in plan.stages}
    if len(known) != len(plan.stages):
        fail("Duplicate stage identity")
    for s in plan.stages:
        if not KEY.fullmatch(s.id) or s.kind not in STAGES or len(s.depends_on) > 16:
            fail("Stage is outside coordinator allowlist")
        if len(set(s.depends_on)) != len(s.depends_on):
            fail("Duplicate dependency")
        if any(type(x) is not int or x < 0 for x in (s.reserve_nusd, s.forecast_input_bytes, s.forecast_output_bytes)):
            fail("Invalid reservation or byte forecast")
        if STAGES[s.kind][0] == "ai" and s.reserve_nusd <= 0:
            fail("Paid stages require a positive spend reservation")
    visited, active = set(), set()
    def visit(key):
        if key not in known or key in active:
            fail("Unknown dependency or cyclic workflow")
        if key in visited:
            return
        active.add(key)
        for dependency in known[key].depends_on:
            visit(dependency)
        active.remove(key)
        visited.add(key)
    for key in known:
        visit(key)
    if sum(s.reserve_nusd for s in plan.stages) > plan.root_budget_nusd:
        fail("Stage reservations exceed root budget", "BudgetDenied")


def execution_key(plan: Plan, stage: Stage) -> str:
    value = [plan.root_run, plan.version, plan.event_id, plan.evidence_ref, stage.id]
    return hashlib.sha256(json.dumps(value, separators=(",", ":")).encode()).hexdigest()


@dataclass(frozen=True)
class StageRequest:
    plan: Plan
    stage: Stage
    key: str
    dependency_refs: dict[str, str]
    model: str | None
    role: str
    disk_lease: str | None = None


@dataclass(frozen=True)
class StageResult:
    key: str
    artifact_ref: str
    proven: bool
    # Null means unmeasured, never zero inferred from forecast/source size.
    measured_input_bytes: int | None = None
    measured_output_bytes: int | None = None
    measured_read_bytes: int | None = None
    measured_write_bytes: int | None = None
    elapsed_ms: int | None = None
    input_tokens: int | None = None
    output_tokens: int | None = None
    derived_cost_nusd: int | None = None
    measured_energy_joules: None = None


def validate_result(result: StageResult, expected_key: str):
    if result.key != expected_key or not ARTIFACT.fullmatch(result.artifact_ref) or type(result.proven) is not bool:
        fail("Activity result identity or proof contract invalid")
    for value in (result.measured_input_bytes, result.measured_output_bytes, result.measured_read_bytes,
                  result.measured_write_bytes, result.elapsed_ms, result.input_tokens, result.output_tokens,
                  result.derived_cost_nusd):
        if value is not None and (type(value) is not int or value < 0):
            fail("Invalid measured counter")
    if result.measured_energy_joules is not None:
        fail("Power telemetry is not configured")


@dataclass(frozen=True)
class Admission:
    # Stored within the Activity process; never serialized into Workflow history.
    receipt: str
    completed: StageResult | None = None


class StageFailure(Exception):
    """A trusted handler must classify failure certainty instead of retrying blindly."""
    def __init__(self, kind: str):
        if kind not in {*NONRETRYABLE, "TransientReadFailure"}:
            raise ValueError("Unknown failure classification")
        self.kind = kind
        super().__init__(kind)


class ActivityBackend(Protocol):
    """Production implementation must be an authenticated, atomic shared service.

    claim verifies coordinator policy/role/model, root budget, idempotency, intent
    durability and native OS flock ownership in the single disk-worker unit when requested. A duplicate completed key
    returns its result; an admitted-but-unresolved key raises UnknownEffect.
    perform uses the existing Assembly/Agents SDK or official Rucio/FTS clients.
    complete commits measured receipts; failed records uncertain effects durably.
    No backend/provider credential is a Workflow input or output.
    """
    async def claim(self, request: StageRequest) -> Admission: ...
    async def perform(self, request: StageRequest, admission: Admission) -> StageResult: ...
    async def complete(self, request: StageRequest, admission: Admission, result: StageResult): ...
    async def failed(self, request: StageRequest, admission: Admission | None, kind: str): ...


class Activities:
    def __init__(self, backend: ActivityBackend):
        self.backend = backend

    async def _run(self, req: StageRequest, expected_group: str) -> StageResult:
        validate_plan(req.plan)
        bound = next((s for s in req.plan.stages if s.id == req.stage.id), None)
        if bound != req.stage or req.stage.kind not in STAGES:
            fail("Activity does not match admitted immutable plan")
        group, model, role = STAGES[req.stage.kind]
        if expected_group != group or req.model != model or req.role != role or req.key != execution_key(req.plan, req.stage):
            fail("Activity route/model/role/idempotency mismatch", "PolicyDenied")
        if req.disk_lease != (HDD_LEASE if group == "hdd" else None):
            fail("HDD work requires native disk-worker flock ownership", "PolicyDenied")
        if set(req.dependency_refs) != set(req.stage.depends_on) or any(not ARTIFACT.fullmatch(r) for r in req.dependency_refs.values()):
            fail("Dependency evidence mismatch")
        admission = None
        started = time.perf_counter_ns()
        try:
            admission = await self.backend.claim(req)
            if admission.completed is not None:
                validate_result(admission.completed, req.key)
                return admission.completed
            result = await self.backend.perform(req, admission)
            validate_result(result, req.key)
            result = replace(result, elapsed_ms=(time.perf_counter_ns() - started) // 1000000)
            await self.backend.complete(req, admission, result)
            return result
        except StageFailure as exc:
            await self._record_failure(req, admission, exc.kind)
            retryable = exc.kind == "TransientReadFailure" and req.stage.kind in RETRY_SAFE_READS
            raise ApplicationError("Stage failed; see protected coordinator receipt", type=exc.kind,
                                   non_retryable=not retryable) from None
        except asyncio.CancelledError:
            await asyncio.shield(self._record_failure(req, admission, "UnknownEffect"))
            raise
        except ApplicationError as exc:
            # Backend-specific ApplicationErrors must not accidentally inherit a
            # retryable default after an effect or leak its raw error body.
            kind = exc.type if admission is None and exc.type in NONRETRYABLE else "UnknownEffect"
            await self._record_failure(req, admission, kind)
            raise ApplicationError("Stage result requires protected receipt reconciliation", type=kind, non_retryable=True) from None
        except Exception:
            await self._record_failure(req, admission, "UnknownEffect")
            raise ApplicationError("Effect outcome is unknown; reconcile before a new attempt", type="UnknownEffect", non_retryable=True) from None

    async def _record_failure(self, req, admission, kind):
        try:
            await self.backend.failed(req, admission, kind)
        except Exception:
            # The original admission remains unresolved in the shared service.
            # No failure to append a terminal receipt authorizes effect replay.
            pass

    @activity.defn(name="diatonic.control_stage")
    async def control(self, req: StageRequest) -> StageResult:
        return await self._run(req, "control")

    @activity.defn(name="diatonic.ai_stage")
    async def ai(self, req: StageRequest) -> StageResult:
        return await self._run(req, "ai")

    @activity.defn(name="diatonic.hdd_stage")
    async def hdd(self, req: StageRequest) -> StageResult:
        return await self._run(req, "hdd")


@dataclass
class BatchResult:
    root_run: str
    event_id: str
    status: str
    completed: dict[str, StageResult]


@workflow.defn(name="DiatonicBatchV1")
class BatchWorkflow:
    def __init__(self):
        self.current: list[str] = []
        self.finished: list[str] = []

    @workflow.query
    def progress(self) -> dict:
        return {"active_stage_ids": list(self.current), "completed_stage_ids": list(self.finished)}

    @workflow.run
    async def run(self, plan: Plan) -> BatchResult:
        validate_plan(plan)
        completed: dict[str, StageResult] = {}
        remaining = list(plan.stages)
        while remaining:
            ready = [s for s in remaining if set(s.depends_on).issubset(completed)][:plan.max_parallel]
            if not ready:
                fail("Workflow dependencies cannot progress")
            self.current = [s.id for s in ready]
            async def execute(stage):
                group, model, role = STAGES[stage.kind]
                queues = {"control": CONTROL_QUEUE, "ai": AI_QUEUE, "hdd": HDD_QUEUE}
                req = StageRequest(plan, stage, execution_key(plan, stage),
                                   {d: completed[d].artifact_ref for d in stage.depends_on}, model, role,
                                   HDD_LEASE if group == "hdd" else None)
                return await workflow.execute_activity(
                    "diatonic." + group + "_stage", req, result_type=StageResult,
                    task_queue=queues[group], activity_id=req.key,
                    start_to_close_timeout=timedelta(minutes=10 if group == "hdd" else 3),
                    schedule_to_close_timeout=timedelta(minutes=20 if group == "hdd" else 5),
                    retry_policy=READ_RETRY if stage.kind in RETRY_SAFE_READS else NO_RETRY,
                )
            results = await asyncio.gather(*(execute(s) for s in ready))
            for stage, result in zip(ready, results):
                validate_result(result, execution_key(plan, stage))
                completed[stage.id] = result
                self.finished.append(stage.id)
                remaining.remove(stage)
            self.current = []
            if any(not r.proven for r in results):
                return BatchResult(plan.root_run, plan.event_id, "needs_evidence", completed)
        return BatchResult(plan.root_run, plan.event_id, "verified_in_declared_scope", completed)


@dataclass(frozen=True)
class Trigger:
    id: str
    evidence_ref: str


@dataclass(frozen=True)
class EventPlan:
    plan: Plan
    maximum_events: int = 16
    idle_timeout_seconds: int = 3600


@workflow.defn(name="DiatonicEventDispatcherV1")
class EventDispatcher:
    def __init__(self):
        self.queue: list[Trigger] = []
        self.seen: dict[str, str] = {}
        self.duplicates = 0
        self.stopped = False
        self.processed = 0
        self.active_event: str | None = None

    @workflow.signal(name="trigger")
    async def trigger(self, event: Trigger):
        if not KEY.fullmatch(event.id) or not ARTIFACT.fullmatch(event.evidence_ref):
            fail("Invalid external trigger")
        if event.id in self.seen:
            if self.seen[event.id] != event.evidence_ref:
                fail("Duplicate event identity carries conflicting evidence")
            self.duplicates += 1
            return
        if len(self.seen) >= 64 or self.stopped:
            fail("Event dispatcher admission closed", "PolicyDenied")
        self.seen[event.id] = event.evidence_ref
        self.queue.append(event)

    @workflow.signal(name="stop")
    async def stop(self):
        # Stop drains already admitted events. It does not terminate a running
        # file job or erase uncertain effects.
        self.stopped = True

    @workflow.query
    def progress(self) -> dict:
        return {"queued": len(self.queue), "processed": self.processed,
                "duplicates": self.duplicates, "active_event": self.active_event, "admission_closed": self.stopped}

    @workflow.run
    async def run(self, config: EventPlan) -> dict:
        validate_plan(config.plan)
        if not 1 <= config.maximum_events <= 64 or not 1 <= config.idle_timeout_seconds <= 86400:
            fail("Invalid dispatcher lifetime")
        while self.processed < config.maximum_events:
            try:
                await workflow.wait_condition(lambda: bool(self.queue) or self.stopped,
                                              timeout=timedelta(seconds=config.idle_timeout_seconds))
            except asyncio.TimeoutError:
                break
            if not self.queue:
                break
            event = self.queue.pop(0)
            self.active_event = event.id
            plan = replace(config.plan, event_id=event.id, evidence_ref=event.evidence_ref)
            child_key = hashlib.sha256((plan.root_run + ":" + event.id).encode()).hexdigest()
            result = await workflow.execute_child_workflow(
                BatchWorkflow.run, plan, id="diatonic-batch-" + child_key,
                task_queue=CONTROL_QUEUE, retry_policy=NO_RETRY,
                id_reuse_policy=WorkflowIDReusePolicy.REJECT_DUPLICATE)
            self.processed += 1
            self.active_event = None
            if result.status != "verified_in_declared_scope":
                return {**self.progress(), "status": "needs_evidence"}
        return {**self.progress(), "status": "drained" if not self.queue else "bounded_pending",
                "pending_event_ids": [e.id for e in self.queue]}


@workflow.defn(name="DiatonicScheduledTickV1")
class ScheduledTickWorkflow:
    @workflow.run
    async def run(self, plan: Plan) -> BatchResult:
        validate_plan(plan)
        # start_time and workflow ID are history-backed values; no wall clock.
        slot = workflow.info().workflow_id + ":" + workflow.info().start_time.isoformat()
        event_id = "tick-" + hashlib.sha256(slot.encode()).hexdigest()
        scoped = replace(plan, event_id=event_id)
        return await workflow.execute_child_workflow(
            BatchWorkflow.run, scoped, id="diatonic-tick-" + event_id,
            task_queue=CONTROL_QUEUE, retry_policy=NO_RETRY,
            id_reuse_policy=WorkflowIDReusePolicy.REJECT_DUPLICATE)


@dataclass(frozen=True)
class ServerReadiness:
    address: str = ""
    namespace: str = NAMESPACE
    authenticated: bool = False
    namespace_provisioned: bool = False
    capacity_reviewed: bool = False
    shared_admission_backend_verified: bool = False
    worker_roles_verified: bool = False
    history_privacy_reviewed: bool = False
    readiness_evidence_ref: str = ""

    def require(self):
        if self.namespace != NAMESPACE or not self.address or not ARTIFACT.fullmatch(self.readiness_evidence_ref) or not all((
            self.authenticated, self.namespace_provisioned, self.capacity_reviewed,
            self.shared_admission_backend_verified, self.worker_roles_verified, self.history_privacy_reviewed)):
            raise ValueError("Dedicated Temporal server/namespace/auth/capacity/admission readiness is unverified")


def worker_options(group: str) -> dict:
    if group not in {"control", "ai", "hdd"}:
        raise ValueError("Unknown worker role")
    return {"task_queue": {"control": CONTROL_QUEUE, "ai": AI_QUEUE, "hdd": HDD_QUEUE}[group],
            "max_concurrent_activities": 1 if group == "hdd" else 2,
            "max_concurrent_workflow_tasks": 2,
            "max_concurrent_activity_task_polls": 1 if group == "hdd" else 2,
            "max_concurrent_workflow_task_polls": 1 if group == "hdd" else 2}


def build_worker(client: Client, backend: ActivityBackend, group: str, readiness: ServerReadiness) -> Worker:
    readiness.require()
    if client.namespace != NAMESPACE:
        raise ValueError("Postiz/default/other Temporal namespace is forbidden")
    activities = Activities(backend)
    return Worker(client, **worker_options(group),
                  workflows=[BatchWorkflow, EventDispatcher, ScheduledTickWorkflow] if group == "control" else [],
                  activities=[{"control": activities.control, "ai": activities.ai, "hdd": activities.hdd}[group]])


async def submit_event(client: Client, config: EventPlan, event: Trigger, readiness: ServerReadiness):
    readiness.require()
    validate_plan(config.plan)
    if not KEY.fullmatch(event.id) or not ARTIFACT.fullmatch(event.evidence_ref):
        raise ValueError("Invalid event signal")
    if client.namespace != NAMESPACE:
        raise ValueError("Dedicated Temporal namespace required")
    key = hashlib.sha256((config.plan.root_run + ":" + config.plan.version).encode()).hexdigest()
    return await client.start_workflow(
        EventDispatcher.run, config, id="diatonic-events-" + key,
        task_queue=CONTROL_QUEUE, start_signal="trigger", start_signal_args=[event],
        retry_policy=NO_RETRY, id_reuse_policy=WorkflowIDReusePolicy.REJECT_DUPLICATE,
        id_conflict_policy=WorkflowIDConflictPolicy.USE_EXISTING)


def paused_schedule(plan: Plan, *, every_seconds: int = 3600) -> Schedule:
    """Build an upstream schedule object; does not connect or create a schedule."""
    validate_plan(plan)
    if not 60 <= every_seconds <= 86400:
        raise ValueError("Schedule interval outside bounds")
    return Schedule(
        action=ScheduleActionStartWorkflow(
            ScheduledTickWorkflow.run, plan, id="diatonic-scheduled-" + plan.root_run,
            task_queue=CONTROL_QUEUE, retry_policy=NO_RETRY,
            execution_timeout=timedelta(hours=2)),
        spec=ScheduleSpec(intervals=[ScheduleIntervalSpec(every=timedelta(seconds=every_seconds))]),
        policy=SchedulePolicy(overlap=ScheduleOverlapPolicy.SKIP,
                              catchup_window=timedelta(minutes=5), pause_on_failure=True),
        state=ScheduleState(paused=True, note="Prepared only; no server creation or activation authorized by this builder"))


def deployment_plan() -> dict:
    return {"namespace": NAMESPACE, "active": False,
            "server_candidate": "Existing Temporal 1.28.1 discovered in Kubernetes namespace postiz; capacity/auth unverified",
            "new_server": False, "postiz_namespace_reused": False,
            "readiness_evidence_required": True,
            "global_budget_authority": "one coordinator/AI admission owner on VM104 using its same persistent ledger, or an already verified central atomic backend; independent per-host ledgers forbidden",
            "workers": {g: worker_options(g) for g in ("control", "ai", "hdd")},
            "hdd_placement": "metal-01 only, one systemd worker/unit, aux-batch.slice and native OS flock",
            "control_ai_placement": "dedicated cluster-side worker deployment; never metal-02",
            "metal02": "observer of bounded projection only",
            "model_activity_policy": "one Temporal attempt; existing SDK/Bifrost retry accounting remains required",
            "assembly_loop": "existing upstream Agents SDK inside Activity; no custom replacement loop",
            "durability_scope": "stage results and control flow; interrupted in-progress Assembly is unresolved, not transparently resumed",
            "power_telemetry": "unavailable; energy_joules remains null"}
