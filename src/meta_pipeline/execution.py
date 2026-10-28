"""Bounded local adapter for the existing Temporal ActivityBackend contract.

This is a disposable-fixture admission authority, not a production shared service.
Handlers, verifiers, policy and inputs are coordinator-bound objects; models never
supply callables, grants, verifier labels or resource capacities. Native services
keep their own authorization and idempotency semantics.
"""
from __future__ import annotations

import asyncio
from dataclasses import asdict, dataclass
import hashlib
import inspect
import json
import time
from typing import Any, Callable

from pydantic import BaseModel, ConfigDict, Field

from .protocol import digest as contract_digest
from .scheduling import (Admission, StageFailure, StageRequest, StageResult, STAGES,
                         execution_key, validate_plan, validate_result, ARTIFACT, HDD_LEASE)


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def sha(value: Any) -> str:
    return hashlib.sha256(canonical(value).encode()).hexdigest()


class Verification(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    verified: bool
    evidence_refs: list[str] = Field(min_length=1, max_length=32)
    reason: str = Field(min_length=1, max_length=512)


@dataclass(frozen=True)
class ContractBinding:
    task: str
    stage_kind: str
    handler_version: str
    input_model: type[BaseModel]
    output_model: type[BaseModel]
    handler: Callable
    verifier: Callable
    fidelity: Callable
    effects: tuple[str, ...] = ()
    requirements: tuple[str, ...] = ()
    exclusion: str | None = None
    timeout_seconds: float = 30.0

    def __post_init__(self):
        if self.stage_kind not in STAGES or not self.task or not self.handler_version:
            raise ValueError("Known stage and versioned task binding required")
        if not 0 < self.timeout_seconds <= 600:
            raise ValueError("Handler timeout outside bounded range")
        if self.handler is self.verifier:
            raise ValueError("Effect handler cannot attest its own result")
        if not all(callable(f) for f in (self.handler, self.verifier, self.fidelity)):
            raise ValueError("Explicit handler, independent verifier and fidelity checker required")

    @property
    def document(self):
        return {"task": self.task, "stage_kind": self.stage_kind,
                "handler_version": self.handler_version,
                "input_schema": self.input_model.model_json_schema(),
                "output_schema": self.output_model.model_json_schema(),
                "effects": self.effects, "requirements": self.requirements,
                "exclusion": self.exclusion, "timeout_seconds": self.timeout_seconds}

    @property
    def digest(self):
        return sha(self.document)


class ContractRegistry:
    """Exactly one handler/schema per task and stage kind, no name guessing."""
    def __init__(self):
        self.tasks: dict[str, ContractBinding] = {}
        self.stages: dict[str, ContractBinding] = {}

    def register(self, binding: ContractBinding):
        if binding.task in self.tasks or binding.stage_kind in self.stages:
            raise ValueError("Ambiguous task or stage binding")
        self.tasks[binding.task] = binding
        self.stages[binding.stage_kind] = binding

    def binding(self, task: str):
        if task not in self.tasks:
            raise ValueError("unbound_handler")
        return self.tasks[task]


@dataclass(frozen=True)
class FixturePolicy:
    root_run: str
    policy_ref: str
    allowed_tasks: frozenset[str]
    budget_nusd: int
    requirements: frozenset[str] = frozenset()
    maximum_depth: int = 2
    expires_at: float = float("inf")

    def __post_init__(self):
        if not self.root_run or self.budget_nusd < 0 or not 0 <= self.maximum_depth <= 2:
            raise ValueError("Invalid trusted fixture policy")


async def _call(fn, *args):
    # Async effects can be cancelled safely into an unresolved receipt. Sync
    # handlers must be short bounded local calls; do not run an uncancellable
    # effect in a background thread and release its exclusion on timeout.
    result = fn(*args)
    return await result if inspect.isawaitable(result) else result


class LocalFixtureBackend:
    production_ready = False

    def __init__(self, audit, registry: ContractRegistry, policies: list[FixturePolicy],
                 *, capacity_check: Callable | None = None):
        self.audit, self.registry = audit, registry
        self.policies = {p.root_run: p for p in policies}
        if len(self.policies) != len(policies):
            raise ValueError("Duplicate root policy")
        self.capacity_check = capacity_check
        with audit.connect() as db:
            db.execute("CREATE TABLE IF NOT EXISTS fixture_policies(root TEXT PRIMARY KEY, document TEXT NOT NULL)")
            for policy in policies:
                document = canonical({"root_run": policy.root_run, "policy_ref": policy.policy_ref,
                    "allowed_tasks": sorted(policy.allowed_tasks), "budget_nusd": policy.budget_nusd,
                    "requirements": sorted(policy.requirements), "maximum_depth": policy.maximum_depth,
                    "expires_at": policy.expires_at if policy.expires_at != float("inf") else None})
                old = db.execute("SELECT document FROM fixture_policies WHERE root=?", (policy.root_run,)).fetchone()
                if old and old[0] != document:
                    raise ValueError("Root fixture policy is immutable; create a separately authorized root")
                db.execute("INSERT OR IGNORE INTO fixture_policies VALUES(?,?)", (policy.root_run, document))
            db.execute("""CREATE TABLE IF NOT EXISTS fixture_tasks(
                key TEXT PRIMARY KEY, document TEXT NOT NULL)""")
            db.execute("""CREATE TABLE IF NOT EXISTS fixture_executions(
                key TEXT PRIMARY KEY, root TEXT NOT NULL, state TEXT NOT NULL,
                reserved INTEGER NOT NULL, exclusion_name TEXT, receipt TEXT NOT NULL,
                result TEXT, output TEXT, verification TEXT, reason TEXT)""")

    def derive(self, req: StageRequest, *, task: str, original_request: str,
               inputs: dict, correlation_id: str, causal_parents: tuple[str, ...] = (),
               depth: int = 0):
        validate_plan(req.plan)
        binding = self.registry.binding(task)
        if req.stage not in req.plan.stages or binding.stage_kind != req.stage.kind:
            raise ValueError("Task is incompatible with the registered workflow stage")
        if req.key != execution_key(req.plan, req.stage):
            raise ValueError("Task identity mismatch")
        data = binding.input_model.model_validate(inputs)
        if not original_request or not correlation_id or not 0 <= depth <= 2:
            raise ValueError("Original request, correlation and bounded depth required")
        # Fidelity is trusted deterministic code, bound once outside model scope.
        if binding.fidelity(original_request, data) is not True:
            raise ValueError("Translation fidelity failed")
        document = {"task": task, "binding": binding.digest,
                    "handler_version": binding.handler_version,
                    "protocol_sha256": contract_digest(), "root_run": req.plan.root_run,
                    "workflow_version": req.plan.version, "evidence_ref": req.plan.evidence_ref,
                    "inputs": data.model_dump(mode="json"),
                    "original_sha256": hashlib.sha256(original_request.encode()).hexdigest(),
                    "correlation_id": correlation_id, "causal_parents": list(causal_parents),
                    "depth": depth}
        body = canonical(document)
        with self.audit.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT document FROM fixture_tasks WHERE key=?", (req.key,)).fetchone()
            if row and row[0] != body:
                raise ValueError("Immutable task identity reused with changed input")
            db.execute("INSERT OR IGNORE INTO fixture_tasks VALUES(?,?)", (req.key, body))
        self._event(req, "task.derived", {"task": task, "binding": binding.digest,
                    "handler_version": binding.handler_version,
                    "input_sha256": sha(document["inputs"]),
                    "original_sha256": document["original_sha256"],
                    "correlation_id": correlation_id, "causal_parents": list(causal_parents),
                    "depth": depth})
        return document

    def _task(self, req):
        with self.audit.connect() as db:
            row = db.execute("SELECT document FROM fixture_tasks WHERE key=?", (req.key,)).fetchone()
        if not row:
            raise StageFailure("SchemaFailure")
        task = json.loads(row[0])
        try:
            binding = self.registry.binding(task["task"])
        except ValueError:
            raise StageFailure("SchemaFailure") from None
        if (task["binding"] != binding.digest or task["protocol_sha256"] != contract_digest()
                or task["workflow_version"] != req.plan.version
                or task["root_run"] != req.plan.root_run or task["evidence_ref"] != req.plan.evidence_ref
                or binding.stage_kind != req.stage.kind or req.key != execution_key(req.plan, req.stage)):
            raise StageFailure("SchemaFailure")
        return task, binding

    def _event(self, req, kind, detail):
        self.audit.emit(req.plan.root_run, req.key, kind,
                        {"key": req.key, "workflow_version": req.plan.version,
                         "contract_version": "diatonic-13-v1", **detail})

    def _authorized(self, req, task, binding):
        policy = self.policies.get(req.plan.root_run)
        if (policy is None or policy.policy_ref != req.plan.policy_ref or policy.expires_at <= time.time()
                or task["task"] not in policy.allowed_tasks or task["depth"] > policy.maximum_depth
                or not set(binding.requirements).issubset(policy.requirements)
                or req.plan.root_budget_nusd > policy.budget_nusd):
            raise StageFailure("PolicyDenied")
        return policy

    async def claim(self, req: StageRequest):
        validate_plan(req.plan)
        task, binding = self._task(req)
        p = self._authorized(req, task, binding)
        group, model, role = STAGES[req.stage.kind]
        if (req.stage not in req.plan.stages or req.model != model or req.role != role
                or req.disk_lease != (HDD_LEASE if group == "hdd" else None)
                or set(req.dependency_refs) != set(req.stage.depends_on)
                or any(not ARTIFACT.fullmatch(value) for value in req.dependency_refs.values())):
            raise StageFailure("SchemaFailure")
        # The real HDD group is deliberately unavailable without a native fresh
        # capacity+slice+flock checker. This local backend never grants that alone.
        if STAGES[req.stage.kind][0] == "hdd":
            if self.capacity_check is None or await _call(self.capacity_check, req) is not True:
                raise StageFailure("PolicyDenied")
        receipt = sha([req.key, task["binding"], task["correlation_id"]])
        with self.audit.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            old = db.execute("SELECT state,result,receipt FROM fixture_executions WHERE key=?", (req.key,)).fetchone()
            if old:
                if old[0] == "completed":
                    return Admission(old[2], StageResult(**json.loads(old[1])))
                raise StageFailure("UnknownEffect")
            for dependency in req.stage.depends_on:
                stage = next(s for s in req.plan.stages if s.id == dependency)
                producer_key = execution_key(req.plan, stage)
                producer = db.execute("SELECT state,result FROM fixture_executions WHERE key=?", (producer_key,)).fetchone()
                if not producer or producer[0] != "completed" or not producer[1]:
                    raise StageFailure("PolicyDenied")
                evidence = StageResult(**json.loads(producer[1]))
                if not evidence.proven or evidence.artifact_ref != req.dependency_refs[dependency]:
                    raise StageFailure("PolicyDenied")
            used = db.execute("SELECT COALESCE(SUM(reserved),0) FROM fixture_executions WHERE root=?", (p.root_run,)).fetchone()[0]
            if used + req.stage.reserve_nusd > p.budget_nusd:
                raise StageFailure("BudgetDenied")
            if binding.exclusion and db.execute("SELECT 1 FROM fixture_executions WHERE exclusion_name=? AND state IN ('admitted','unresolved','failed_verification')", (binding.exclusion,)).fetchone():
                raise StageFailure("PolicyDenied")
            db.execute("INSERT INTO fixture_executions VALUES(?,?,'admitted',?,?,?,?,NULL,NULL,NULL)",
                       (req.key, p.root_run, req.stage.reserve_nusd, binding.exclusion, receipt, None))
        self._event(req, "task.admitted", {"correlation_id": task["correlation_id"],
                    "causal_parents": task["causal_parents"], "handler_version": binding.handler_version,
                    "reserved_nusd": req.stage.reserve_nusd, "native_activation": "pending"})
        return Admission(receipt)

    def _admitted(self, req, admission):
        with self.audit.connect() as db:
            row = db.execute("SELECT state,receipt FROM fixture_executions WHERE key=?", (req.key,)).fetchone()
        if not row or row != ("admitted", admission.receipt):
            raise StageFailure("UnknownEffect")

    async def perform(self, req, admission):
        self._admitted(req, admission)
        task, binding = self._task(req)
        self._authorized(req, task, binding)
        data = binding.input_model.model_validate(task["inputs"])
        started = time.monotonic()
        try:
            async with asyncio.timeout(binding.timeout_seconds):
                output = binding.output_model.model_validate(await _call(binding.handler, data))
                if time.monotonic() - started > binding.timeout_seconds:
                    raise TimeoutError
                verdict = Verification.model_validate(await _call(binding.verifier, data, output))
                if time.monotonic() - started > binding.timeout_seconds:
                    raise TimeoutError
        except TimeoutError:
            raise StageFailure("UnknownEffect") from None
        body = output.model_dump(mode="json")
        artifact = "artifact:" + sha({"output": body, "verification": verdict.model_dump(mode="json"), "binding": binding.digest})
        result = StageResult(req.key, artifact, verdict.verified,
                             measured_input_bytes=len(canonical(task["inputs"]).encode()),
                             measured_output_bytes=len(canonical(body).encode()),
                             input_tokens=0, output_tokens=0, derived_cost_nusd=0)
        with self.audit.connect() as db:
            changed = db.execute("UPDATE fixture_executions SET output=?,verification=?,result=? WHERE key=? AND state='admitted' AND receipt=?",
                                 (canonical(body), canonical(verdict.model_dump(mode="json")), canonical(asdict(result)), req.key, admission.receipt)).rowcount
            if changed != 1:
                raise StageFailure("UnknownEffect")
        return result

    async def complete(self, req, admission, result):
        validate_result(result, req.key)
        self._admitted(req, admission)
        with self.audit.connect() as db:
            row = db.execute("SELECT result,verification FROM fixture_executions WHERE key=?", (req.key,)).fetchone()
            if not row[0] or not row[1]:
                raise StageFailure("UnknownEffect")
            recorded = StageResult(**json.loads(row[0]))
            # Activities adds its measured elapsed_ms, no other result changes.
            if {**asdict(recorded), "elapsed_ms": result.elapsed_ms} != asdict(result):
                raise StageFailure("SchemaFailure")
            state = "completed" if result.proven else "failed_verification"
            db.execute("UPDATE fixture_executions SET state=?,result=? WHERE key=? AND state='admitted'", (state, canonical(asdict(result)), req.key))
        task, binding = self._task(req)
        self._event(req, "task." + state, {"artifact_ref": result.artifact_ref,
                    "correlation_id": task["correlation_id"], "handler_version": binding.handler_version,
                    "causal_parents": task["causal_parents"], "proven": result.proven})

    async def failed(self, req, admission, kind):
        # Once admitted any exception/cancellation/timeout is unresolved; retain
        # reservation and exclusion until native/fixture reconciliation proves it.
        with self.audit.connect() as db:
            changed = db.execute("UPDATE fixture_executions SET state='unresolved',reason=? WHERE key=? AND state='admitted'", (kind, req.key)).rowcount
        self._event(req, "task.unresolved" if changed else "task.blocked",
                    {"reason": kind, "reservation_retained": bool(changed)})

    async def reconcile(self, req):
        """Read-only independent verifier observes effect; never replay handler."""
        task, binding = self._task(req)
        with self.audit.connect() as db:
            row = db.execute("SELECT state,output,result FROM fixture_executions WHERE key=?", (req.key,)).fetchone()
        if not row or row[0] not in {"admitted", "unresolved"} or not row[1]:
            return {"state": "unresolved", "reason": "No durable output; native request reconciliation required"}
        verdict = Verification.model_validate(await _call(binding.verifier,
                    binding.input_model.model_validate(task["inputs"]),
                    binding.output_model.model_validate(json.loads(row[1]))))
        if not verdict.verified:
            return {"state": "unresolved", "reason": verdict.reason}
        result = StageResult(**json.loads(row[2]))
        if not result.proven:
            return {"state": "unresolved", "reason": "Original verification failed; no silent promotion"}
        with self.audit.connect() as db:
            db.execute("UPDATE fixture_executions SET state='completed',verification=? WHERE key=? AND state IN ('admitted','unresolved')", (canonical(verdict.model_dump(mode="json")), req.key))
        self._event(req, "task.reconciled", {"artifact_ref": result.artifact_ref, "proven": True})
        return {"state": "completed", "artifact_ref": result.artifact_ref}

    def records(self):
        with self.audit.connect() as db:
            return [dict(zip(("key", "root", "state", "reserved_nusd", "exclusion", "receipt", "result", "output", "verification", "reason"), row))
                    for row in db.execute("SELECT * FROM fixture_executions ORDER BY rowid")]
