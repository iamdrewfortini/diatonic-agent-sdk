"""Bounded local workflow promotion using existing replay and experiment gates.

No verifier/policy editing and no native rollout. Frozen measured trials, costs,
failures and rollback history remain in the audit database. The caller is a
trusted evaluator, never a registered model tool.
"""
from __future__ import annotations

import json
import math
import sqlite3
import time
from dataclasses import dataclass

from .execution import canonical, sha
from .proof import Claim, Experiments
from .regression import FixtureSet, ReplaySet, compare_replays
from .workflows import Workflow, WorkflowRegistry


@dataclass(frozen=True)
class TrialMeasurements:
    incumbent_value: float
    candidate_value: float
    elapsed_seconds: float
    cost_nusd: int
    retries: int
    payload_bits: int | None = None
    input_tokens: int | None = None
    output_tokens: int | None = None

    def __post_init__(self):
        if any(type(x) not in (int, float) or not math.isfinite(x) or x < 0
               for x in (self.incumbent_value, self.candidate_value, self.elapsed_seconds)):
            raise ValueError("Finite nonnegative measured values required")
        if any(type(x) is not int or x < 0 for x in (self.cost_nusd, self.retries)):
            raise ValueError("Actual costs and retries must be retained")
        if any(x is not None and (type(x) is not int or x < 0)
               for x in (self.payload_bits, self.input_tokens, self.output_tokens)):
            raise ValueError("Measured counters must be nonnegative or unknown")


class LocalPromotionController:
    """Canaries change only a local WorkflowRegistry pointer, not worker activation."""
    native_activation = "pending_authenticated_production_admission_and_worker_binding"

    def __init__(self, registry: WorkflowRegistry, *, claim: Claim,
                 authorized_runs: frozenset[str], trusted_gate,
                 development_fixture_sha256: str, maximum_total_cost_nusd: int = 0,
                 maximum_total_seconds: float = 60, canary_jobs: int = 1):
        if maximum_total_cost_nusd < 0 or maximum_total_seconds <= 0 or not 1 <= canary_jobs <= 16:
            raise ValueError("Invalid bounded promotion limits")
        if not callable(trusted_gate):
            raise ValueError("Independent fixed security/capability/fidelity gate required")
        self.registry, self.audit = registry, registry.audit
        self._claim_document = canonical(claim.model_dump())
        self.experiments = Experiments(self.audit)
        self.authorized_runs, self.trusted_gate = authorized_runs, trusted_gate
        self.development_fixture = development_fixture_sha256
        self.max_cost, self.max_seconds, self.canary_jobs = maximum_total_cost_nusd, maximum_total_seconds, canary_jobs
        self._contract = canonical({"claim": claim.model_dump(), "development_fixture": development_fixture_sha256,
                                   "max_cost": maximum_total_cost_nusd, "max_seconds": maximum_total_seconds,
                                   "canary_jobs": canary_jobs})
        with self.audit.connect() as db:
            db.execute("CREATE TABLE IF NOT EXISTS promotion_locks(claim TEXT PRIMARY KEY, document TEXT NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS promotion_contracts(claim TEXT PRIMARY KEY, document TEXT NOT NULL)")
            prior = db.execute("SELECT document FROM promotion_contracts WHERE claim=?", (claim.id,)).fetchone()
            if prior and prior[0] != self._contract:
                raise ValueError("Immutable promotion contract changed; version the claim")
            db.execute("INSERT OR IGNORE INTO promotion_contracts VALUES(?,?)", (claim.id, self._contract))
            db.execute("""CREATE TABLE IF NOT EXISTS promotion_state(
                root TEXT PRIMARY KEY, active TEXT NOT NULL, rollback TEXT,
                state TEXT NOT NULL, remaining_canary INTEGER NOT NULL)""")
            db.execute("""CREATE TABLE IF NOT EXISTS promotion_observations(
                root TEXT NOT NULL, candidate TEXT NOT NULL, evidence_sha256 TEXT NOT NULL,
                passed INTEGER NOT NULL, UNIQUE(root,candidate,evidence_sha256))""")
            db.execute("""CREATE TABLE IF NOT EXISTS promotion_trials(
                claim TEXT NOT NULL, attempt INTEGER NOT NULL, root TEXT NOT NULL,
                incumbent TEXT NOT NULL, candidate TEXT NOT NULL, document TEXT NOT NULL,
                eligible INTEGER NOT NULL, promoted INTEGER NOT NULL DEFAULT 0,
                heldout TEXT NOT NULL, UNIQUE(claim,attempt), UNIQUE(claim,heldout))""")

    @property
    def claim(self):
        # Return a fresh model: neither a mutable caller's Claim nor a later
        # external reference can alter the controller's sealed acceptance rule.
        return Claim.model_validate_json(self._claim_document)

    def initialize(self, run: str, incumbent: Workflow):
        self._authorize(run)
        self.registry.deploy(run, incumbent)
        with self.audit.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT active FROM promotion_state WHERE root=?", (run,)).fetchone()
            if row and row[0] != incumbent.digest:
                raise ValueError("Incumbent already initialized to another version")
            db.execute("INSERT OR IGNORE INTO promotion_state VALUES(?,?,NULL,'incumbent',0)", (run, incumbent.digest))

    def _authorize(self, run):
        if run not in self.authorized_runs:
            raise PermissionError("Run has no existing local promotion authorization")

    def state(self, run):
        self._authorize(run)
        with self.audit.connect() as db:
            row = db.execute("SELECT active,rollback,state,remaining_canary FROM promotion_state WHERE root=?", (run,)).fetchone()
        if not row:
            raise ValueError("Frozen incumbent required")
        return dict(zip(("active", "rollback", "state", "remaining_canary"), row))

    def evaluate(self, run: str, *, incumbent_digest: str, candidate: Workflow,
                 heldout: FixtureSet, baseline: ReplaySet, replay: ReplaySet,
                 measured: TrialMeasurements):
        self._authorize(run)
        # Durable single-evaluator admission protects aggregate limits and heldout
        # consumption across processes, not just threads. A process crash leaves
        # a visible pending lock; it never silently permits another experiment.
        lock = {"root": run, "incumbent": incumbent_digest, "candidate": candidate.digest,
                "heldout": heldout.fixture_sha256, "measured": measured.__dict__, "created_at": time.time()}
        try:
            with self.audit.connect() as db:
                db.execute("INSERT INTO promotion_locks VALUES(?,?)", (self.claim.id, canonical(lock)))
        except sqlite3.IntegrityError:
            raise ValueError("Concurrent or unresolved evaluation; inspect durable promotion lock") from None
        try:
            return self._evaluate(run, incumbent_digest=incumbent_digest, candidate=candidate,
                                  heldout=heldout, baseline=baseline, replay=replay, measured=measured)
        except BaseException as error:
            self.audit.emit(run, "promotion-controller", "promotion.evaluation.blocked",
                            {"candidate": candidate.digest, "reason_class": type(error).__name__,
                             "measured": measured.__dict__})
            raise
        finally:
            with self.audit.connect() as db:
                db.execute("DELETE FROM promotion_locks WHERE claim=?", (self.claim.id,))

    def _evaluate(self, run: str, *, incumbent_digest: str, candidate: Workflow,
                 heldout: FixtureSet, baseline: ReplaySet, replay: ReplaySet,
                 measured: TrialMeasurements):
        self._authorize(run)
        current = self.state(run)
        if current["active"] != incumbent_digest or current["state"] == "canary":
            raise ValueError("Stale incumbent or active canary")
        if heldout.fixture_sha256 == self.development_fixture:
            raise ValueError("Held-out cases must be separate from development cases")
        if candidate.digest == incumbent_digest:
            raise ValueError("A changed candidate is required")
        # Fixed trusted evaluator gates security, capability and translation
        # fidelity. Caller-supplied verifier labels/booleans are not accepted.
        comparison = compare_replays(heldout, baseline, replay)
        security = self.trusted_gate(candidate, heldout, baseline, replay)
        if type(security) is not bool:
            raise ValueError("Trusted evaluator must return a strict boolean")
        improvement = (measured.candidate_value > measured.incumbent_value if self.claim.direction == "at_least"
                       else measured.candidate_value < measured.incumbent_value)
        threshold = (measured.candidate_value >= self.claim.threshold if self.claim.direction == "at_least"
                     else measured.candidate_value <= self.claim.threshold)
        with self.audit.connect() as db:
            rows = db.execute("SELECT document FROM promotion_trials WHERE claim=?", (self.claim.id,)).fetchall()
        costs = sum(json.loads(r[0])["measured"]["cost_nusd"] for r in rows)
        seconds = sum(json.loads(r[0])["measured"]["elapsed_seconds"] for r in rows)
        # A heldout is consumed once, including failed candidates; tuning against
        # the same holdout cannot become a promotion experiment.
        if any(json.loads(r[0])["heldout_sha256"] == heldout.fixture_sha256 for r in rows):
            raise ValueError("Heldout already consumed; retain failure and use a separate sealed evaluation")
        bounded = costs + measured.cost_nusd <= self.max_cost and seconds + measured.elapsed_seconds <= self.max_seconds
        eligible = comparison.regression_gate_passed and security and improvement and threshold and bounded
        # Existing immutable claims and iteration bounds remain the authority.
        attempt = self.experiments.request(run, self.claim, candidate.digest)
        document = {"heldout_sha256": heldout.fixture_sha256, "comparison": comparison.model_dump(mode="json"),
                    "measured": measured.__dict__, "security_capability_fidelity_gate": security,
                    "strict_improvement": improvement, "threshold_passed": threshold, "within_limits": bounded,
                    "candidate_digest": candidate.digest, "incumbent_digest": incumbent_digest,
                    "eligible": eligible, "scope": "local workflow fixture evaluation; no native rollout"}
        with self.audit.connect() as db:
            db.execute("INSERT INTO promotion_trials(claim,attempt,root,incumbent,candidate,document,eligible,heldout) VALUES(?,?,?,?,?,?,?,?)",
                       (self.claim.id, attempt, run, incumbent_digest, candidate.digest, canonical(document), int(eligible), heldout.fixture_sha256))
        # Record real measured metric even when ancillary gates fail; no falsified
        # metric is used to make Experiments' scoped threshold outcome agree.
        self.experiments.record(run, self.claim, attempt,
            measured={self.claim.metric: measured.candidate_value, "promotion_eligible": eligible,
                      "cost_nusd": measured.cost_nusd, "retries": measured.retries},
            artifact=canonical(document).encode(), verifier="deterministic-replay")
        self.audit.emit(run, "promotion-controller", "promotion.trial.recorded",
                        {"attempt": attempt, "candidate_digest": candidate.digest, "eligible": eligible,
                         "regression_status": comparison.status, "document_sha256": sha(document)})
        return {"attempt": attempt, **document}

    def promote(self, run: str, *, attempt: int, candidate: Workflow, incumbent_digest: str):
        self._authorize(run)
        # Version artifacts are immutable and parented through the real engine.
        # A definition can be registered even if later CAS loses; never activated.
        with self.audit.connect() as db:
            trial = db.execute("SELECT root,incumbent,candidate,eligible,promoted FROM promotion_trials WHERE claim=? AND attempt=?", (self.claim.id, attempt)).fetchone()
        if trial != (run, incumbent_digest, candidate.digest, 1, 0):
            raise ValueError("Ineligible, mismatched or duplicate promotion")
        if self.state(run)["active"] != incumbent_digest:
            raise ValueError("Stale incumbent promotion")
        self.registry.deploy(run, candidate, parent=incumbent_digest)
        with self.audit.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            changed = db.execute("UPDATE promotion_state SET active=?,rollback=?,state='canary',remaining_canary=? WHERE root=? AND active=? AND state!='canary'",
                                 (candidate.digest, incumbent_digest, self.canary_jobs, run, incumbent_digest)).rowcount
            if changed != 1:
                raise ValueError("Stale incumbent promotion")
            db.execute("UPDATE promotion_trials SET promoted=1 WHERE claim=? AND attempt=? AND promoted=0", (self.claim.id, attempt))
        self.audit.emit(run, "promotion-controller", "promotion.canary", {"candidate": candidate.digest, "rollback": incumbent_digest, "native_activation": self.native_activation})
        return self.state(run)

    def observe_canary(self, run: str, *, expected_digest: str, evidence):
        self._authorize(run)
        # Trusted fixed gate independently validates monitored results as well.
        evidence = json.loads(canonical(evidence))
        passed = self.trusted_gate(expected_digest, evidence, None, None)
        if type(passed) is not bool:
            raise ValueError("Trusted evaluator must return a strict boolean")
        evidence_digest = sha(evidence)
        with self.audit.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT active,rollback,state,remaining_canary FROM promotion_state WHERE root=?", (run,)).fetchone()
            if not row or row[0] != expected_digest or row[2] not in {"canary", "active"}:
                raise ValueError("Stale version or no active monitored candidate")
            if db.execute("SELECT 1 FROM promotion_observations WHERE root=? AND candidate=? AND evidence_sha256=?", (run, expected_digest, evidence_digest)).fetchone():
                raise ValueError("Duplicate monitored job evidence")
            db.execute("INSERT INTO promotion_observations VALUES(?,?,?,?)", (run, expected_digest, evidence_digest, int(passed)))
            if passed:
                remaining = max(0, row[3] - 1)
                db.execute("UPDATE promotion_state SET remaining_canary=?,state=? WHERE root=?",
                           (remaining, "active" if remaining == 0 else "canary", run))
                event = "promotion.canary.verified"
            else:
                db.execute("UPDATE promotion_state SET active=?,rollback=?,state='rolled_back',remaining_canary=0 WHERE root=?", (row[1], row[0], run))
                event = "promotion.rolled_back"
        self.audit.emit(run, "promotion-controller", event, {"observed_version": expected_digest, "evidence_sha256": evidence_digest, "passed": passed,
                         "rollback_pointer": row[1], "monitored_state": row[2]})
        return self.state(run)
