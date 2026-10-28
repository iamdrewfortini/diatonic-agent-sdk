"""Finite labelled replay comparison for a narrow canonicalizer/abstain system.

No model calls, commands, CAS, source execution or external I/O. Correctness means
exact agreement with supplied fixture labels, not proof that those labels are true.
Track IDs refer to the coordinator's schema; this module invents no extra records.
"""
from __future__ import annotations

import hashlib
import json
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

SHA = r"^[0-9a-f]{64}$"
IDENTITY = r"^[A-Za-z0-9_.:-]{1,100}$"
TRACK = r"^[A-Za-z][A-Za-z0-9_.-]{0,63}$"


class StrictRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class Provenance(StrictRecord):
    source_ref: str = Field(min_length=1, max_length=2048)
    source_sha256: str = Field(pattern=SHA)
    authority: str = Field(min_length=1, max_length=255)
    kind: Literal["human_label", "deterministic_verifier", "reference_fixture", "replay_capture"]


class LabeledCase(StrictRecord):
    case_id: str = Field(pattern=IDENTITY)
    track_id: str = Field(pattern=TRACK)
    input_sha256: str = Field(pattern=SHA)
    truth: Literal["known", "unknown"]
    expected_canonical: str | None = Field(default=None, max_length=65536)

    @model_validator(mode="after")
    def label_contract(self):
        if self.truth == "known" and self.expected_canonical is None:
            raise ValueError("Known labels require a canonical expected value; empty string is valid")
        if self.truth == "unknown" and self.expected_canonical is not None:
            raise ValueError("Unknown truth cannot carry an expected answer")
        return self


def _digest(value: dict) -> str:
    data = json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


class FixtureSet(StrictRecord):
    schema_version: Literal["1.0"] = "1.0"
    name: str = Field(pattern=IDENTITY)
    provenance: Provenance
    cases: list[LabeledCase] = Field(min_length=1, max_length=10000)
    fixture_sha256: str = Field(pattern=SHA)

    def content_digest(self) -> str:
        return _digest(self.model_dump(mode="json", exclude={"fixture_sha256"}))

    @model_validator(mode="after")
    def fixture_contract(self):
        ids = [c.case_id for c in self.cases]
        if len(ids) != len(set(ids)):
            raise ValueError("Duplicate fixture case")
        if self.provenance.kind == "replay_capture":
            raise ValueError("A replay capture alone is not a labelled fixture authority")
        if self.fixture_sha256 != self.content_digest():
            raise ValueError("Fixture digest does not bind the supplied labels, order and provenance")
        return self

    @classmethod
    def seal(cls, *, name: str, provenance: Provenance, cases: list[LabeledCase]) -> FixtureSet:
        payload = {"schema_version": "1.0", "name": name,
                   "provenance": provenance.model_dump(mode="json"),
                   "cases": [c.model_dump(mode="json") for c in cases]}
        return cls.model_validate({**payload, "fixture_sha256": _digest(payload)})


class TaskRoute(StrictRecord):
    task_id: str = Field(pattern=IDENTITY)
    route_id: str = Field(pattern=IDENTITY)
    mechanism: Literal["rule_only", "model_proposal", "human_review"]
    implementation_sha256: str = Field(pattern=SHA)
    model_id: str | None = Field(default=None, min_length=1, max_length=255)

    @model_validator(mode="after")
    def route_contract(self):
        if self.mechanism == "model_proposal" and self.model_id is None:
            raise ValueError("Model routes must name their model")
        if self.mechanism != "model_proposal" and self.model_id is not None:
            raise ValueError("Non-model routes cannot masquerade as model execution")
        return self


class ReplayRecord(StrictRecord):
    case_id: str = Field(pattern=IDENTITY)
    input_sha256: str = Field(pattern=SHA)
    decision: Literal["committed", "abstain"]
    canonical_value: str | None = Field(default=None, max_length=65536)
    abstain_reason: str | None = Field(default=None, min_length=1, max_length=512)
    task_route: TaskRoute

    @model_validator(mode="after")
    def outcome_contract(self):
        if self.decision == "committed":
            if self.canonical_value is None or self.abstain_reason is not None:
                raise ValueError("Committed result needs a canonical value and no abstention reason")
        elif self.canonical_value is not None or self.abstain_reason is None:
            raise ValueError("Abstention needs a reason and cannot carry a tentative committed answer")
        return self


class ReplaySet(StrictRecord):
    replay_id: str = Field(pattern=IDENTITY)
    fixture_sha256: str = Field(pattern=SHA)
    provenance: Provenance
    records: list[ReplayRecord] = Field(max_length=10000)

    @model_validator(mode="after")
    def unique_cases(self):
        ids = [r.case_id for r in self.records]
        if len(ids) != len(set(ids)):
            raise ValueError("Duplicate replay case")
        return self


class Ratio(StrictRecord):
    numerator: int = Field(ge=0)
    denominator: int = Field(ge=0)
    value: float | None = Field(default=None, allow_inf_nan=False)
    basis: str

    @classmethod
    def of(cls, numerator: int, denominator: int, basis: str) -> Ratio:
        if numerator > denominator:
            raise ValueError("Numerator exceeds denominator")
        return cls(numerator=numerator, denominator=denominator,
                   value=numerator / denominator if denominator else None, basis=basis)


class Metrics(StrictRecord):
    total_cases: int
    labeled_cases: int
    unknown_truth_cases: int
    committed_cases: int
    abstained_cases: int
    missing_cases_as_abstentions: int
    labeled_committed_cases: int
    committed_unknown_truth_cases: int
    correct_committed_cases: int
    wrong_committed_cases: int
    committed_precision: Ratio
    coverage: Ratio
    labeled_coverage: Ratio
    unknown_truth_rate: Ratio
    unscored_commit_rate: Ratio
    abstention_rate: Ratio
    labeled_correct_commit_rate: Ratio


class LostCorrect(StrictRecord):
    case_id: str
    track_id: str
    kind: Literal["LOST_CORRECT"] = "LOST_CORRECT"
    candidate_outcome: Literal["wrong_commit", "abstain", "missing_as_abstain"]


class RouteChange(StrictRecord):
    case_id: str
    track_id: str
    before: TaskRoute
    after: TaskRoute | None
    kind: Literal["changed", "missing_candidate_route"]


class RegressionComparison(StrictRecord):
    fixture_sha256: str
    fixture_provenance: Provenance
    baseline_replay_id: str
    candidate_replay_id: str
    baseline: Metrics
    candidate: Metrics
    candidate_missing_cases: list[str]
    replay_complete: bool
    lost_correct: list[LostCorrect]
    gained_correct_cases: list[str]
    route_changes: list[RouteChange]
    correct_case_preservation: Ratio
    status: Literal["LOST_CORRECT", "INCOMPLETE_CANDIDATE", "NO_BASELINE_CORRECT_CASES", "PASSED_SCOPED_REGRESSION_CHECK"]
    regression_gate_passed: bool
    scope: str = "Finite exact comparison with the supplied labelled fixture digest; no universal or empirical-population 100% correctness guarantee."
    truth_boundary: str = "Provenance and hashes bind supplied records; they do not authenticate the authority or prove ground-truth labels, physics, mathematics, or task meaning."


def _correct(case: LabeledCase, record: ReplayRecord | None) -> bool:
    return bool(case.truth == "known" and record is not None and record.decision == "committed"
                and record.canonical_value == case.expected_canonical)


def _metrics(cases: list[LabeledCase], rows: dict[str, ReplayRecord]) -> Metrics:
    total = len(cases)
    labeled = sum(c.truth == "known" for c in cases)
    committed = sum(c.case_id in rows and rows[c.case_id].decision == "committed" for c in cases)
    labeled_committed = sum(c.truth == "known" and c.case_id in rows and rows[c.case_id].decision == "committed" for c in cases)
    correct = sum(_correct(c, rows.get(c.case_id)) for c in cases)
    unscored = committed - labeled_committed
    return Metrics(total_cases=total, labeled_cases=labeled, unknown_truth_cases=total-labeled,
        committed_cases=committed, abstained_cases=total-committed,
        missing_cases_as_abstentions=sum(c.case_id not in rows for c in cases),
        labeled_committed_cases=labeled_committed, committed_unknown_truth_cases=unscored,
        correct_committed_cases=correct, wrong_committed_cases=labeled_committed-correct,
        committed_precision=Ratio.of(correct, labeled_committed, "correct commits / committed cases with known fixture truth; unscored commits excluded and reported separately"),
        coverage=Ratio.of(committed, total, "all commits / all fixture cases, including unknown truth"),
        labeled_coverage=Ratio.of(labeled_committed, labeled, "commits with known truth / all labelled cases"),
        unknown_truth_rate=Ratio.of(total-labeled, total, "unknown fixture truth / all fixture cases"),
        unscored_commit_rate=Ratio.of(unscored, committed, "commits with unknown fixture truth / all committed cases"),
        abstention_rate=Ratio.of(total-committed, total, "explicit abstentions plus missing records / all fixture cases"),
        labeled_correct_commit_rate=Ratio.of(correct, labeled, "correct commits / all labelled cases; abstentions remain in denominator"))


def compare_replays(fixtures: FixtureSet, baseline: ReplaySet, candidate: ReplaySet) -> RegressionComparison:
    """Missing candidates never disappear from scoring; they are abstentions.

    Missing baseline records, unknown extra IDs, input drift or fixture mismatch
    are invalid comparison inputs. Route changes are reported independently and
    do not become proof of task-equivalence or permission to deploy.
    """
    # Revalidate mutable list contents as well as top-level frozen model fields.
    fixtures = FixtureSet.model_validate(fixtures.model_dump())
    baseline = ReplaySet.model_validate(baseline.model_dump())
    candidate = ReplaySet.model_validate(candidate.model_dump())
    cases = {c.case_id: c for c in fixtures.cases}
    by_run = []
    for replay in (baseline, candidate):
        if replay.fixture_sha256 != fixtures.fixture_sha256:
            raise ValueError("Replay refers to a different fixture digest")
        rows = {r.case_id: r for r in replay.records}
        if set(rows) - set(cases):
            raise ValueError("Replay includes a case absent from the fixture")
        if any(r.input_sha256 != cases[r.case_id].input_sha256 for r in replay.records):
            raise ValueError("Case identity reused for a different input")
        by_run.append(rows)
    before, after = by_run
    if set(before) != set(cases):
        raise ValueError("Incomplete baseline would conceal previously correct cases")
    missing = [c.case_id for c in fixtures.cases if c.case_id not in after]
    losses, gains, routes = [], [], []
    for case in fixtures.cases:
        old, new = before[case.case_id], after.get(case.case_id)
        old_correct, new_correct = _correct(case, old), _correct(case, new)
        if old_correct and not new_correct:
            outcome = "missing_as_abstain" if new is None else "abstain" if new.decision == "abstain" else "wrong_commit"
            losses.append(LostCorrect(case_id=case.case_id, track_id=case.track_id, candidate_outcome=outcome))
        if not old_correct and new_correct:
            gains.append(case.case_id)
        if new is None or old.task_route != new.task_route:
            routes.append(RouteChange(case_id=case.case_id, track_id=case.track_id,
                                     before=old.task_route, after=new.task_route if new else None,
                                     kind="changed" if new else "missing_candidate_route"))
    old_metrics, new_metrics = _metrics(fixtures.cases, before), _metrics(fixtures.cases, after)
    status = ("LOST_CORRECT" if losses else "INCOMPLETE_CANDIDATE" if missing else
              "NO_BASELINE_CORRECT_CASES" if old_metrics.correct_committed_cases == 0 else "PASSED_SCOPED_REGRESSION_CHECK")
    return RegressionComparison(fixture_sha256=fixtures.fixture_sha256, fixture_provenance=fixtures.provenance,
        baseline_replay_id=baseline.replay_id, candidate_replay_id=candidate.replay_id,
        baseline=old_metrics, candidate=new_metrics, candidate_missing_cases=missing,
        replay_complete=not missing, lost_correct=losses, gained_correct_cases=gains,
        route_changes=routes,
        correct_case_preservation=Ratio.of(old_metrics.correct_committed_cases-len(losses),
                                          old_metrics.correct_committed_cases, "preserved previously correct commits / all previously correct commits"),
        status=status, regression_gate_passed=status == "PASSED_SCOPED_REGRESSION_CHECK")
