"""Finite deterministic replay scoring; no model or external service fixtures."""
from dataclasses import asdict
import hashlib
import json

import pytest
from pydantic import ValidationError
from meta_pipeline.regression import (
    FixtureSet, LabeledCase, Provenance, ReplayRecord, ReplaySet,
    TaskRoute, compare_replays,
)


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def provenance(kind="human_label"):
    return Provenance(source_ref="artifact:"+"a"*64, source_sha256="a"*64,
                      authority="synthetic-test-owner", kind=kind)


def case(case_id, expected="ok", track="read_files"):
    return LabeledCase(case_id=case_id, track_id=track, input_sha256=digest("input:"+case_id),
                       truth="unknown" if expected is None else "known", expected_canonical=expected)


def fixtures(cases=None):
    return FixtureSet.seal(name="finite-canonicalizer-fixture", provenance=provenance(),
                           cases=cases or [case("a"), case("b")])


def route(route_id="literal-v1", **extra):
    return TaskRoute(task_id="exact-canonicalize", route_id=route_id,
                     mechanism="rule_only", implementation_sha256="b"*64, **extra)


def row(c, value="ok", *, abstain=False, task_route=None):
    return ReplayRecord(case_id=c.case_id, input_sha256=c.input_sha256,
                         decision="abstain" if abstain else "committed",
                         canonical_value=None if abstain else value,
                         abstain_reason="unsupported canonical shape" if abstain else None,
                         task_route=task_route or route())


def replay(f, rows, name="candidate"):
    return ReplaySet(replay_id=name, fixture_sha256=f.fixture_sha256,
                      provenance=provenance("replay_capture"), records=rows)


@pytest.mark.parametrize("decision", ["wrong", "abstain", "missing"])
def test_previous_correct_always_becomes_lost_correct(decision):
    f = fixtures([case("a")]); c = f.cases[0]
    baseline = replay(f, [row(c)], "baseline")
    candidate_rows = [] if decision == "missing" else [row(c, "wrong", abstain=decision=="abstain")]
    result = compare_replays(f, baseline, replay(f, candidate_rows))
    assert result.status == "LOST_CORRECT" and not result.regression_gate_passed
    assert len(result.lost_correct) == 1 and result.lost_correct[0].kind == "LOST_CORRECT"
    assert result.lost_correct[0].candidate_outcome == {
        "wrong":"wrong_commit", "abstain":"abstain", "missing":"missing_as_abstain"}[decision]
    assert result.correct_case_preservation.numerator == 0
    assert result.correct_case_preservation.denominator == 1


def test_overall_improvement_does_not_hide_lost_correct_case():
    f=fixtures([case("a"),case("b"),case("c")]);a,b,c=f.cases
    before=replay(f,[row(a),row(b,"wrong"),row(c,"wrong")],"baseline")
    after=replay(f,[row(a,abstain=True),row(b),row(c)])
    result=compare_replays(f,before,after)
    assert result.candidate.correct_committed_cases==2 > result.baseline.correct_committed_cases
    assert result.gained_correct_cases==["b","c"]
    assert [r.case_id for r in result.lost_correct]==["a"]
    assert not result.regression_gate_passed


def test_precision_coverage_and_unknown_denominators_are_explicit():
    f=fixtures([case("a"),case("b"),case("c"),case("u",None)])
    a,b,c,u=f.cases
    before=replay(f,[row(a),row(b,"wrong"),row(c,abstain=True),row(u,"unscored")],"baseline")
    result=compare_replays(f,before,replay(f,[row(a),row(b,"wrong"),row(c,abstain=True),row(u,"unscored")]))
    m=result.candidate
    assert (m.total_cases,m.labeled_cases,m.unknown_truth_cases)==(4,3,1)
    assert (m.committed_cases,m.abstained_cases,m.labeled_committed_cases,m.committed_unknown_truth_cases)==(3,1,2,1)
    assert (m.correct_committed_cases,m.wrong_committed_cases)==(1,1)
    assert (m.committed_precision.numerator,m.committed_precision.denominator,m.committed_precision.value)==(1,2,0.5)
    assert (m.coverage.numerator,m.coverage.denominator,m.coverage.value)==(3,4,0.75)
    assert (m.labeled_coverage.numerator,m.labeled_coverage.denominator)==(2,3)
    assert (m.unknown_truth_rate.numerator,m.unknown_truth_rate.denominator)==(1,4)
    assert (m.unscored_commit_rate.numerator,m.unscored_commit_rate.denominator)==(1,3)
    assert m.labeled_correct_commit_rate.denominator==3


def test_candidate_omission_cannot_inflate_precision_or_coverage():
    f=fixtures();a,b=f.cases
    result=compare_replays(f,replay(f,[row(a),row(b,"wrong")],"baseline"),replay(f,[row(a)]))
    assert result.status=="INCOMPLETE_CANDIDATE" and not result.regression_gate_passed
    assert result.candidate_missing_cases==["b"] and not result.replay_complete
    assert result.candidate.total_cases==2 and result.candidate.coverage.denominator==2
    assert result.candidate.missing_cases_as_abstentions==1
    assert result.candidate.abstention_rate.numerator==1
    assert result.candidate.committed_precision.value==1.0  # explicitly 1/1 finite scored commit
    assert result.candidate.labeled_correct_commit_rate.value==0.5  # no missing case disappears


def test_all_abstention_precision_is_undefined_not_perfect():
    f=fixtures();a,b=f.cases
    result=compare_replays(f,replay(f,[row(a),row(b)],"baseline"),replay(f,[row(a,abstain=True),row(b,abstain=True)]))
    assert result.candidate.committed_precision.denominator==0
    assert result.candidate.committed_precision.value is None
    assert result.candidate.coverage.value==0
    assert len(result.lost_correct)==2


def test_unknown_truth_does_not_become_correct_by_matching_none():
    f=fixtures([case("u",None)]);u=f.cases[0]
    result=compare_replays(f,replay(f,[row(u,"claim")],"baseline"),replay(f,[row(u,"claim")]))
    assert result.status=="NO_BASELINE_CORRECT_CASES" and not result.regression_gate_passed
    assert result.baseline.correct_committed_cases==0
    assert result.candidate.committed_precision.value is None
    assert result.correct_case_preservation.value is None
    assert result.candidate.unknown_truth_rate.value==1.0


def test_route_and_model_changes_are_reported_without_relabelling_truth():
    f=fixtures([case("a")]);a=f.cases[0]
    model_route=TaskRoute(task_id="exact-canonicalize",route_id="proposal-route",mechanism="model_proposal",
                          implementation_sha256="c"*64,model_id="muse-spark-1.3")
    result=compare_replays(f,replay(f,[row(a)],"baseline"),replay(f,[row(a,task_route=model_route)]))
    assert not result.lost_correct and len(result.route_changes)==1
    assert result.route_changes[0].after.model_id=="muse-spark-1.3"
    assert result.regression_gate_passed  # only the finite LOST_CORRECT property passed
    assert "no universal" in result.scope
    assert "do not authenticate" in result.truth_boundary


def test_empty_canonical_value_is_a_valid_known_label():
    f=fixtures([case("empty","")]);c=f.cases[0]
    result=compare_replays(f,replay(f,[row(c,"")],"baseline"),replay(f,[row(c,"")]))
    assert result.regression_gate_passed and result.candidate.correct_committed_cases==1


def test_exact_comparison_does_not_silently_normalize_or_solve():
    f=fixtures([case("expression","x+x")]);c=f.cases[0]
    for guess in ["2*x","x + x","x+x\n"]:
        result=compare_replays(f,replay(f,[row(c,"x+x")],"baseline"),replay(f,[row(c,guess)]))
        assert result.status=="LOST_CORRECT"


def test_duplicate_fixture_or_replay_cases_are_rejected():
    c=case("a")
    with pytest.raises(ValidationError):fixtures([c,c])
    f=fixtures([c])
    with pytest.raises(ValidationError):replay(f,[row(c),row(c)])


def test_fixture_provenance_digest_and_input_binding_are_required():
    f=fixtures();a,b=f.cases
    with pytest.raises(ValidationError):
        FixtureSet.model_validate({**f.model_dump(),"fixture_sha256":"0"*64})
    with pytest.raises(ValidationError):
        FixtureSet.seal(name="bad",provenance=provenance("replay_capture"),cases=[a])
    with pytest.raises(ValidationError):
        Provenance.model_validate({"source_ref":"no-digest","authority":"nobody","kind":"human_label"})
    candidate=replay(f,[row(a),row(b)])
    with pytest.raises(ValueError):
        compare_replays(f,replay(f,[row(a),row(b)],"baseline"),candidate.model_copy(update={"fixture_sha256":"0"*64}))
    altered=row(a).model_copy(update={"input_sha256":"0"*64})
    with pytest.raises(ValueError):compare_replays(f,replay(f,[row(a),row(b)],"baseline"),replay(f,[altered,row(b)]))


def test_incomplete_baseline_and_extra_candidate_ids_are_rejected():
    f=fixtures();a,b=f.cases
    with pytest.raises(ValueError):compare_replays(f,replay(f,[row(a)],"baseline"),replay(f,[row(a),row(b)]))
    with pytest.raises(ValueError):compare_replays(f,replay(f,[row(a),row(b)],"baseline"),replay(f,[row(a),row(b),row(case("extraneous"))]))


def test_strict_outcome_and_route_contracts_forbid_coercions_and_extra_fields():
    c=case("a")
    with pytest.raises(ValidationError):ReplayRecord.model_validate({**row(c).model_dump(),"canonical_value":True})
    with pytest.raises(ValidationError):ReplayRecord.model_validate({**row(c).model_dump(),"extra_claim":"perfect"})
    with pytest.raises(ValidationError):ReplayRecord.model_validate({**row(c).model_dump(),"decision":"abstain"})
    with pytest.raises(ValidationError):LabeledCase(case_id="a",track_id="read_files",input_sha256="a"*64,truth="unknown",expected_canonical="answer")
    with pytest.raises(ValidationError):TaskRoute(task_id="task",route_id="route",mechanism="model_proposal",implementation_sha256="a"*64)


def test_mutating_a_validated_list_does_not_bypass_comparison_validation():
    f=fixtures();a,b=f.cases
    before=replay(f,[row(a),row(b)],"baseline");after=replay(f,[row(a),row(b)])
    after.records.append(row(a))
    with pytest.raises(ValidationError):compare_replays(f,before,after)


def test_replay_results_and_denominators_are_order_deterministic():
    f=fixtures();a,b=f.cases
    before=replay(f,[row(a),row(b)],"baseline")
    first=compare_replays(f,before,replay(f,[row(a),row(b,"wrong")])).model_dump(mode="json")
    second=compare_replays(f,before,replay(f,[row(b,"wrong"),row(a)])).model_dump(mode="json")
    assert first==second
