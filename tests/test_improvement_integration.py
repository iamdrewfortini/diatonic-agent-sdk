import hashlib
import json
from pathlib import Path

import pytest

from meta_pipeline.audit import Audit
from meta_pipeline.improvement import LocalPromotionController, TrialMeasurements
from meta_pipeline.proof import Claim
from meta_pipeline.regression import FixtureSet, ReplaySet
from meta_pipeline.workflows import Workflow, WorkflowRegistry


EXAMPLES = Path(__file__).parents[1] / "examples"


def workflow(name):
    return Workflow(name=name, purpose="Bounded fixture policy candidate", cells=[{
        "id": "verify", "kind": "proof_review", "instructions": name, "depends_on": []}])


def replay_fixture(tag="holdout", wrong=False):
    original = json.loads((EXAMPLES / "contract-fixtures.json").read_text())
    original["name"] = tag
    fixtures = FixtureSet.seal(name=tag,
        provenance=FixtureSet.model_validate(json.loads((EXAMPLES / "contract-fixtures.json").read_text())).provenance,
        cases=FixtureSet.model_validate(json.loads((EXAMPLES / "contract-fixtures.json").read_text())).cases)
    base = json.loads((EXAMPLES / "contract-baseline.json").read_text())
    after = json.loads((EXAMPLES / ("contract-regressed.json" if wrong else "contract-candidate.json")).read_text())
    base["fixture_sha256"] = after["fixture_sha256"] = fixtures.fixture_sha256
    return fixtures, ReplaySet.model_validate(base), ReplaySet.model_validate(after)


def setup(tmp_path, **kwargs):
    audit = Audit(tmp_path / "audit.db")
    registry = WorkflowRegistry(tmp_path / "definitions", audit)
    # Independent fixed gate in this disposable test checks complete metric
    # evidence; production must bind its real verifier, not this fixture lambda.
    def gate(candidate, evidence, baseline, replay):
        return evidence == {"verified": True} if isinstance(candidate, str) else True
    claim = Claim(id="throughput-v1", property="Higher verified fixture job throughput", scope="sealed fixture jobs", metric="jobs_per_second", direction="at_least", threshold=2.0)
    controller = LocalPromotionController(registry, claim=claim, authorized_runs=frozenset({"run"}),
        trusted_gate=gate, development_fixture_sha256="d"*64,
        maximum_total_cost_nusd=10, maximum_total_seconds=10, **kwargs)
    incumbent = workflow("incumbent")
    controller.initialize("run", incumbent)
    return controller, incumbent


def evaluate(controller, incumbent, candidate, *, wrong=False, tag="holdout", measured=None):
    fixtures, before, after = replay_fixture(tag, wrong)
    return controller.evaluate("run", incumbent_digest=incumbent.digest, candidate=candidate,
        heldout=fixtures, baseline=before, replay=after,
        measured=measured or TrialMeasurements(1.0, 3.0, 1.0, 0, 0))


def test_accept_canary_duplicate_stale_and_rollback_use_real_workflow_registry(tmp_path):
    c, incumbent = setup(tmp_path)
    candidate = workflow("candidate")
    trial = evaluate(c, incumbent, candidate)
    assert trial["eligible"]
    state = c.promote("run", attempt=trial["attempt"], candidate=candidate, incumbent_digest=incumbent.digest)
    assert state["active"] == candidate.digest and state["rollback"] == incumbent.digest
    assert (c.registry.root / (candidate.digest + ".json")).is_file()
    with pytest.raises(ValueError, match="duplicate"):
        c.promote("run", attempt=trial["attempt"], candidate=candidate, incumbent_digest=incumbent.digest)
    with pytest.raises(ValueError, match="Stale"):
        c.observe_canary("run", expected_digest=incumbent.digest, evidence={"verified": True})
    state = c.observe_canary("run", expected_digest=candidate.digest, evidence={"verified": False})
    assert state["active"] == incumbent.digest and state["state"] == "rolled_back"
    assert c.audit.verify()["valid"]


def test_reject_regression_even_if_throughput_improves_preserve_trial_cost_retries(tmp_path):
    c, incumbent = setup(tmp_path)
    candidate = workflow("regressed")
    trial = evaluate(c, incumbent, candidate, wrong=True, measured=TrialMeasurements(1.0, 9.0, 2.0, 4, 2, payload_bits=512))
    assert not trial["eligible"]
    assert trial["comparison"]["status"] == "LOST_CORRECT"
    assert trial["measured"]["cost_nusd"] == 4 and trial["measured"]["retries"] == 2
    with pytest.raises(ValueError, match="Ineligible"):
        c.promote("run", attempt=trial["attempt"], candidate=candidate, incumbent_digest=incumbent.digest)
    with pytest.raises(ValueError, match="Heldout already consumed"):
        evaluate(c, incumbent, workflow("changed"))
    assert c.state("run")["active"] == incumbent.digest
    with c.audit.connect() as db:
        assert db.execute("SELECT COUNT(*) FROM promotion_trials").fetchone()[0] == 1


def test_no_improvement_and_budget_exhaustion_are_preserved(tmp_path):
    c, incumbent = setup(tmp_path)
    no_gain = evaluate(c, incumbent, workflow("no-gain"), measured=TrialMeasurements(1.0, 1.0, 1.0, 2, 0))
    assert not no_gain["eligible"] and not no_gain["strict_improvement"]
    over_budget = evaluate(c, incumbent, workflow("expensive"), tag="fresh-holdout",
                           measured=TrialMeasurements(1.0, 3.0, 1.0, 9, 1))
    assert not over_budget["eligible"] and not over_budget["within_limits"]


def test_canary_success_and_authorization(tmp_path):
    c, incumbent = setup(tmp_path)
    candidate = workflow("candidate")
    t = evaluate(c, incumbent, candidate)
    c.promote("run", attempt=t["attempt"], candidate=candidate, incumbent_digest=incumbent.digest)
    assert c.observe_canary("run", expected_digest=candidate.digest, evidence={"verified": True})["state"] == "active"
    with pytest.raises(PermissionError):
        c.initialize("untrusted", workflow("other"))
    with pytest.raises(ValueError):
        evaluate(c, incumbent, workflow("stale"), tag="unconsumed")


def test_post_canary_monitoring_rolls_back_on_regression(tmp_path):
    c, incumbent = setup(tmp_path)
    candidate = workflow("candidate")
    t = evaluate(c, incumbent, candidate)
    c.promote("run", attempt=t["attempt"], candidate=candidate, incumbent_digest=incumbent.digest)
    assert c.observe_canary("run", expected_digest=candidate.digest, evidence={"verified": True})["state"] == "active"
    assert c.observe_canary("run", expected_digest=candidate.digest, evidence={"verified": False})["active"] == incumbent.digest


def test_claim_is_sealed_against_mutating_returned_model(tmp_path):
    c, incumbent = setup(tmp_path)
    external = c.claim
    external.threshold = 0.0
    external.maximum_experiments = 10
    assert c.claim.threshold == 2.0 and c.claim.maximum_experiments == 3


def test_duplicate_canary_evidence_cannot_consume_second_job(tmp_path):
    c, incumbent = setup(tmp_path, canary_jobs=2)
    candidate = workflow("candidate")
    t = evaluate(c, incumbent, candidate)
    c.promote("run", attempt=t["attempt"], candidate=candidate, incumbent_digest=incumbent.digest)
    assert c.observe_canary("run", expected_digest=candidate.digest, evidence={"verified": True})["remaining_canary"] == 1
    with pytest.raises(ValueError, match="Duplicate"):
        c.observe_canary("run", expected_digest=candidate.digest, evidence={"verified": True})
    assert c.state("run")["remaining_canary"] == 1 and c.state("run")["state"] == "canary"
