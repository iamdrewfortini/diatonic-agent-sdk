import json
import time

import pytest

from meta_pipeline.audit import Audit
from meta_pipeline.execution import ContractRegistry, FixturePolicy, LocalFixtureBackend
from meta_pipeline.rmm import (DesiredState, FixtureAction, FixtureRMMAdapter,
                               RMMProjection, plan_remediation)
from meta_pipeline.scheduling import Activities
from test_execution_integration import request


def adapter(tmp_path):
    state = tmp_path / "disposable-host.json"
    state.write_text(json.dumps({"service": "stopped", "unrelated": "retained"}))
    return FixtureRMMAdapter(state, asset_id="fixture:host", allowed_values={"service": frozenset({"running"})}, policy_version="policy-v1")


def test_unknown_telemetry_never_means_failure_or_remediation(tmp_path):
    a = adapter(tmp_path)
    desired = DesiredState(asset_id="fixture:host", policy_version="policy-v1", values={"service": "running"})
    assert plan_remediation(None, desired).status == "unknown"
    observation = a.observe()
    assert plan_remediation(observation, desired, now=observation.observed_at+61).status == "unknown"
    assert plan_remediation(observation, desired, now=observation.observed_at-1).status == "unknown"
    with pytest.raises(ValueError):
        plan_remediation(observation, desired.model_copy(update={"asset_id": "another"}))


@pytest.mark.asyncio
async def test_drift_proposed_authorized_activity_effect_independent_verification(tmp_path):
    a = adapter(tmp_path)
    desired = DesiredState(asset_id="fixture:host", policy_version="policy-v1", values={"service": "running"})
    observation = a.observe()
    proposal = plan_remediation(observation, desired)
    assert proposal.status == "proposed"
    assert a.observe().version == observation.version
    action = FixtureAction(proposal=proposal, request_id="fixture-action")
    audit = Audit(tmp_path / "audit.db")
    registry = ContractRegistry(); registry.register(a.binding())
    req = request()
    backend = LocalFixtureBackend(audit, registry, [FixturePolicy("run", req.plan.policy_ref,
                        frozenset({"fixture_rmm_remediate"}), 100,
                        frozenset({"fixture_rmm_authorized"}))])
    backend.derive(req, task="fixture_rmm_remediate", original_request=json.dumps(action.model_dump(mode="json"), sort_keys=True),
                   inputs=action.model_dump(mode="json"), correlation_id="rmm-drift")
    result = await Activities(backend).control(req)
    assert result.proven
    assert a.observe().values == {"service": "running", "unrelated": "retained"}
    assert plan_remediation(a.observe(), desired).status == "no_drift"
    assert await Activities(backend).control(req) == result
    assert audit.verify()["valid"]


def test_stale_proposal_and_unauthorized_value_rejected(tmp_path):
    a = adapter(tmp_path)
    desired = DesiredState(asset_id="fixture:host", policy_version="policy-v1", values={"service": "running"})
    proposal = plan_remediation(a.observe(), desired)
    a.path.write_text(json.dumps({"service": "changed"}))
    with pytest.raises(PermissionError, match="Stale"):
        a.execute(FixtureAction(proposal=proposal, request_id="stale"))
    malicious = plan_remediation(a.observe(), desired.model_copy(update={"values": {"command": "rm"}}))
    with pytest.raises(PermissionError, match="authorization"):
        a.execute(FixtureAction(proposal=malicious, request_id="unapproved"))


def test_native_projection_provenance_and_no_authority():
    body = {"utc": time.time(), "resources": [{"id": "vm/104", "status": "running"}],
            "metals": [{"id": "metal/02", "status": "unavailable"}], "guests": [],
            "allowed_actions": [], "allowed_guests": []}
    rows = RMMProjection(source_ref="rmm:authenticated-wall").ingest_wall(body)
    assert rows[0].provider == "native_rmm" and rows[0].health == "up"
    assert rows[1].health == "unknown"
    assert all(r.source_ref == "rmm:authenticated-wall" for r in rows)
    with pytest.raises(ValueError, match="grants"):
        RMMProjection(source_ref="rmm:wall").ingest_wall({**body, "allowed_actions": ["restart"]})
