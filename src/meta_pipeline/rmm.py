"""Provenance-bearing projection of the existing RMM's native observations.

No host enrollment, credentials, policy changes or production action transport.
Missing/stale telemetry is unknown. Fixture remediation is bound through the
existing scheduling ActivityBackend; native RMM execution remains pending.
"""
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from .execution import ContractBinding, Verification, sha


class Record(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class Observation(Record):
    asset_id: str = Field(min_length=1, max_length=128)
    provider: Literal["native_rmm", "fixture"]
    source_ref: str = Field(min_length=1, max_length=2048)
    observed_at: float = Field(ge=0, allow_inf_nan=False)
    version: str = Field(min_length=1, max_length=128)
    health: Literal["up", "down", "unknown"]
    values: dict[str, str] = Field(max_length=64)


class DesiredState(Record):
    asset_id: str
    policy_version: str
    values: dict[str, str] = Field(max_length=64)


class Remediation(Record):
    asset_id: str
    observation_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    observed_version: str
    desired_policy_version: str
    proposed: dict[str, str]
    status: Literal["proposed", "unknown", "no_drift"]
    source_ref: str
    reason: str


def plan_remediation(observation: Observation | None, desired: DesiredState,
                     *, now: float | None = None, maximum_age: float = 60) -> Remediation:
    now = time.time() if now is None else now
    if maximum_age <= 0:
        raise ValueError("Positive freshness bound required")
    if observation and observation.asset_id != desired.asset_id:
        raise ValueError("Observed and desired asset identities differ")
    unknown = (observation is None or observation.health == "unknown"
               or not 0 <= now - observation.observed_at <= maximum_age)
    if unknown:
        return Remediation(asset_id=desired.asset_id,
            observation_sha256=sha(observation.model_dump()) if observation else "0"*64,
            observed_version=observation.version if observation else "unknown",
            desired_policy_version=desired.policy_version, proposed={}, status="unknown",
            source_ref=observation.source_ref if observation else "missing",
            reason="Missing, stale, future or unknown telemetry; refresh native observation")
    proposed = {key: value for key, value in desired.values.items() if observation.values.get(key) != value}
    return Remediation(asset_id=desired.asset_id, observation_sha256=sha(observation.model_dump()),
        observed_version=observation.version, desired_policy_version=desired.policy_version,
        proposed=proposed, status="proposed" if proposed else "no_drift",
        source_ref=observation.source_ref, reason="Observed drift; execution requires separate task-specific authorization" if proposed else "Observed desired values match")


class RMMProjection:
    """Read-only view; callers fetch through existing authenticated RMM API."""
    def __init__(self, *, source_ref: str):
        self.source_ref = source_ref

    def ingest_wall(self, payload: dict) -> list[Observation]:
        # Reuse deployed RMM's resource fields rather than accepting commands or
        # treating its controllable=False inventory as an execution grant.
        utc = payload.get("utc")
        if type(utc) not in (float, int) or not 0 <= utc < float("inf"):
            raise ValueError("Native observation timestamp required")
        if payload.get("allowed_actions") or payload.get("allowed_guests"):
            raise ValueError("Observer projection cannot carry execution grants")
        rows = []
        for group in ("resources", "guests", "metals"):
            values = payload.get(group, [])
            if not isinstance(values, list) or len(values) > 256:
                raise ValueError("Bounded native inventory required")
            for item in values:
                if not isinstance(item, dict) or not isinstance(item.get("id"), str):
                    raise ValueError("Native resource identity required")
                status = item.get("status")
                if status is not None and not isinstance(status, str):
                    raise ValueError("Native status must be a string or unknown")
                health = "up" if status in {"online", "running", "up"} else "down" if status in {"offline", "stopped", "down"} else "unknown"
                observed = {k: str(item[k]) for k in ("status", "role", "node", "type") if k in item}
                rows.append(Observation(asset_id=item["id"], provider="native_rmm",
                    source_ref=self.source_ref, observed_at=float(utc), version=sha(item),
                    health=health, values=observed))
        return rows


class FixtureAction(Record):
    proposal: Remediation
    request_id: str = Field(min_length=1, max_length=128)


class FixtureActionResult(Record):
    request_id: str
    asset_id: str
    before_sha256: str
    after_sha256: str
    version: str
    scope: Literal["disposable_fixture"] = "disposable_fixture"


class FixtureRMMAdapter:
    """An explicitly supplied fixture file, no arbitrary host or shell interface."""
    def __init__(self, state_file: Path, *, asset_id: str,
                 allowed_values: dict[str, frozenset[str]], policy_version: str):
        self.path = Path(state_file)
        self.asset_id, self.allowed_values, self.policy_version = asset_id, allowed_values, policy_version
        if self.path.is_symlink() or not self.path.is_file():
            raise ValueError("Existing disposable fixture state file required")
        self.path = self.path.resolve()

    def observe(self) -> Observation:
        import os
        import stat
        fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > 262144:
                raise ValueError("Bounded regular fixture state required")
            raw = stream.read(262145)
        if len(raw) > 262144:
            raise ValueError("Fixture state grew beyond bound")
        body = json.loads(raw)
        return Observation(asset_id=self.asset_id, provider="fixture", source_ref="fixture:"+str(self.path),
                           observed_at=time.time(), version=hashlib.sha256(raw).hexdigest(),
                           health="up", values=body)

    def execute(self, action: FixtureAction):
        p = action.proposal
        current = self.observe()
        if (p.status != "proposed" or p.asset_id != self.asset_id
                or p.observed_version != current.version
                or p.desired_policy_version != self.policy_version
                or p.source_ref != current.source_ref):
            raise PermissionError("Stale, unbound or unauthorized fixture proposal")
        # Timestamp changes on refresh; proposal digest must bind its exact native
        # observation. Source/version checks guard the live fixture precondition.
        if not p.proposed or any(k not in self.allowed_values or v not in self.allowed_values[k]
                                  for k, v in p.proposed.items()):
            raise PermissionError("Fixture remediation exceeds trusted authorization")
        result = {**current.values, **p.proposed}
        raw = json.dumps(result, sort_keys=True, separators=(",", ":")).encode()
        import os
        temporary = self.path.with_name(self.path.name + "." + hashlib.sha256(action.request_id.encode()).hexdigest() + ".pending")
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        # Recheck precondition immediately before committing the fixture change.
        if self.observe().version != current.version:
            raise RuntimeError("Fixture state changed during remediation; pending file retained")
        os.replace(temporary, self.path)
        directory_fd = os.open(self.path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        return FixtureActionResult(request_id=action.request_id, asset_id=self.asset_id,
                                   before_sha256=current.version, after_sha256=hashlib.sha256(raw).hexdigest(),
                                   version="fixture-rmm-v1")

    def verify(self, action: FixtureAction, result: FixtureActionResult):
        current = self.observe()
        valid = (result.request_id == action.request_id and result.asset_id == self.asset_id
                 and current.version == result.after_sha256
                 and all(current.values.get(k) == v for k, v in action.proposal.proposed.items()))
        return Verification(verified=valid, evidence_refs=["fixture-state:"+current.version],
                            reason="Independent post-action fixture observation" if valid else "Post-action fixture mismatch")

    def binding(self):
        return ContractBinding(task="fixture_rmm_remediate", stage_kind="proof_review",
            handler_version="fixture-rmm-v1", input_model=FixtureAction, output_model=FixtureActionResult,
            handler=self.execute, verifier=self.verify,
            fidelity=lambda original, data: original == json.dumps(data.model_dump(mode="json"), sort_keys=True),
            effects=("disposable_fixture_config_write",), requirements=("fixture_rmm_authorized",),
            exclusion="fixture-rmm:"+str(self.path))
