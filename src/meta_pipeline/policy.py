"""Versioned application contract used by upstream SDK tool guardrails.

Personas are instructions. Permissions come from coordinator-bound roles.
Native Rucio/FTS/Bifrost/Kubernetes policies remain authoritative downstream.
"""
import hashlib
import json
from dataclasses import dataclass
from types import MappingProxyType

ROLE_TOOLS=MappingProxyType({
    "assembler":frozenset({"inspect_evidence","deploy_workflow","spawn_cell","search_reference"}),
    "specialist":frozenset({"inspect_evidence"}),
    "verifier":frozenset(),
    "observer":frozenset(),
    "classifier":frozenset({"inspect_evidence"}),
    "planner":frozenset({"inspect_evidence","search_reference"}),
    "file-verifier":frozenset(),
    "native-operator":frozenset(), # native API effects require separate backend authority
})
ERROR_ACTIONS=MappingProxyType({
    "authentication":"block_until_identity_or_configuration_changes",
    "permission":"deny_and_record; never_switch_to_a_more_privileged_identity",
    "schema":"reject; request_a_changed_candidate_within_experiment_budget",
    "rate_limit":"wait_for_native_retry_after; reserve_before_any_new_attempt",
    "stale_evidence":"refresh_authoritative_observation; do_not_treat_missing_monitoring_as_asset_failure",
    "unknown_effect":"reconcile_native_job_or_rule_id_before_retrying",
    "capacity":"park_pending_work; do_not_stop_existing_jobs_or_lower_reserves",
    "context":"split_bounded_cells_or_compact_at_valid_replay_boundary",
    "cancelled":"record_pending_effects_as_unresolved; reconcile_before_resume",
})

@dataclass(frozen=True)
class Identity:
    tenant:str
    root_run:str
    role:str
    parent_agent:str|None
    workflow_digest:str
    policy_digest:str

class Policy:
    def __init__(self,tenant,root_run):
        if not tenant or not root_run:raise ValueError("Server-assigned tenant and root run required")
        self.tenant,self.root_run=tenant,root_run
        self.bindings={}

    @property
    def document(self):
        from .protocol import PROTOCOL_ID,digest
        return {"version":"1","roles":{k:sorted(v)for k,v in ROLE_TOOLS.items()},
            "communication_protocol":PROTOCOL_ID,"communication_contract_sha256":digest(),
            "root_budget_inherited":True,"maximum_spawns":4,"maximum_spawn_depth":2,
            "maximum_workflow_versions":8,"maximum_agent_turns":4,
            "filesystem_effect_tools":[],"error_actions":dict(ERROR_ACTIONS),
            "persona_grants_permissions":False,"native_control_planes":["Rucio","FTS","Bifrost","systemd"]}

    @property
    def digest(self):return hashlib.sha256(json.dumps(self.document,sort_keys=True,separators=(",",":")).encode()).hexdigest()

    def bind(self,agent,role,*,parent=None,workflow_digest="unversioned-input"):
        if role not in ROLE_TOOLS:raise ValueError("Unknown server-assigned role")
        if id(agent) in self.bindings:raise ValueError("Agent identity is already bound")
        identity=Identity(self.tenant,self.root_run,role,parent,workflow_digest,self.digest)
        self.bindings[id(agent)]=(agent,identity) # keep strong reference: no object-ID reuse
        return identity

    def authorize(self,agent,tool):
        pair=self.bindings.get(id(agent))
        if not pair or pair[0] is not agent:raise PermissionError("Unbound agent identity")
        identity=pair[1]
        if tool not in ROLE_TOOLS[identity.role]:raise PermissionError("Tool denied for server-assigned role")
        return {"allowed":True,"role":identity.role,"tenant":identity.tenant,"root_run":identity.root_run,
                "policy_digest":self.digest,"authorization_source":"coordinator-bound role; not model text"}

    def identity(self,agent):
        pair=self.bindings.get(id(agent))
        if not pair or pair[0]is not agent:raise PermissionError("Unbound agent identity")
        from dataclasses import asdict
        return asdict(pair[1])
