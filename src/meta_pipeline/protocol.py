"""Versioned 13-channel engineering contract, not a physical spacetime model.

Nine corpus partitions describe reference data. Four control channels describe
causal progress, candidate branches, forecasts and coordinator decisions.
"""
import hashlib
import json
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

FAMILIES = ('standalone_terminal', 'search', 'pattern_builders', 'response_filters',
            'read_files', 'hooks', 'cost_routes', 'write_update', 'parallel_tmux')
CODONS = ('SSS', 'SST', 'SSA', 'SAM', 'STM', 'SMM', 'ASS', 'AST', 'ASM',
          'TSS', 'TTM', 'TAM', 'MMM')
CONTROLS = ('causal_sequence', 'alternative_plans', 'forecast', 'coordination')
SYMBOLS = 'STAM'
PROTOCOL_ID = 'diatonic-13-v1'
AGENT_CONTEXT = ('Use typed task inputs and registered tools only. Output is a proposal, not proof. '
                 'Abstain on unknown inputs, missing evidence or ambiguous meaning. '
                 'Forecasts are estimates; candidate branches grant no execution authority.')


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                      allow_nan=False).encode()


def pack_codons(codons):
    if len(codons) != 13 or any(not isinstance(c, str) or len(c) != 3 or
                              any(s not in SYMBOLS for s in c) for c in codons):
        raise ValueError('Expected thirteen three-symbol STAM codons')
    value = 0
    for codon in codons:
        for symbol in codon:
            value = (value << 2) | SYMBOLS.index(symbol)
    return value.to_bytes(10, 'big')


def unpack_codons(frame):
    if not isinstance(frame, bytes) or len(frame) != 10 or frame[0] & 0xC0:
        raise ValueError('Expected 78 opcode bits with two zero high padding bits')
    value = int.from_bytes(frame, 'big')
    symbols = ''.join(SYMBOLS[(value >> shift) & 3] for shift in range(76, -1, -2))
    return tuple(symbols[i:i+3] for i in range(0, 39, 3))


def document():
    return {'id': PROTOCOL_ID, 'version': 1,
            'channels': [{'track': i+1, 'name': name, 'codon': CODONS[i],
                          'kind': 'reference_partition' if i < 9 else 'control',
                          'record_count': 900 if i < 9 else None}
                         for i, name in enumerate(FAMILIES+CONTROLS)],
            'records': 8100, 'control_tracks_are_recipe_partitions': False,
            'opcode_bits': 78, 'opcode_storage_bytes': 10,
            'frame_scope': 'opcode symbols only; arguments, identity, policy, evidence and state are separate',
            'encoding_is_proof': False, 'future_observations_available': False,
            'authority': 'coordinator-bound policy plus downstream native control plane',
            'model_role': 'bounded canonicalizer/proposer; never its own verifier',
            'abstain_stages': ['route', 'translation', 'validation', 'handler'],
            'formal_verification': 'not implemented; schema checks and finite tests are not Lean proofs'}


def digest():
    return hashlib.sha256(canonical(document())).hexdigest()


def reference_track(category):
    if category not in FAMILIES:
        raise ValueError('Unknown corpus family')
    return FAMILIES.index(category)+1


class ContractModel(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True, frozen=True)


class ForecastCell(ContractModel):
    as_of_tick: int = Field(ge=0)
    latest_observation_tick: int = Field(ge=0)
    horizon_steps: int = Field(ge=1, le=1000000)
    metric: str = Field(pattern=r'^[a-z_]{1,64}$')
    unit: Literal['bytes', 'seconds', 'tokens', 'nano_usd', 'bytes_per_second']
    lower: float = Field(ge=0, allow_inf_nan=False)
    expected: float = Field(ge=0, allow_inf_nan=False)
    upper: float = Field(ge=0, allow_inf_nan=False)
    basis_refs: list[str] = Field(min_length=1, max_length=16)

    @model_validator(mode='after')
    def ordered(self):
        if self.latest_observation_tick > self.as_of_tick:
            raise ValueError('Forecast cannot observe future causal events')
        if not self.lower <= self.expected <= self.upper:
            raise ValueError('Forecast bounds do not bracket estimate')
        return self

    def validate_snapshot(self, head_tick, known_refs):
        if self.as_of_tick != head_tick or not set(self.basis_refs) <= set(known_refs):
            raise ValueError('Forecast must bind to the admitted snapshot and known observations')
        return self


class AgentProposal(ContractModel):
    """Model-writable surface: no verified/success status or authority fields."""
    protocol: Literal['diatonic-13-v1']
    track: int = Field(ge=1, le=13)
    task: Literal['assess_evidence', 'inspect_evidence', 'search_reference', 'deploy_workflow', 'spawn_cell']
    input_digest: str = Field(pattern=r'^[0-9a-f]{64}$')
    evidence_refs: list[str] = Field(max_length=32)
    outcome: Literal['proposal', 'abstain']
    reason: str = Field(max_length=256)


class Abstain(ContractModel):
    status: Literal['abstain'] = 'abstain'
    stage: Literal['route', 'translation', 'validation', 'handler']
    reason: Literal['no_route', 'ambiguous_route', 'unknown_input', 'schema_rejected',
                    'missing_evidence', 'unbound_handler', 'handler_declined', 'handler_failed']
    answer: None = None


class EventEnvelope(ContractModel):
    protocol: Literal['diatonic-13-v1'] = PROTOCOL_ID
    track: int = Field(ge=1, le=13)
    tick: int = Field(ge=1)
    previous_event_hash: str = Field(pattern=r'^[0-9a-f]{64}$')
    payload_sha256: str = Field(pattern=r'^[0-9a-f]{64}$')
    contract_sha256: str = Field(pattern=r'^[0-9a-f]{64}$')
    status: Literal['observed', 'unresolved']


def event_envelope(kind, detail, tick, previous):
    # Telemetry classification does not infer permission, success, or NAS health.
    track = 12 if 'forecast' in kind else 11 if kind.startswith(('workflow.deploy', 'spawn.')) else (
        13 if any(s in kind for s in ('authorized', 'denied', 'policy', 'admission', 'delegation')) else 10)
    return EventEnvelope(track=track, tick=tick, previous_event_hash=previous,
                         payload_sha256=hashlib.sha256(canonical(detail)).hexdigest(),
                         contract_sha256=digest(),
                         status='unresolved' if any(s in kind for s in ('unresolved', 'failed', 'denied')) else 'observed')


def schemas():
    return {'contract': document(), 'contract_sha256': digest(),
            'opcode_frame_hex': pack_codons(CODONS).hex(),
            'agent_proposal': AgentProposal.model_json_schema(),
            'forecast': ForecastCell.model_json_schema(), 'abstain': Abstain.model_json_schema(),
            'event': EventEnvelope.model_json_schema()}


def check_canonical_call(tools, name, raw):
    """Check one SDK-owned task/schema/handler binding; never invoke it here.

    Schema acceptance proves neither intent preservation nor postconditions.
    Tool permissions and effects remain the SDK guardrail/native API's job.
    """
    from jsonschema import Draft202012Validator, ValidationError
    matched = [tool for tool in tools if tool.name == name]
    if len(matched) != 1:
        return Abstain(stage='route', reason='ambiguous_route' if matched else 'no_route')
    if not isinstance(raw, str) or len(raw.encode()) > 16384:
        return Abstain(stage='translation', reason='unknown_input')
    def unique(pairs):
        out = {}
        for key, value in pairs:
            if key in out:
                raise ValueError('Duplicate canonical field')
            out[key] = value
        return out
    try:
        data = json.loads(raw, object_pairs_hook=unique,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Nonfinite JSON')))
        Draft202012Validator(matched[0].params_json_schema).validate(data)
    except (ValueError, ValidationError, RecursionError):
        return Abstain(stage='validation', reason='schema_rejected')
    return {'status': 'canonical_schema_checked', 'task': name,
            'schema_sha256': hashlib.sha256(canonical(matched[0].params_json_schema)).hexdigest(),
            'arguments_sha256': hashlib.sha256(canonical(data)).hexdigest(),
            'semantic_fidelity': 'requires independent comparison to original task',
            'execution_verified': False}


def measure_forecast(forecast, *, actual, observation_tick, observation_ref, known_refs):
    """Score an admitted forecast against a later observation, never its own output."""
    import math
    if type(actual) not in (int,float) or not math.isfinite(actual) or actual < 0:
        raise ValueError('A finite measured quantity is required')
    if type(observation_tick) is not int or observation_tick < forecast.as_of_tick+forecast.horizon_steps:
        raise ValueError('Observation predates the forecast horizon')
    if observation_ref not in known_refs or observation_ref in forecast.basis_refs:
        raise ValueError('A distinct authoritative later observation is required')
    error = actual-forecast.expected
    return {'forecast_sha256':hashlib.sha256(canonical(forecast.model_dump())).hexdigest(),
            'observation_ref':observation_ref,'observation_tick':observation_tick,'unit':forecast.unit,
            'actual':actual,'signed_error':error,'absolute_error':abs(error),
            'relative_absolute_error':abs(error)/actual if actual else None,
            'inside_declared_bounds':forecast.lower<=actual<=forecast.upper,
            'scope':'one supplied observation; no population calibration or optimality proved'}
