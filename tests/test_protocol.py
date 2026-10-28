import hashlib
import json
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from meta_pipeline.audit import Audit
from meta_pipeline.protocol import (CODONS, SYMBOLS, AgentProposal, Abstain, ForecastCell,
    check_canonical_call, document, pack_codons, reference_track, unpack_codons,measure_forecast)


def test_opcode_roundtrip_each_value_at_each_position_and_padding():
    assert len(pack_codons(CODONS)) == 10 and unpack_codons(pack_codons(CODONS)) == CODONS
    for position in range(13):
        for value in range(64):
            codon = ''.join(SYMBOLS[(value >> shift) & 3] for shift in (4, 2, 0))
            variant = list(CODONS);variant[position] = codon
            assert unpack_codons(pack_codons(variant)) == tuple(variant)
    with pytest.raises(ValueError): unpack_codons(b'\xc0'+b'\0'*9)
    with pytest.raises(ValueError): pack_codons(['SSS']*12)
    with pytest.raises(ValueError): pack_codons(['XXX']*13)


def test_tracks_do_not_invent_records_or_physical_guarantees():
    d = document()
    assert len(d['channels']) == 13 and d['records'] == 8100
    assert sum(c['record_count'] or 0 for c in d['channels']) == 8100
    assert [c['kind'] for c in d['channels'][9:]] == ['control']*4
    assert not d['encoding_is_proof'] and not d['future_observations_available']
    assert reference_track('search') == 2
    with pytest.raises(ValueError): reference_track('quantum_future')


def test_forecast_must_use_known_admitted_snapshot_without_future_leakage():
    values = dict(as_of_tick=10, latest_observation_tick=9, horizon_steps=2,
                  metric='staging_bytes', unit='bytes', lower=1., expected=2., upper=3., basis_refs=['measured-1'])
    forecast = ForecastCell(**values)
    assert forecast.validate_snapshot(10, {'measured-1'}) is forecast
    with pytest.raises(ValueError): forecast.validate_snapshot(9, {'measured-1'})
    with pytest.raises(ValueError): forecast.validate_snapshot(10, set())
    with pytest.raises(ValidationError): ForecastCell(**{**values, 'latest_observation_tick': 11})
    with pytest.raises(ValidationError): ForecastCell(**{**values, 'lower': 4.})
    with pytest.raises(ValidationError): ForecastCell(**{**values, 'expected': float('nan')})
    measured=measure_forecast(forecast,actual=4.,observation_tick=12,observation_ref='measured-2',known_refs={'measured-2'})
    assert measured['absolute_error']==2. and not measured['inside_declared_bounds']
    assert measure_forecast(forecast,actual=0.,observation_tick=12,observation_ref='m2',known_refs={'m2'})['relative_absolute_error']is None
    with pytest.raises(ValueError):measure_forecast(forecast,actual=4.,observation_tick=11,observation_ref='m2',known_refs={'m2'})
    with pytest.raises(ValueError):measure_forecast(forecast,actual=4.,observation_tick=12,observation_ref='measured-1',known_refs={'measured-1'})


def test_model_can_propose_or_abstain_but_not_self_attest_or_grant_permissions():
    proposal = dict(protocol='diatonic-13-v1', track=11, task='spawn_cell', input_digest='a'*64,
                    evidence_refs=[], outcome='proposal', reason='bounded candidate')
    assert AgentProposal(**proposal).outcome == 'proposal'
    for change in [{'outcome': 'verified'}, {'permissions': ['root']}, {'shell': 'delete'}]:
        with pytest.raises(ValidationError): AgentProposal(**{**proposal, **change})


def test_one_task_one_schema_binding_and_abstain_on_unknown_or_duplicate_fields():
    tool = SimpleNamespace(name='inspect_evidence', params_json_schema={
        'type': 'object', 'properties': {'mode': {'enum': ['read']}},
        'required': ['mode'], 'additionalProperties': False})
    result = check_canonical_call([tool], 'inspect_evidence', '{"mode":"read"}')
    assert result['status'] == 'canonical_schema_checked' and not result['execution_verified']
    for raw in ['{"mode":"delete"}', '{"mode":"read","mode":"delete"}', 'NaN', '{}']:
        assert isinstance(check_canonical_call([tool], 'inspect_evidence', raw), Abstain)
    assert check_canonical_call([], 'x', '{}').reason == 'no_route'
    assert check_canonical_call([tool, tool], 'inspect_evidence', '{}').reason == 'ambiguous_route'


def test_concurrent_events_have_causal_contracts_and_payload_bindings(tmp_path):
    audit = Audit(tmp_path/'events')
    def emit(n):return audit.emit('run', 'agent-'+str(n), 'observation', {'n': n})
    with ThreadPoolExecutor(max_workers=4) as pool: list(pool.map(emit, range(24)))
    events = audit.events()
    for event in events:
        detail = dict(event['detail']);contract = detail.pop('_communication')
        assert contract['tick'] == event['seq']
        assert contract['previous_event_hash'] == event['previous_hash']
        canonical = json.dumps(detail,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
        assert contract['payload_sha256'] == hashlib.sha256(canonical).hexdigest()
    assert audit.verify()['contract_events'] == 24
    with pytest.raises(ValueError): audit.emit('r','a','fake',{'_communication': {}})
