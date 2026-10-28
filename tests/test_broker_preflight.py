import json
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from meta_pipeline.broker_preflight import inspect_broker
from meta_pipeline.broker_runtime import BrokerConfig
from meta_pipeline.gateway import GatewayConfig
from meta_pipeline.model_routing import BindingRegistry


class MetadataOnlySource:
    def __init__(self, available): self.present = available
    def available(self): return self.present
    def load(self): raise AssertionError('preflight must not read bootstrap values')


def run(*, present=False, rows=(), enabled=False, request=None, **kwargs):
    return inspect_broker(gateway_config=GatewayConfig(base_url='https://bifrost.local/openai',
        allowed_hosts=['bifrost.local']), broker_config=BrokerConfig(tenant='tenant', enabled=enabled,
        secret_bindings=list(rows)), registry=BindingRegistry(approved_handlers=()),
        token_source=MetadataOnlySource(present), request=request, **kwargs)


def binding(**changes):
    return dict(binding_id='worker', reference='op://fixture-vault/fixture-item/credential',
                purpose='gateway_virtual_key', gateway_id='bifrost', tenant='tenant',
                scope_verified=True, **changes)


def test_missing_prerequisites_reported_without_reading_secrets_or_authenticating():
    with patch('meta_pipeline.broker_preflight.metadata.version', return_value='0.4.2'):
        result = run()
    assert result['status'] == 'blocked'
    assert {'runtime_enabled', 'bootstrap_metadata_available', 'scoped_worker_binding_configured'} <= set(result['blockers'])
    assert not result['sdk_authentication_attempted'] and not result['state_written']
    assert not result['secret_values_read'] and not result['provider_requests_made']


def test_metadata_is_not_production_acceptance_and_output_contains_no_references():
    with patch('meta_pipeline.broker_preflight.metadata.version', return_value='0.4.2'):
        result = run(present=True, rows=[binding()], enabled=True)
    assert result['status'] == 'configuration_ready_unverified'
    assert result['production_acceptance'] == 'unverified' and result['spend_admission'] is False
    assert 'fixture-vault' not in json.dumps(result) and 'fixture-item' not in json.dumps(result)


@pytest.mark.parametrize('change', [{'purpose':'provider_upstream'}, {'scope_verified':False},
                                  {'tenant':'other'}, {'gateway_id':'other'}])
def test_wrong_scope_is_not_accepted(change):
    row=binding();row.update(change)
    result=run(present=True, rows=[row], enabled=True)
    assert 'scoped_worker_binding_configured' in result['blockers']


def test_mismatched_route_credential_does_not_inherit_an_unrelated_worker_binding():
    class Selector:
        def __init__(self,*a,**kw):pass
        def select(self,*a,**kw):return SimpleNamespace(credential_binding_id='unrelated')
    with patch('meta_pipeline.broker_preflight.RouteSelector',Selector):
        result=run(present=True,rows=[binding()],enabled=True,request=object())
    assert result['checks']['request_has_eligible_route']
    assert not result['checks']['selected_route_has_scoped_worker_binding']


def test_wrong_sdk_version_blocks_metadata_readiness():
    with patch('meta_pipeline.broker_preflight.metadata.version', return_value='0.0.0'):
        result=run(present=True,rows=[binding()],enabled=True)
    assert 'official_sdk_version_available' in result['blockers']


@pytest.mark.parametrize('amount',[-1,True,1.5])
def test_forecast_budget_must_be_explicit_nonnegative_integer(amount):
    with pytest.raises(ValueError):run(remaining_nusd=amount)


def test_cli_preflight_blocks_without_creating_state(tmp_path, monkeypatch, capsys):
    from meta_pipeline.cli import main
    gateway=tmp_path/'gateway.json'
    gateway.write_text(json.dumps({'base_url':'https://bifrost.local/openai','allowed_hosts':['bifrost.local']}))
    config=tmp_path/'broker.json';config.write_text(json.dumps({'tenant':'fixture','enabled':False}))
    bindings=tmp_path/'bindings.json';bindings.write_text(json.dumps({'version':'bindings-v1','bindings':[]}))
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr('sys.argv',['meta-pipeline','--config',str(gateway),'broker-preflight',str(bindings),'--broker-config',str(config)])
    assert main()==2
    result=json.loads(capsys.readouterr().out)
    assert result['status']=='blocked' and not result['state_written']
    assert not (tmp_path/'state').exists()
