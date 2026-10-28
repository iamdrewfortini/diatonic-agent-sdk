import pytest
from pydantic import ValidationError
from meta_pipeline.provider_contracts import (BrokerRequest, BrokerMessage, BrokerUsage,
    BrokerResult, UsageBound, EndpointBinding, GeneBinding, REPORTED_CREDITS,
    ChatShapeAdapter, ResponsesShapeAdapter)
from meta_pipeline.protocol import CODONS

SHA = 'a'*64


def request(**changes):
    values = dict(task='classify', messages=(BrokerMessage(role='user',content='bounded fixture'),),
        capabilities=('classify',), max_output_tokens=16,
        usage_bounds=(UsageBound(unit='input_tokens',quantity=4096),UsageBound(unit='output_tokens',quantity=16)),
        original_request_sha256=SHA, correlation_id='correlation', root_run_id='root',
        flow_id='flow',flow_version='1',prompt_id='prompt',prompt_version='1')
    return BrokerRequest(**{**values,**changes})


def test_strict_immutable_provider_independent_request_and_usage():
    r = request(); assert r.digest == request().digest
    assert request(messages=(BrokerMessage(role='user',content='changed'),)).digest != r.digest
    for patch in [{'max_output_tokens':True}, {'permissions':['root']}, {'contract_version':'future'},
                  {'artifact_sha256s':('pathname',)}, {'usage_bounds':(UsageBound(unit='output_tokens',quantity=1),)}]:
        with pytest.raises(ValidationError): request(**patch)
    with pytest.raises(ValidationError): r.task='other'
    with pytest.raises(ValidationError): BrokerUsage(input_tokens=2,cached_tokens=3)
    assert BrokerUsage().cost_nusd is None
    with pytest.raises(ValidationError): BrokerResult(status='proposed',provider_id='any',model_id='any',request_sha256=SHA,reason='x',execution_verified=True)
    assert all(not c.spend_authority and c.status=='user_reported_unverified' for c in REPORTED_CREDITS)


@pytest.mark.parametrize('path',['https://evil/api','//evil/api','/%2f%2fevil','/%252e%252e/file','/../a','/a/./b','/ok?key=x','/ok#x','/a\\b'])
def test_endpoint_rejects_external_and_ambiguous_paths(path):
    with pytest.raises(ValidationError):
        EndpointBinding(id='endpoint',version='1',source_sha256=SHA,provider_id='any',gateway_id='bifrost',
            path=path,api_shape='chat-completions-v1',credential_binding_id='worker-key',evidence_ref='fixture')


def test_genes_cannot_change_track_contract_or_carry_code_or_grants():
    values=dict(id='inspect',version='1',source_sha256=SHA,track=5,codon=CODONS[4],
        handler_id='inspect',handler_version='1',input_schema_sha256=SHA,
        output_schema_sha256=SHA,effects=('read',),capabilities=('classify',),evidence_requirements=('source',))
    assert GeneBinding(**values).track==5
    for change in [{'codon':'MMM'},{'python':'eval(...)'},{'permissions':('root',)}]:
        with pytest.raises(ValidationError):GeneBinding(**{**values,**change})
