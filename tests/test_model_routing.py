from datetime import datetime, timezone
import pytest
from meta_pipeline.provider_contracts import (ProviderBinding,ModelBinding,EndpointBinding,SDKBinding,
    FlowBinding,PromptBinding,PricingBinding,UnitPrice,GeneBinding,BrokerUsage,UsageBound,
    ChatShapeAdapter,ResponsesShapeAdapter)
from meta_pipeline.model_routing import BindingRegistry,RouteSelector,SelectedRoute,RouteAbstention
from meta_pipeline.protocol import CODONS
from test_provider_contracts import request,SHA

NOW=datetime(2026,10,28,tzinfo=timezone.utc)


def registry(*, provider='arbitrary-provider', model='model-any-version', api_shape='chat-completions-v1', **model_changes):
    r=BindingRegistry(approved_handlers={('chat','1'),('flow','1'),('inspect','1')})
    bindings=[ProviderBinding(id=provider,version='1',source_sha256=SHA,gateway_id='bifrost',enabled=True,evidence_ref='fixture'),
      ModelBinding(id='model',version='1',source_sha256=SHA,provider_id=provider,model_id=model,
        wire_model=provider+'/'+model,capabilities=('classify',),endpoint_ids=('endpoint',),
        input_modalities=('text',),output_modalities=('text',),allowed_data_classes=('private',),
        context_limit=10000,entitlement_verified=True,evidence_ref='fixture',**model_changes),
      EndpointBinding(id='endpoint',version='1',source_sha256=SHA,provider_id=provider,gateway_id='bifrost',path='/openai/chat/completions',
        api_shape=api_shape,credential_binding_id='worker-key',verified=True,authentication_verified=True,evidence_ref='fixture'),
      SDKBinding(id='sdk',version='1',source_sha256=SHA,api_shape=api_shape,handler_id='chat',handler_version='1',verified=True),
      FlowBinding(id='flow',version='1',source_sha256=SHA,handler_id='flow',handler_version='1',sdk_ids=('sdk',),
        capabilities=('classify',),allowed_gene_ids=('inspect',)),
      PromptBinding(id='prompt',version='1',source_sha256=SHA,template='Approved bounded prompt'),
      PricingBinding(id='price',version='1',source_sha256=SHA,provider_id=provider,model_id=model,
        rates=(UnitPrice(unit='input_tokens',nusd=2),UnitPrice(unit='output_tokens',nusd=4)),verified=True,
        observed_at='2026-10-27T00:00:00+00:00',valid_until='2026-10-29T00:00:00+00:00',evidence_ref='fixture')]
    for b in bindings:r.register(b)
    return r


def selector(r):return RouteSelector(r,gateway_id='bifrost',now=lambda:NOW)


def test_any_registered_provider_and_model_deterministic_scope_and_budget():
    r=registry();s=selector(r);req=request();route=s.select(req,10000)
    assert isinstance(route,SelectedRoute) and route.provider_id=='arbitrary-provider'
    assert route.reserve_nusd==4096*2+16*4 and route==s.select(req,10000)
    assert route.request_sha256==req.digest and route.credential_binding_id=='worker-key'
    assert isinstance(s.select(req,0),RouteAbstention)
    for patch in [{'capabilities':('unknown',)},{'data_class':'restricted'},
                  {'input_modalities':('video',)},{'flow_version':'unknown'}]:
        assert isinstance(s.select(request(**patch),100000),RouteAbstention)
    with pytest.raises(ValueError):s.select(req,True)


def test_unverified_endpoint_entitlement_pricing_no_credit_fallback():
    for kind,patch in [(ModelBinding,{'entitlement_verified':False}),
                       (EndpointBinding,{'authentication_verified':False}),
                       (PricingBinding,{'verified':False})]:
        r=registry();current=r.active(kind)[0]
        replacement=current.model_copy(update={'version':'2',**patch})
        r.register(replacement);r.activate(kind,current.id,'2',expected_version='1')
        assert isinstance(selector(r).select(request(),1000000000),RouteAbstention)


def test_immutable_registration_activation_and_stale_prompt_flow_route():
    for kind in [PromptBinding,FlowBinding,ModelBinding,SDKBinding,EndpointBinding,PricingBinding]:
        r=registry();s=selector(r);req=request();route=s.select(req,10000)
        old=r.active(kind)[0]
        with pytest.raises(ValueError):r.register(old)
        r.register(old.model_copy(update={'version':'2'}))
        assert s.select(req,10000)==route
        with pytest.raises(ValueError):r.activate(kind,old.id,'2',expected_version='wrong')
        r.activate(kind,old.id,'2',expected_version='1')
        assert isinstance(s.validate(req,route,10000),RouteAbstention)
        assert r.get(kind,old.id,'1')==old
        with pytest.raises(ValueError):r.activate(kind,old.id,'2',expected_version='1')


def test_genetic_derivation_known_handler_schema_effect_bindings_not_authority():
    r=registry();gene=GeneBinding(id='inspect',version='1',source_sha256=SHA,track=5,codon=CODONS[4],
        handler_id='inspect',handler_version='1',input_schema_sha256=SHA,output_schema_sha256=SHA,
        effects=('read_metadata',),capabilities=('classify',),evidence_requirements=('source_version',))
    r.register(gene);plan=r.derive(request(),(('inspect','1'),))
    assert plan.request_sha256==request().digest and not plan.grants_authority
    assert plan.steps[0].handler_id=='inspect' and plan.steps[0].effects==('read_metadata',)
    assert plan.original_request_sha256==SHA and plan.independent_verification_required
    for genes in [(),(('unknown','1'),),(('inspect','1'),)*5]:
        assert isinstance(r.derive(request(),genes),RouteAbstention)
    with pytest.raises(ValueError):r.register(gene.model_copy(update={'id':'malicious','handler_id':'shell'}))
    r.register(gene.model_copy(update={'version':'2','input_schema_sha256':'b'*64}))
    assert isinstance(r.derive(request(),(('inspect','1'),('inspect','2'))),RouteAbstention)


def test_price_usage_uses_pinned_rates_unknown_is_unknown_and_expiry_checked():
    r=registry();route=selector(r).select(request(),10000)
    usage=BrokerUsage(input_tokens=10,output_tokens=5,cost_nusd=0)
    assert r.price_usage(route,usage,now=NOW)==40
    assert r.price_usage(route,BrokerUsage(cost_nusd=0),now=NOW) is None
    assert r.price_usage(route,usage,now=datetime(2026,10,30,tzinfo=timezone.utc)) is None
    assert r.price_usage(route,usage,now=datetime(2026,10,26,tzinfo=timezone.utc)) is None
    assert r.price_usage(route,usage.model_copy(update={'cache_state':'bifrost_direct'}),now=NOW)==40


def test_replaceable_shapes_preserve_prompts_identity_usage_and_proposal_boundary():
    req=request();r=registry();route=selector(r).select(req,10000);adapter=ChatShapeAdapter()
    payload=adapter.encode(req,route)
    assert payload['model']==route.wire_model and payload['messages'][0]['content']==route.prompt_template
    body={'model':route.model_id,'choices':[{'finish_reason':'stop','message':{'content':'answer'}}],
          'usage':{'prompt_tokens':20,'completion_tokens':3}}
    out=adapter.decode(body,{},req,route)
    assert out.status=='proposed' and out.usage.input_tokens==20 and not out.execution_verified
    assert out.usage.cost_nusd is None and out.request_sha256==req.digest
    assert adapter.decode({**body,'model':'other'}, {},req,route).status=='abstained'
    body['choices'][0]['finish_reason']='length'
    assert adapter.decode(body,{},req,route).status=='abstained'
    assert adapter.decode({'model':route.model_id,'choices':[]}, {},req,route).usage.input_tokens is None
    r=registry(api_shape='responses-v1');route=selector(r).select(req,10000);adapter=ResponsesShapeAdapter()
    assert adapter.encode(req,route)['store'] is False
    good={'model':route.model_id,'status':'completed','output':[{'type':'message','role':'assistant','content':[{'type':'output_text','text':'answer'}]}]}
    assert adapter.decode(good,{},req,route).status=='proposed'
    assert adapter.decode({**good,'status':'incomplete'},{},req,route).status=='abstained'
    good['output'].append({'type':'reasoning','encrypted_content':'opaque'})
    assert adapter.decode(good,{},req,route).status=='abstained'


def test_registry_revalidates_bypassed_models_and_derivation_unknowns_abstain():
    r=registry();endpoint=r.get(EndpointBinding,'endpoint')
    with pytest.raises(ValueError):r.register(endpoint.model_copy(update={'id':'unsafe','path':'//external'}))
    assert isinstance(r.derive(request(flow_version='missing'),(('inspect','1'),)),RouteAbstention)
    assert isinstance(r.derive(request(),None),RouteAbstention)
    assert isinstance(r.derive(request(),('malformed',)),RouteAbstention)


def test_shape_adapters_abstain_on_nonobject_and_malformed_usage():
    req=request();r=registry();route=selector(r).select(req,10000)
    for body in [[],None,{'model':route.model_id,'choices':[{'message':[],'finish_reason':'stop'}]}]:
        assert ChatShapeAdapter().decode(body,{},req,route).status=='abstained'
    body={'model':route.model_id,'choices':[{'message':{'content':'answer'},'finish_reason':'stop'}],
          'usage':{'prompt_tokens':True,'completion_tokens':-1}}
    out=ChatShapeAdapter().decode(body,{},req,route)
    assert out.usage.input_tokens is None and out.usage.output_tokens is None
    route=selector(registry(api_shape='responses-v1')).select(req,10000)
    assert ResponsesShapeAdapter().decode([],{},req,route).status=='abstained'


def test_training_optin_and_context_gate_are_independent_of_model_registration():
    r=registry();old=r.get(ModelBinding,'model')
    r.register(old.model_copy(update={'version':'2','training_opt_in_required':True}))
    r.activate(ModelBinding,'model','2',expected_version='1');s=selector(r)
    assert isinstance(s.select(request(),10000),RouteAbstention)
    assert isinstance(s.select(request(allow_training_opt_in=True),10000),SelectedRoute)
    r.register(old.model_copy(update={'version':'3','context_limit':10}))
    r.activate(ModelBinding,'model','3',expected_version='2')
    assert isinstance(s.select(request(allow_training_opt_in=True),10000),RouteAbstention)


def test_price_usage_conflicting_counters_never_produce_negative_or_hidden_cost():
    r=registry();route=selector(r).select(request(),10000)
    conflict=BrokerUsage(input_tokens=10,output_tokens=5,units=(UsageBound(unit='input_tokens',quantity=999),))
    assert r.price_usage(route,conflict,now=NOW) is None
    invalid_cache=BrokerUsage(cached_tokens=20,output_tokens=5,units=(UsageBound(unit='input_tokens',quantity=10),))
    assert r.price_usage(route,invalid_cache,now=NOW) is None
