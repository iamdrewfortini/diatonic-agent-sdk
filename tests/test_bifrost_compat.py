import httpx,json,pytest
from meta_pipeline.bifrost_compat import preserve_meta_request,BifrostMetaHTTP

def test_native_preservation_only_restores_same_meta_fields():
    original={'model':'meta/muse-spark-1.3','reasoning':{'effort':'minimal'},'input':[{'type':'reasoning','summary':[],'encrypted_content':'opaque'}, {'type':'function_call','call_id':'c','arguments':'{}','name':'inspect_evidence'}, {'type':'function_call_output','call_id':'c','output':'{}'}]}
    d=preserve_meta_request(original,'/openai/responses')
    assert d['extra_params']['input']==original['input']
    assert d['extra_params']['reasoning']=={'effort':'minimal'}
    assert 'extra_params'not in original
    assert set(d['extra_params'])=={'input','reasoning'}
    with pytest.raises(ValueError):preserve_meta_request({**original,'extra_params':{'model':'other'}},'/responses')
    with pytest.raises(ValueError):preserve_meta_request({**original,'model':'openai/other'},'/responses')

@pytest.mark.asyncio
async def test_adapter_measures_actual_modified_body_and_preserves_auth():
    captured=[]
    def handler(req):
        d=json.loads(req.content);assert d['extra_params']=={'reasoning_effort':'minimal'}
        assert req.headers['content-length']==str(len(req.content))
        assert req.headers['x-bf-vk']=='synthetic-key'
        assert req.headers['x-bf-passthrough-extra-params']=='true'
        return httpx.Response(200,json={'ok':True})
    async def before(req):captured.append(len(req.content))
    async with BifrostMetaHTTP(transport=httpx.MockTransport(handler),event_hooks={'request':[before]})as client:
        r=await client.post('http://localhost/openai/chat/completions',headers={'x-bf-vk':'synthetic-key'},json={'model':'meta/muse-spark-1.3','reasoning_effort':'minimal'})
        assert captured==[len(r.request.content)]
