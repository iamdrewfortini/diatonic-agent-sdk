import asyncio
import json
from concurrent.futures import ThreadPoolExecutor
import httpx
import pytest
from meta_pipeline.models import MODELS, Workload, bill_nusd, route, forecast
from meta_pipeline.ledger import Ledger
from meta_pipeline.gateway import GatewayConfig, MetaGateway, measured_usage
from meta_pipeline.evidence import Record, load_manifest, assess
from meta_pipeline.manager import request, strict_schema, validate_labels, ValidationManager

def record(name="first.bin",rse="NAS_SOURCE",**kw):
    return Record(scope="test",name=name,rse=rse,bytes=100,sha256="a"*64,
                  checksum_kind="full",source_mutable=False,**kw)

@pytest.mark.parametrize("mid",[m.id for m in MODELS.values() if m.billing=="tokens"])
def test_text_prices(mid):
    m=MODELS[mid]
    assert bill_nusd(m,input_tokens=1000000,output_tokens=1000000)==1000000*(m.input_nusd+m.output_nusd)

def test_routes_and_opt_in():
    assert route(Workload()).id=="muse-spark-1.3"
    assert route(Workload(allow_contributor=True)).id.endswith("-contributor")
    with pytest.raises(ValueError):route(Workload(model="muse-spark-1.3-contributor"))
    assert route(Workload(task="plan")).id=="muse-wonder-1.0"
    assert route(Workload(task="audio_understanding",input_kind="audio")).id=="muse-spark-1.2"
    with pytest.raises(ValueError):route(Workload(task="audio_understanding",input_kind="audio",model="muse-spark-1.3"))
    with pytest.raises(ValueError):route(Workload(model="muse-image-1.0"))
    with pytest.raises(ValueError):route(Workload(model="Muse Glimmer"))
    with pytest.raises(ValueError):route(Workload(input_tokens=1048576))

def test_media_separate_units():
    assert forecast(Workload(task="generate_image",images=3))["reserve_nusd"]==30000000
    assert forecast(Workload(task="transcribe",input_kind="audio",audio_seconds=3600))["reserve_nusd"]==180000000
    assert bill_nusd(MODELS["muse-voice-transcribe-1.0"],audio_seconds=1.9)==50000
    assert forecast(Workload(task="segment",input_kind="video",video_frames=[1,51]))["reserve_nusd"]==101*200000
    assert forecast(Workload(task="segment",input_kind="image",images=1000))["reserve_nusd"]==2500000000
    with pytest.raises(ValueError):forecast(Workload(task="generate_image"))
    # Image tokens are informational, not an extra token charge.
    assert bill_nusd(MODELS["muse-image-1.0"],images=1,input_tokens=1000000)==10000000

def test_prefix_cache_not_assumed_for_reservation():
    f=forecast(Workload(input_tokens=1000,cached_tokens=1000))
    assert f["reserve_nusd"]>f["projected_nusd"]
    assert forecast(Workload(hdd_read_bytes=100000000))["hdd_read_min_seconds"]==1

def test_atomic_budget_under_parallel_admission(tmp_path):
    ledger=Ledger(str(tmp_path/"usage.db"),100,100)
    def reserve(_):
        try:return ledger.reserve("r","m",30)
        except ValueError:return None
    with ThreadPoolExecutor(max_workers=8) as pool:
        assert len([x for x in pool.map(reserve,range(20)) if x])==3
    assert ledger.summary()["states"][0]["accounted_nusd"]==90

def test_unknown_usage_keeps_reservation(tmp_path):
    l=Ledger(str(tmp_path/"l"),10,10)
    key=l.reserve("run","m",10);l.settle(key,None,{"error_type":"timeout"})
    with pytest.raises(ValueError):l.reserve("next","m",1)
    with pytest.raises(ValueError):l.settle(key,0,{})

def test_real_usage_updates_budget(tmp_path):
    l=Ledger(str(tmp_path/"l"),20,20)
    key=l.reserve("run","m",10);l.settle(key,3,{})
    l.reserve("run","m",17)
    with pytest.raises(ValueError):l.reserve("run","m",1)

def test_cache_replay_vs_prefix_cache():
    m=MODELS["muse-spark-1.3"]
    body={"usage":{"prompt_tokens":1000,"completion_tokens":10,"prompt_tokens_details":{"cached_tokens":800}}}
    price,detail=measured_usage(body,{},m)
    assert price==200*1250+800*150+10*4250
    assert measured_usage(body,{"x-bifrost-cache-hit":"true","x-bifrost-cache-hit-type":"direct"},m)[0]==0
    assert measured_usage(body,{"x-bifrost-cache-hit":"true","x-bifrost-cache-hit-type":"semantic"},m)[0]!=0
    assert measured_usage({}, {},m)[0] is None

def test_duplicate_evidence_and_replicas():
    r=record()
    report=assess([r,record(rse="EOS_COLD")])
    assert report["unique_dids"]==1 and not report["duplicate_candidates"]
    report=assess([r,record(name="second.bin")])
    assert report["duplicate_candidates"][0]["potential_duplicate_bytes"]==100
    mutable=r.model_copy(update={"source_mutable":True})
    assert not assess([mutable,record(name="second.bin")])["duplicate_candidates"]
    live=record(live_database=True)
    assert assess([live])["classifications"][0]["label"]=="database_snapshot_required"
    assert not assess([live,record(name="other")])["duplicate_candidates"]

def test_manifest_conflicts_and_bounds(tmp_path):
    p=tmp_path/"manifest"
    r=record()
    p.write_text(r.model_dump_json()+"\n"+r.model_dump_json()+"\n")
    with pytest.raises(ValueError):load_manifest(p)
    r2=r.model_copy(update={"rse":"EOS_COLD","sha256":"b"*64})
    p.write_text(r.model_dump_json()+"\n"+r2.model_dump_json()+"\n")
    with pytest.raises(ValueError):load_manifest(p)
    p.write_text(r.model_dump_json()+"\n")
    with pytest.raises(ValueError):load_manifest(p,max_bytes=2)

def test_ai_cannot_invent_ids_or_verbs():
    batch=[{"id":"a"*32,"bytes":5}]
    with pytest.raises(ValueError):validate_labels({"labels":[{"id":"b"*32,"label":"documents","confidence":0.99}]},batch)
    with pytest.raises(ValueError):validate_labels({"labels":[{"id":"a"*32,"label":"documents","confidence":0.99,"delete":True}]},batch)
    result=validate_labels({"labels":[{"id":"a"*32,"label":"unknown","confidence":0.99}]},batch)
    assert result[0]["requires_review"]

@pytest.mark.parametrize("url",["https://api.meta.ai/v1","https://api.openai.com/v1","http://untrusted.local/openai","https://u:p@bifrost.local/openai"])
def test_no_direct_provider_or_untrusted_gateway(url):
    host=httpx.URL(url).host
    with pytest.raises(ValueError):GatewayConfig(base_url=url,allowed_hosts=[host]).validate_origin()

def make_gateway(tmp_path,handler,attempts=1):
    cfg=GatewayConfig(base_url="http://localhost:8080/openai",allowed_hosts=["localhost"],
        allowed_models=["muse-spark-1.3"],verified_endpoints=["chat"],gateway_attempts=attempts)
    l=Ledger(str(tmp_path/"l"),1000000000,1000000000)
    return MetaGateway(cfg,l,key="synthetic-test-key",transport=httpx.MockTransport(handler))

@pytest.mark.asyncio
async def test_sdk_gateway_request_schema_cache_and_accounting(tmp_path):
    def handler(req):
        assert str(req.url)=="http://localhost:8080/openai/chat/completions"
        assert req.headers["x-bf-vk"]=="synthetic-test-key"
        assert req.headers["x-bf-cache-type"]=="direct"
        assert req.headers["x-bf-disable-content-logging"]=="true"
        d=json.loads(req.content);assert d["model"]=="meta/muse-spark-1.3"
        assert d["response_format"]["type"]=="json_schema"
        assert "tools" not in d
        return httpx.Response(200,json={"id":"test","model":"muse-spark-1.3","object":"chat.completion","created":0,
            "choices":[{"index":0,"finish_reason":"stop","message":{"role":"assistant","content":'{"labels":[]}'}}],
            "usage":{"prompt_tokens":10,"completion_tokens":2,"total_tokens":12}})
    g=make_gateway(tmp_path,handler)
    try:
        w,msgs=request([])
        assert await g.text(run="test",w=w,messages=msgs,schema=strict_schema(),cache_scope="test",evidence_digest="digest")=={"labels":[]}
        assert g.ledger.summary()["states"][0]["accounted_nusd"]==10*1250+2*4250
    finally:await g.close()

@pytest.mark.asyncio
async def test_invalid_result_still_billed(tmp_path):
    def handler(req):
        return httpx.Response(200,json={"id":"test","model":"muse-spark-1.3","object":"chat.completion","created":0,
            "choices":[{"index":0,"finish_reason":"length","message":{"role":"assistant","content":"bad"}}],
            "usage":{"prompt_tokens":10,"completion_tokens":2,"total_tokens":12}})
    g=make_gateway(tmp_path,handler)
    try:
        w,msgs=request([])
        with pytest.raises(ValueError):await g.text(run="r",w=w,messages=msgs,schema=strict_schema(),cache_scope="x",evidence_digest="d")
        assert g.ledger.summary()["states"][0]["accounted_nusd"]>0
    finally:await g.close()

@pytest.mark.asyncio
async def test_gateway_error_no_client_retries(tmp_path):
    calls=[]
    def handler(req):
        calls.append(req);return httpx.Response(500,json={"error":{"message":"unsafe body"}})
    g=make_gateway(tmp_path,handler)
    try:
        w,msgs=request([])
        with pytest.raises(RuntimeError) as err:await g.text(run="r",w=w,messages=msgs,schema=strict_schema(),cache_scope="x",evidence_digest="d")
        assert "unsafe" not in str(err.value) and len(calls)==1
        assert g.ledger.summary()["states"][0]["state"]=="unresolved"
    finally:await g.close()

@pytest.mark.asyncio
async def test_manager_bounded_and_no_paid_calls_for_known_extension(tmp_path):
    def handler(req):raise AssertionError("No gateway call expected")
    g=make_gateway(tmp_path,handler)
    try:
        m=ValidationManager(g)
        result=await m.run([record(name="known.pdf")],run="x")
        assert result["ai_batches"]==[] and result["nas_bytes_moved"]==0
        unknown=[record(name=f"{i}.unknown") for i in range(100)]
        m=ValidationManager(g,max_batches=1,batch_size=2)
        assert m.forecast(unknown)["deferred_records"]==98
        assert m.forecast(unknown)["file_content_bytes_sent"]==0
    finally:await g.close()
