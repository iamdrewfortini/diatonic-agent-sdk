import json
import pytest
from meta_pipeline.storage import StageWorkload, forecast_stages
from meta_pipeline.schemas import inspect
from meta_pipeline.models import Workload

def test_storage_capacity_and_capped_stages():
    w=StageWorkload(bytes=200000000,batch_bytes=100000000,hdd_free_bytes=107474182400)
    f=forecast_stages(w)
    assert f["admission"] and f["batch_count"]==2
    assert f["hdd_read_bytes"]==400000000 and f["hdd_write_bytes"]==200000000
    assert f["ideal_sequential_min_seconds"]==6
    assert not f["existing_job_stopped_by_admission"]
    assert not f["native_execution_ready"]
    assert f["caps"]["network_cap"] is None
    assert not forecast_stages(w.model_copy(update={"hdd_free_bytes":1000}))["admission"]

def test_invalid_usage_inputs():
    with pytest.raises(ValueError):Workload(audio_seconds=float("nan"))
    with pytest.raises(ValueError):Workload(video_frames=[0])
    with pytest.raises(ValueError):Workload(cached_tokens=1,input_tokens=0)

def test_vendor_schema_inventory_no_external_execution(tmp_path):
    p=tmp_path/"meta.json"
    p.write_text(json.dumps({"openapi":"3.1.0","paths":{"/v1/responses":{"post":{"operationId":"responses"}}},
                             "components":{"schemas":{"X":{"$ref":"https://example.invalid/never-fetch"}}}}))
    r=inspect(str(tmp_path))
    assert r["schemas"][0]["operations"][0]["method"]=="POST"
    assert r["schemas"][0]["external_refs_blocked"]
    assert len(r["schemas"][0]["sha256"])==64
