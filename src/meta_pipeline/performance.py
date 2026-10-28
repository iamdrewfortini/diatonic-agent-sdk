"""Job/stage measurements, byte amplification and comparable improvements."""
from typing import Literal
from pydantic import BaseModel,ConfigDict,Field,model_validator

class Counters(BaseModel):
    model_config=ConfigDict(extra="forbid",strict=True)
    host:str
    boot_id:str
    scope:str
    monotonic_ns:int=Field(ge=0)
    disk_read_bytes:int|None=Field(default=None,ge=0)
    disk_write_bytes:int|None=Field(default=None,ge=0)
    network_bytes:int|None=Field(default=None,ge=0)
    cpu_time_ns:int|None=Field(default=None,ge=0)

class JobResult(BaseModel):
    model_config=ConfigDict(extra="forbid",strict=True)
    job_id:str
    source_digest:str
    rucio_rule_id:str|None=None
    fts_job_id:str|None=None
    expected_bytes:int=Field(ge=0)
    verified_bytes:int=Field(ge=0)
    request_body_bytes:int=Field(default=0,ge=0)
    response_body_bytes:int=Field(default=0,ge=0)
    scratch_bytes_after:int|None=Field(default=None,ge=0)
    peak_scratch_bytes:int|None=Field(default=None,ge=0)
    peak_memory_bytes:int|None=Field(default=None,ge=0)
    checksum_validation:Literal["passed","failed","unknown"]="unknown"
    native_completion_verified:bool=False

    @model_validator(mode="after")
    def counts(self):
        if self.verified_bytes>self.expected_bytes:raise ValueError("Verified bytes exceed expected bytes")
        if self.peak_scratch_bytes is not None and self.scratch_bytes_after is not None and self.scratch_bytes_after>self.peak_scratch_bytes:
            raise ValueError("Remaining scratch exceeds reported peak")
        return self

def measure(before:Counters,after:Counters,result:JobResult):
    if (before.host,before.boot_id,before.scope)!=(after.host,after.boot_id,after.scope):raise ValueError("Counters must have the same host, boot and attribution scope")
    elapsed=(after.monotonic_ns-before.monotonic_ns)/1e9
    if elapsed<=0:raise ValueError("Positive monotonic measurement interval required")
    deltas={}
    for field in ("disk_read_bytes","disk_write_bytes","network_bytes","cpu_time_ns"):
        a,b=getattr(before,field),getattr(after,field)
        if a is None or b is None:deltas[field]=None
        elif b<a:raise ValueError("Counter reset; cannot derive job performance")
        else:deltas[field]=b-a
    complete=(result.verified_bytes==result.expected_bytes and result.checksum_validation=="passed"
              and result.native_completion_verified and result.scratch_bytes_after==0)
    total_ai=result.request_body_bytes+result.response_body_bytes
    return {**result.model_dump(),"elapsed_seconds":elapsed,**deltas,
        "verified_bytes_per_second":result.verified_bytes/elapsed,
        "model_payload_bits":8*total_ai,"model_payload_bytes":total_ai,
        "disk_read_amplification":deltas['disk_read_bytes']/result.verified_bytes if result.verified_bytes and deltas['disk_read_bytes']is not None else None,
        "disk_write_amplification":deltas['disk_write_bytes']/result.verified_bytes if result.verified_bytes and deltas['disk_write_bytes']is not None else None,
        "network_amplification":deltas['network_bytes']/result.verified_bytes if result.verified_bytes and deltas['network_bytes']is not None else None,
        "fully_verified_and_clean":complete,"measurement_scope":before.scope,
        "bits_basis":"HTTP payload bodies only, not Ethernet/TLS wire counts",
        "power_measurement_required":False}

def compare(baseline:dict,candidate:dict):
    if baseline['source_digest']!=candidate['source_digest'] or baseline['expected_bytes']!=candidate['expected_bytes']:
        raise ValueError("Comparable fixtures and byte counts required")
    if not all(x['fully_verified_and_clean']for x in [baseline,candidate]):raise ValueError("Both jobs must pass independent verification and cleanup")
    metrics={}
    for field in ['elapsed_seconds','disk_read_bytes','disk_write_bytes','network_bytes','model_payload_bits']:
        a,b=baseline.get(field),candidate.get(field)
        metrics[field]={"baseline":a,"candidate":b,"reduction_fraction":(a-b)/a if a and b is not None else None}
    return {"source_digest":candidate['source_digest'],"metrics":metrics,
            "quality_preserved_in_declared_fixture":True,"population_improvement_proven":False}
