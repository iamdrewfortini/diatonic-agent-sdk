"""Planning only: observed device ceilings, free-space admission, temporary batches.

No benchmarks or jobs are run. Native Rucio/FTS policy remains authoritative.
"""
from pydantic import BaseModel, ConfigDict, Field

class StageWorkload(BaseModel):
    model_config = ConfigDict(extra="forbid",strict=True)
    bytes: int = Field(ge=1)
    batch_bytes: int = Field(default=10737418240,ge=1) # 10 GiB
    hdd_free_bytes: int = Field(ge=0)
    reserve_bytes: int = Field(default=107374182400,ge=107374182400)
    checksum_passes: int = Field(default=1,ge=1,le=3)
    # Must be supplied from fresh official target measurements; absence blocks execution.
    target_write_bytes_per_second: int | None = Field(default=None,ge=1)
    independent_target_verified: bool = False

def forecast_stages(w: StageWorkload):
    batch=min(w.bytes,w.batch_bytes)
    headroom=max(0,w.hdd_free_bytes-w.reserve_bytes)
    admission=batch<=headroom
    disk=100000000
    ingress=min(disk,115951412)
    egress=min(disk,109233891,w.target_write_bytes_per_second or disk)
    # Conservative sequential stages, one HDD job at a time. Read/write caps are
    # separately shared across all processes in the slice, not a combined bucket.
    seconds=w.bytes/ingress+w.bytes*w.checksum_passes/disk+w.bytes/egress
    n=(w.bytes+w.batch_bytes-1)//w.batch_bytes
    return {"source_bytes":w.bytes,"batch_count":n,"largest_batch_bytes":batch,
        "admission":admission,"available_after_reserve_bytes":headroom,
        "reserve_bytes":w.reserve_bytes,"hdd_write_bytes":w.bytes,
        "hdd_read_bytes":w.bytes*(1+w.checksum_passes),"network_ingress_bytes":w.bytes,
        "network_egress_bytes":w.bytes,"ideal_sequential_min_seconds":seconds,
        "target_speed_unknown":w.target_write_bytes_per_second is None,
        "planning_rates_basis":"previous supplied measurements; fresh live capacity and native health required",
        "native_execution_ready":False,"independent_target_verified":w.independent_target_verified,
        "stages":["Rucio policy and capacity admission","FTS transfer to registered temporary staging RSE",
                  "bounded full-checksum validation","Rucio rule + FTS target transfer",
                  "independent target checksum verification","native staging replica retirement"],
        "cleanup_policy":"Staging retirement follows verified target completion; unresolved jobs retain evidence and are reported, never silently discarded",
        "controller":"Rucio and FTS; this module forecasts only",
        "existing_job_stopped_by_admission":False,
        "caps":{"cpu_quota":"200%","memory_high":"8G","memory_max":"10G","memory_swap_max":"2G",
                "cpu_weight":10,"io_weight":10,"ssd_read_bytes_per_second":180000000,
                "ssd_write_bytes_per_second":180000000,"hdd_read_bytes_per_second":disk,
                "hdd_write_bytes_per_second":disk,"network_cap":None,"iops_cap":None}}
