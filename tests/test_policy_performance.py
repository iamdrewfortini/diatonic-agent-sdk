import pytest
from meta_pipeline.policy import Policy
from meta_pipeline.performance import Counters,JobResult,measure,compare

def test_persona_cannot_grant_or_promote_authority():
    p=Policy('hq','root-run')
    class Agent:pass
    a=Agent();a.name="administrator"
    p.bind(a,"specialist")
    assert p.authorize(a,"inspect_evidence")["allowed"]
    with pytest.raises(PermissionError):p.authorize(a,"deploy_workflow")
    a.name="assembler"
    with pytest.raises(PermissionError):p.authorize(a,"spawn_cell")
    with pytest.raises(ValueError):p.bind(a,"assembler")
    other=Agent()
    with pytest.raises(PermissionError):p.authorize(other,"inspect_evidence")
    assert len(p.digest)==64 and not p.document['persona_grants_permissions']

def measured(seconds=10,read=200,write=100,request=50,scratch=0):
    before=Counters(host="metal01",boot_id="boot",scope="job-123",monotonic_ns=1000,disk_read_bytes=0,disk_write_bytes=0,cpu_time_ns=0)
    after=before.model_copy(update={"monotonic_ns":1000+int(seconds*1e9),"disk_read_bytes":read,"disk_write_bytes":write,"cpu_time_ns":1000000000})
    result=JobResult(job_id="job-123",source_digest="fixed-fixture",expected_bytes=100,verified_bytes=100,
                     request_body_bytes=request,response_body_bytes=10,scratch_bytes_after=scratch,
                     checksum_validation="passed",native_completion_verified=True)
    return measure(before,after,result)

def test_bits_time_amplification_and_cleanup():
    m=measured()
    assert m['model_payload_bits']==480 and m['verified_bytes_per_second']==10
    assert m['disk_read_amplification']==2 and m['disk_write_amplification']==1
    assert m['network_bytes']is None and m['network_amplification']is None
    assert m['fully_verified_and_clean']
    assert not measured(scratch=1)['fully_verified_and_clean']
    improvement=compare(m,measured(seconds=5,read=100,request=20))
    assert improvement['metrics']['elapsed_seconds']['reduction_fraction']==.5
    assert not improvement['population_improvement_proven']
    with pytest.raises(ValueError):compare(m,measured(scratch=1))

def test_measurement_rejects_cross_scope_and_resets():
    a=Counters(host='a',boot_id='b',scope='x',monotonic_ns=1,disk_read_bytes=100)
    b=a.model_copy(update={"monotonic_ns":2,"disk_read_bytes":99})
    r=JobResult(job_id='x',source_digest='d',expected_bytes=1,verified_bytes=0)
    with pytest.raises(ValueError):measure(a,b,r)
    with pytest.raises(ValueError):measure(a,b.model_copy(update={"scope":"y"}),r)
    with pytest.raises(ValueError):JobResult(job_id='x',source_digest='d',expected_bytes=1,verified_bytes=2)
