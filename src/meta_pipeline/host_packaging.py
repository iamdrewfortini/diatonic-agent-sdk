"""Signed host observations -> bounded, reviewable package simulations.

A finite minimum over registered compatible candidates is not a perfect package.
Plans grant no installation, build, budget or native resource-policy authority.
"""
from __future__ import annotations
import base64
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import platform
import statistics
import sys
import sysconfig
from typing import Literal
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey,Ed25519PublicKey
from pydantic import Field,model_validator
from .provider_contracts import FrozenContract
from .protocol import canonical
from .storage import StageWorkload,forecast_stages

SSD_RESERVE=64*1024**3
HDD_RESERVE=100*1024**3
DOMAIN=b'diatonic-host-measurement-v1\0'


class HostMeasurement(FrozenContract):
    schema_version:Literal['host-measurement-v1']='host-measurement-v1'
    host_id:str=Field(min_length=1,max_length=128)
    observer_id:str=Field(min_length=1,max_length=128)
    boot_id:str=Field(min_length=1,max_length=128)
    source_version:str=Field(min_length=1,max_length=128)
    source_sha256:str=Field(pattern=r'^[0-9a-f]{64}$')
    observed_at:str
    os_id:str
    os_version:str
    architecture:str
    glibc_version:str|None=None
    python_version:str
    python_abi:str
    cpu_features:tuple[str,...]=()
    cpu_affinity:tuple[int,...]=Field(min_length=1,max_length=1024)
    cpu_quota_cores:float=Field(gt=0,le=1024,allow_inf_nan=False)
    memory_available_bytes:int=Field(ge=0)
    controller_memory_current_bytes:int=Field(ge=0)
    controller_memory_high_bytes:int=Field(gt=0)
    controller_memory_max_bytes:int=Field(gt=0)
    resource_controller:str=Field(min_length=1,max_length=256)
    ssd_device_id:str=Field(min_length=1,max_length=128)
    ssd_free_bytes:int=Field(ge=0)
    hdd_device_id:str|None=None
    hdd_free_bytes:int|None=Field(default=None,ge=0)
    shared_reservations_verified:bool=False
    reserved_memory_bytes:int=Field(default=0,ge=0)
    reserved_ssd_bytes:int=Field(default=0,ge=0)
    reserved_hdd_bytes:int=Field(default=0,ge=0)
    ssd_read_bytes_per_second:int|None=Field(default=None,gt=0)
    ssd_write_bytes_per_second:int|None=Field(default=None,gt=0)
    hdd_read_bytes_per_second:int|None=Field(default=None,gt=0)
    hdd_write_bytes_per_second:int|None=Field(default=None,gt=0)
    evidence_refs:tuple[str,...]=Field(min_length=1,max_length=32)

    @model_validator(mode='after')
    def coherent(self):
        t=datetime.fromisoformat(self.observed_at)
        if t.tzinfo is None or self.controller_memory_high_bytes>self.controller_memory_max_bytes:
            raise ValueError('Timezone-aware observation and coherent native memory bounds required')
        if len(set(self.cpu_affinity))!=len(self.cpu_affinity) or any(x<0 for x in self.cpu_affinity):
            raise ValueError('Explicit distinct CPU affinity required')
        if (self.hdd_device_id is None)!=(self.hdd_free_bytes is None):
            raise ValueError('HDD identity and availability must be observed together')
        return self


class SignedHostMeasurement(FrozenContract):
    measurement:HostMeasurement
    key_id:str
    signature_b64:str=Field(max_length=128)


class TrustedHostKey(FrozenContract):
    host_id:str
    key_id:str
    public_key_pem:bytes=Field(max_length=16384)


def sign_measurement(measurement,private_key_pem,key_id):
    """Trusted host-side helper; keys are provisioned separately, never generated."""
    measurement=HostMeasurement.model_validate(measurement.model_dump())
    key=serialization.load_pem_private_key(private_key_pem,password=None)
    if not isinstance(key,Ed25519PrivateKey):raise ValueError('Ed25519 observation key required')
    sig=key.sign(DOMAIN+canonical(measurement.model_dump(mode='json')))
    return SignedHostMeasurement(measurement=measurement,key_id=key_id,signature_b64=base64.b64encode(sig).decode())


def verify_measurement(envelope, trusted_keys, *, expected_host_id, now, max_age_seconds):
    envelope=SignedHostMeasurement.model_validate(envelope.model_dump())
    keys=[k for k in trusted_keys if k.host_id==expected_host_id and k.key_id==envelope.key_id]
    if len(keys)!=1 or envelope.measurement.host_id!=expected_host_id:raise ValueError('Unknown or mismatched host identity')
    if now.tzinfo is None:raise ValueError('Timezone-aware verification time required')
    age=(now-datetime.fromisoformat(envelope.measurement.observed_at)).total_seconds()
    if not 0<=age<=max_age_seconds:raise ValueError('Stale or future host measurement')
    key=serialization.load_pem_public_key(keys[0].public_key_pem)
    if not isinstance(key,Ed25519PublicKey):raise ValueError('Pinned Ed25519 host key required')
    try:key.verify(base64.b64decode(envelope.signature_b64,validate=True),DOMAIN+canonical(envelope.measurement.model_dump(mode='json')))
    except (InvalidSignature,ValueError):raise ValueError('Invalid signed host observation') from None
    return envelope.measurement


class PackageArtifact(FrozenContract):
    id:str=Field(min_length=1,max_length=128)
    sha256:str=Field(pattern=r'^[0-9a-f]{64}$')
    bytes:int=Field(ge=1)
    version:str
    kind:Literal['python','rust_cell','python_c_cell','dependency','rpm']
    architecture:str='any'
    os_ids:tuple[str,...]=('any',)
    python_abis:tuple[str,...]=('any',)
    minimum_python:str='3.11'
    minimum_glibc:str|None=None
    required_cpu_features:tuple[str,...]=()
    dependencies:tuple[str,...]=()
    source_sha256:str=Field(pattern=r'^[0-9a-f]{64}$')
    evidence_ref:str=Field(min_length=1)
    cell_nonblank_lines:int|None=Field(default=None,ge=0)
    cell_public_ops:int|None=Field(default=None,ge=0)
    cell_direct_dependencies:int|None=Field(default=None,ge=0)
    stripped_library_bytes:int|None=Field(default=None,ge=0)


class PackageCandidate(FrozenContract):
    id:str
    artifact_ids:tuple[str,...]=Field(min_length=1,max_length=128)
    capabilities:tuple[str,...]
    independent_verifier_id:str
    implementation:Literal['python','rust_cell','python_c_cell']='python'
    baseline_case_ids:tuple[str,...]=Field(min_length=1)
    expected_cpu_seconds:float=Field(ge=0,allow_inf_nan=False)
    expected_peak_memory_bytes:int=Field(ge=1)
    install_expansion_bytes:int=Field(ge=1)
    hdd_scratch_bytes:int=Field(default=0,ge=0)
    hdd_read_bytes:int=Field(default=0,ge=0)
    hdd_write_bytes:int=Field(default=0,ge=0)
    build_required:bool=False
    build_peak_memory_bytes:int=Field(default=0,ge=0)
    forecast_evidence_refs:tuple[str,...]=Field(min_length=1)


class HistoricalUsage(FrozenContract):
    id:str
    host_id:str
    workload_sha256:str=Field(pattern=r'^[0-9a-f]{64}$')
    artifact_set_sha256:str=Field(pattern=r'^[0-9a-f]{64}$')
    observed_at:str
    outcome:Literal['verified','failed','unresolved']
    input_bytes:int=Field(ge=0)
    elapsed_seconds:float=Field(ge=0,allow_inf_nan=False)
    peak_memory_bytes:int=Field(ge=0)
    peak_scratch_bytes:int=Field(ge=0)
    cpu_seconds:float=Field(ge=0,allow_inf_nan=False)
    cost_nusd:int|None=Field(default=None,ge=0)
    evidence_ref:str=Field(min_length=1)


class NativeBenchmark(FrozenContract):
    host_id:str
    observed_at:str
    development_case_ids:tuple[str,...]=Field(min_length=1)
    host_hardware_sha256:str=Field(pattern=r'^[0-9a-f]{64}$')
    workload_sha256:str=Field(pattern=r'^[0-9a-f]{64}$')
    incumbent_artifact_set_sha256:str=Field(pattern=r'^[0-9a-f]{64}$')
    candidate_artifact_set_sha256:str=Field(pattern=r'^[0-9a-f]{64}$')
    incumbent_verified_cases:tuple[str,...]
    candidate_verified_cases:tuple[str,...]
    heldout_case_ids:tuple[str,...]=Field(min_length=1)
    independent_verifier_id:str
    incumbent_seconds:float=Field(gt=0,allow_inf_nan=False)
    candidate_seconds:float=Field(gt=0,allow_inf_nan=False)
    unsuccessful_trials:int=Field(ge=0)
    trial_evidence_refs:tuple[str,...]=Field(min_length=1)


class ArtifactCatalog(FrozenContract):
    version:str
    source_sha256:str=Field(pattern=r'^[0-9a-f]{64}$')
    artifacts:tuple[PackageArtifact,...]=Field(max_length=256)
    candidates:tuple[PackageCandidate,...]=Field(max_length=256)
    history:tuple[HistoricalUsage,...]=Field(default=(),max_length=32)
    native_benchmarks:tuple[NativeBenchmark,...]=Field(default=(),max_length=32)

    @model_validator(mode='after')
    def unique(self):
        if len({a.id for a in self.artifacts})!=len(self.artifacts) or len({c.id for c in self.candidates})!=len(self.candidates):
            raise ValueError('Ambiguous artifact/candidate identities')
        return self


class PackageRequest(FrozenContract):
    host_id:str
    workload_sha256:str=Field(pattern=r'^[0-9a-f]{64}$')
    required_capabilities:tuple[str,...]=Field(min_length=1)
    required_verifier_id:str
    required_case_ids:tuple[str,...]=Field(min_length=1)
    max_payload_bytes:int=Field(ge=1)
    schedule_window_seconds:float=Field(gt=0,allow_inf_nan=False)
    allow_build:bool=False


class HostPackagingPolicy(FrozenContract):
    version:Literal['host-packaging-policy-v1']='host-packaging-policy-v1'
    max_measurement_age_seconds:int=Field(default=300,ge=1,le=3600)
    max_history_age_seconds:int=Field(default=86400*30,ge=1,le=86400*90)
    max_candidates:int=Field(default=256,ge=1,le=256)
    ssd_reserve_bytes:int=Field(default=SSD_RESERVE,ge=SSD_RESERVE)
    hdd_reserve_bytes:int=Field(default=HDD_RESERVE,ge=HDD_RESERVE)
    maximum_build_memory_bytes:int=Field(default=512*1024**2,ge=1,le=1024**3)
    maximum_cell_nonblank_lines:int=Field(default=400,ge=1,le=400)
    maximum_cell_public_ops:int=Field(default=6,ge=1,le=6)
    maximum_cell_direct_dependencies:int=Field(default=8,ge=0,le=8)
    maximum_stripped_library_bytes:int=Field(default=2*1024**2,ge=1,le=2*1024**2)


class SimulatedCandidate(FrozenContract):
    id:str
    status:Literal['eligible','rejected']
    reasons:tuple[str,...]
    artifact_ids:tuple[str,...]
    artifact_set_sha256:str
    payload_bytes:int
    forecast_elapsed_seconds:float
    forecast_elapsed_interval_seconds:tuple[float,float]
    forecast_peak_memory_interval_bytes:tuple[int,int]
    forecast_cost_nusd:int|None=None
    forecast_peak_memory_bytes:int
    forecast_install_peak_bytes:int
    matched_history_ids:tuple[str,...]
    unsuccessful_history_ids:tuple[str,...]
    forecast_evidence_refs:tuple[str,...]
    uncertainty:str


class PackagePlan(FrozenContract):
    schema_version:Literal['host-package-plan-v1']='host-package-plan-v1'
    status:Literal['reviewable','blocked']
    host_id:str
    host_measurement_sha256:str
    catalog_sha256:str
    request_sha256:str
    policy_sha256:str
    selected_candidate_id:str|None=None
    artifacts:tuple[PackageArtifact,...]=()
    candidates:tuple[SimulatedCandidate,...]=()
    reasons:tuple[str,...]=()
    cell_budgets:tuple[tuple[str,int],...]=()
    history_sample_ids:tuple[str,...]=()
    historical_input_elapsed_correlation:float|None=None
    history_association_scope:str='bounded observed association, not causation or calibrated prediction'
    aggregate_memory_headroom_bytes:int=0
    ssd_headroom_bytes:int=0
    hdd_headroom_bytes:int|None=None
    directional_hdd_caps:tuple[tuple[str,int],...]=()
    grants_install_authority:Literal[False]=False
    native_resource_policy_changed:Literal[False]=False
    optimality_scope:str='minimum payload among finite registered eligible variants; no universal optimum'


def artifact_set_digest(artifacts):
    return hashlib.sha256(canonical(sorted((a.id,a.sha256,a.bytes) for a in artifacts))).hexdigest()


def hardware_digest(measurement):
    return hashlib.sha256(canonical([measurement.host_id,measurement.architecture,measurement.os_id,
        measurement.os_version,measurement.python_abi,measurement.glibc_version,
        measurement.cpu_features,measurement.cpu_affinity,measurement.cpu_quota_cores,
        measurement.controller_memory_high_bytes,measurement.controller_memory_max_bytes,
        measurement.resource_controller,measurement.ssd_device_id,measurement.hdd_device_id,
        measurement.ssd_read_bytes_per_second,measurement.ssd_write_bytes_per_second,
        measurement.hdd_read_bytes_per_second,measurement.hdd_write_bytes_per_second])).hexdigest()


def _fresh(value, now, maximum):
    try:return 0<=(now-datetime.fromisoformat(value)).total_seconds()<=maximum
    except (ValueError,TypeError):return False


def _version(value):
    try:return tuple(int(x) for x in value.split('.'))
    except (ValueError,AttributeError):return ()


def derive_package_plan(envelope, catalog, request, policy, *, trusted_keys, now, trusted_catalog_digests=()):
    catalog=ArtifactCatalog.model_validate(catalog.model_dump());request=PackageRequest.model_validate(request.model_dump())
    policy=HostPackagingPolicy.model_validate(policy.model_dump())
    base=dict(host_id=request.host_id,host_measurement_sha256=envelope.measurement.digest,
        catalog_sha256=catalog.digest,request_sha256=request.digest,policy_sha256=policy.digest)
    if catalog.digest not in trusted_catalog_digests:
        return PackagePlan(status='blocked',reasons=('artifact_catalog_not_pinned_by_coordinator',),**base)
    try:m=verify_measurement(envelope,trusted_keys,expected_host_id=request.host_id,now=now,max_age_seconds=policy.max_measurement_age_seconds)
    except ValueError as exc:return PackagePlan(status='blocked',reasons=(str(exc),),**base)
    if not m.shared_reservations_verified:
        return PackagePlan(status='blocked',reasons=('shared_reservations_unknown',),**base)
    if m.resource_controller=='unknown':return PackagePlan(status='blocked',reasons=('unknown_resource_enforcement',),**base)
    memory=max(0,min(m.memory_available_bytes,min(m.controller_memory_high_bytes,8*1024**3)-m.controller_memory_current_bytes)-m.reserved_memory_bytes)
    ssd=max(0,m.ssd_free_bytes-policy.ssd_reserve_bytes-m.reserved_ssd_bytes)
    hdd=None if m.hdd_free_bytes is None else max(0,m.hdd_free_bytes-policy.hdd_reserve_bytes-m.reserved_hdd_bytes)
    # Host-derived lower budgets never widen the operator hard ceilings.
    budgets=(('nonblank_lines',min(policy.maximum_cell_nonblank_lines,max(1,memory//(2*1024**2)))),
        ('public_ops',min(policy.maximum_cell_public_ops,max(1,len(m.cpu_affinity)))),
        ('direct_dependencies',min(policy.maximum_cell_direct_dependencies,max(0,memory//(64*1024**2)))),
        ('stripped_library_bytes',min(policy.maximum_stripped_library_bytes,max(0,ssd//128))))
    items={a.id:a for a in catalog.artifacts};results=[]
    baselines={artifact_set_digest([items[i] for i in c.artifact_ids]) for c in catalog.candidates
        if c.implementation=='python' and all(i in items for i in c.artifact_ids) and
        set(request.required_capabilities)<=set(c.capabilities) and c.independent_verifier_id==request.required_verifier_id and
        set(request.required_case_ids)<=set(c.baseline_case_ids)}
    for c in catalog.candidates[:policy.max_candidates]:
        reasons=[];arts=[items[i] for i in c.artifact_ids if i in items]
        if len(arts)!=len(c.artifact_ids) or len(set(c.artifact_ids))!=len(c.artifact_ids):reasons.append('unknown_or_duplicate_artifact')
        aset=artifact_set_digest(arts);payload=sum(a.bytes for a in arts)
        if not set(request.required_capabilities)<=set(c.capabilities):reasons.append('reduced_required_coverage')
        if not set(request.required_case_ids)<=set(c.baseline_case_ids):reasons.append('missing_required_verified_cases')
        if c.independent_verifier_id!=request.required_verifier_id:reasons.append('weaker_or_unknown_verification')
        for a in arts:
            if (a.architecture not in ('any',m.architecture) or
                    'any' not in a.os_ids and m.os_id not in a.os_ids or
                    'any' not in a.python_abis and m.python_abi not in a.python_abis or
                    not _version(a.minimum_python) or _version(m.python_version)<_version(a.minimum_python) or
                    not set(a.required_cpu_features)<=set(m.cpu_features) or
                    a.minimum_glibc is not None and (not m.glibc_version or _version(m.glibc_version)<_version(a.minimum_glibc))):
                reasons.append('artifact_abi_os_arch_or_cpu_mismatch:'+a.id)
            if not set(a.dependencies)<=set(c.artifact_ids):reasons.append('missing_dependency:'+a.id)
        matched=[];unsuccessful=[]
        for sample in catalog.history:
            if sample.host_id!=m.host_id or sample.workload_sha256!=request.workload_sha256 or sample.artifact_set_sha256!=aset:continue
            try:age=(now-datetime.fromisoformat(sample.observed_at)).total_seconds()
            except (ValueError,TypeError):continue
            if not 0<=age<=policy.max_history_age_seconds:continue
            (matched if sample.outcome=='verified' else unsuccessful).append(sample)
        peak=max([c.expected_peak_memory_bytes]+[s.peak_memory_bytes for s in matched+unsuccessful])
        peak=(peak*6+4)//5
        cpu=c.expected_cpu_seconds/min(len(m.cpu_affinity),m.cpu_quota_cores,2.)
        io=0.
        if c.hdd_read_bytes or c.hdd_write_bytes or c.hdd_scratch_bytes:
            if hdd is None or c.hdd_scratch_bytes>hdd:reasons.append('hdd_capacity_unknown_or_reserve_exceeded')
            elif c.hdd_scratch_bytes:
                native_forecast=forecast_stages(StageWorkload(bytes=c.hdd_scratch_bytes,batch_bytes=c.hdd_scratch_bytes,
                    hdd_free_bytes=max(0,m.hdd_free_bytes-m.reserved_hdd_bytes),reserve_bytes=policy.hdd_reserve_bytes))
                if not native_forecast['admission']:reasons.append('native_storage_reserve_blocked')
            if not m.hdd_read_bytes_per_second or not m.hdd_write_bytes_per_second:reasons.append('unknown_directional_hdd_caps')
            else:io=c.hdd_read_bytes/min(100000000,m.hdd_read_bytes_per_second)+c.hdd_write_bytes/min(100000000,m.hdd_write_bytes_per_second)
        elapsed=max([cpu+io]+[s.elapsed_seconds for s in matched+unsuccessful])*1.2
        install_peak=payload+c.install_expansion_bytes
        if payload>request.max_payload_bytes:reasons.append('payload_budget_exceeded')
        if install_peak>ssd:reasons.append('ssd_install_peak_or_reserve_exceeded')
        if peak>memory:reasons.append('aggregate_memory_pressure')
        if elapsed>request.schedule_window_seconds:reasons.append('schedule_window_exceeded')
        if c.build_required and (not request.allow_build or c.build_peak_memory_bytes>min(memory,policy.maximum_build_memory_bytes)):
            reasons.append('build_not_authorized_or_memory_exceeded')
        if c.implementation!='python' or any(a.kind in ('rust_cell','python_c_cell') for a in arts):
            bmap=dict(budgets)
            for a in arts:
                if a.kind not in ('rust_cell','python_c_cell'):continue
                for attr,budget in [('cell_nonblank_lines','nonblank_lines'),('cell_public_ops','public_ops'),('cell_direct_dependencies','direct_dependencies'),('stripped_library_bytes','stripped_library_bytes')]:
                    value=getattr(a,attr)
                    if value is None or value>bmap[budget]:reasons.append('native_cell_size_or_attestation_missing:'+a.id+':'+attr)
            evidence=[b for b in catalog.native_benchmarks if b.host_id==m.host_id and b.host_hardware_sha256==hardware_digest(m)
                and b.workload_sha256==request.workload_sha256 and b.candidate_artifact_set_sha256==aset
                and _fresh(b.observed_at,now,policy.max_history_age_seconds)
                and not set(b.development_case_ids)&set(b.heldout_case_ids)
                and b.incumbent_artifact_set_sha256 in baselines and b.independent_verifier_id==request.required_verifier_id
                and set(b.incumbent_verified_cases)==set(b.candidate_verified_cases)
                and set(request.required_case_ids)<=set(b.candidate_verified_cases)
                and set(b.heldout_case_ids)<=set(b.candidate_verified_cases) and b.candidate_seconds<b.incumbent_seconds]
            if not evidence:reasons.append('native_requires_exact_host_independent_same_coverage_heldout_improvement')
        results.append(SimulatedCandidate(id=c.id,status='rejected' if reasons else 'eligible',reasons=tuple(sorted(set(reasons))),
            artifact_ids=c.artifact_ids,artifact_set_sha256=aset,payload_bytes=payload,
            forecast_elapsed_seconds=elapsed,forecast_elapsed_interval_seconds=(min([cpu+io]+[s.elapsed_seconds for s in matched]),elapsed),
            forecast_peak_memory_interval_bytes=(min([c.expected_peak_memory_bytes]+[s.peak_memory_bytes for s in matched]),peak),
            forecast_peak_memory_bytes=peak,forecast_install_peak_bytes=install_peak,
            matched_history_ids=tuple(s.id for s in matched),unsuccessful_history_ids=tuple(s.id for s in unsuccessful),
            forecast_evidence_refs=c.forecast_evidence_refs+tuple(s.evidence_ref for s in matched+unsuccessful),
            uncertainty='uncalibrated conservative1.2x envelope; matching historical association is not causality'))
    eligible=[r for r in results if r.status=='eligible']
    selected=min(eligible,key=lambda r:(r.payload_bytes,r.forecast_elapsed_seconds,r.id)) if eligible else None
    caps=tuple((n,v) for n,v in [('read_bytes_per_second',min(100000000,m.hdd_read_bytes_per_second) if m.hdd_read_bytes_per_second else None),('write_bytes_per_second',min(100000000,m.hdd_write_bytes_per_second) if m.hdd_write_bytes_per_second else None)] if v is not None)
    history=[sample for sample in catalog.history if sample.host_id==m.host_id and
        _fresh(sample.observed_at,now,policy.max_history_age_seconds)]
    scored=[sample for sample in history if sample.outcome=='verified']
    correlation=None
    if len(scored)>=3:
        xs=[s.input_bytes for s in scored];ys=[s.elapsed_seconds for s in scored]
        if len(set(xs))>1 and len(set(ys))>1:correlation=statistics.correlation(xs,ys)
    return PackagePlan(status='reviewable' if selected else 'blocked',selected_candidate_id=selected.id if selected else None,
        artifacts=tuple(items[i] for i in selected.artifact_ids) if selected else (),candidates=tuple(results),
        reasons=(() if len(catalog.candidates)<=policy.max_candidates else ('candidate_limit_remaining_variants_not_evaluated',)) if selected else ('no_feasible_registered_variant',),
        cell_budgets=budgets,history_sample_ids=tuple(s.id for s in history),historical_input_elapsed_correlation=correlation,aggregate_memory_headroom_bytes=memory,ssd_headroom_bytes=ssd,hdd_headroom_bytes=hdd,
        directional_hdd_caps=caps,**base)


def forecast_error(plan, *, candidate_id, observed_elapsed_seconds, observed_peak_memory_bytes, evidence_ref):
    """Appendable feedback, not mutation of forecast criteria or signed observations."""
    candidates=[c for c in plan.candidates if c.id==candidate_id]
    if len(candidates)!=1 or not evidence_ref or type(observed_elapsed_seconds) not in (int,float) or not 0<=observed_elapsed_seconds<float('inf') or type(observed_peak_memory_bytes)is not int or observed_peak_memory_bytes<0:
        raise ValueError('Distinct independently observed outcome required')
    c=candidates[0]
    return {'plan_sha256':plan.digest,'candidate_id':candidate_id,'observation_ref':evidence_ref,
        'elapsed_signed_error':observed_elapsed_seconds-c.forecast_elapsed_seconds,
        'memory_signed_error_bytes':observed_peak_memory_bytes-c.forecast_peak_memory_bytes,
        'forecasts_are_observations':False}


def collect_local_measurement(*, host_id, observer_id, ssd_root='/var/lib/diatonic-meta/runtime',
                              hdd_root='/data', cgroup_path='/sys/fs/cgroup/aux.slice/aux-batch.slice'):
    """Linux read-only observer; caller signs with separately provisioned identity.

    Unreadable/missing native limits fail rather than infer unlimited capacity.
    No user files, credentials, jobs, network inventory or build tools are read.
    """
    group=Path(cgroup_path).resolve(strict=True)
    if not group.is_relative_to('/sys/fs/cgroup'):raise ValueError('Native cgroup evidence required')
    def integer(name):
        text=(group/name).read_text().strip()
        if not text.isdigit():raise ValueError('Missing finite native limit:'+name)
        return int(text)
    quota,period=(group/'cpu.max').read_text().split()
    if quota=='max' or int(period)<=0:raise ValueError('Finite observed CPU quota required')
    effective=set()
    for piece in (group/'cpuset.cpus.effective').read_text().strip().split(','):
        if '-' in piece:
            first,last=map(int,piece.split('-'));effective.update(range(first,last+1))
        elif piece:effective.add(int(piece))
    affinity=tuple(sorted(set(os.sched_getaffinity(0))&effective))
    mem={k:int(v.split()[0])*1024 for k,v in (line.split(':',1) for line in Path('/proc/meminfo').read_text().splitlines()) if k=='MemAvailable'}
    release={k:v.strip('"') for k,v in (line.split('=',1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)}
    features=[]
    for line in Path('/proc/cpuinfo').read_text().splitlines():
        if line.startswith(('flags\t','Features\t')):features.append(set(line.split(':',1)[1].split()))
    def volume(path):
        st=os.stat(path);v=os.statvfs(path)
        return f'{os.major(st.st_dev)}:{os.minor(st.st_dev)}',v.f_bavail*v.f_frsize
    ssd_id,ssd_free=volume(ssd_root);hdd_id,hdd_free=volume(hdd_root)
    libc_name,libc_version=platform.libc_ver()
    caps={}
    for direction,name in [('read','rbps'),('write','wbps')]:
        rows=(group/'io.max').read_text().splitlines()
        for label,device in [('ssd',ssd_id),('hdd',hdd_id)]:
            devicepath=Path('/sys/dev/block')/device
            parent_device=(devicepath.resolve().parent/'dev').read_text().strip() if (devicepath/'partition').exists() else device
            values=[dict(pair.split('=',1) for pair in row.split()[1:] if '=' in pair).get(name) for row in rows if row.split()[0]==device or row.split()[0]==parent_device]
            # Partition and whole-device keys differ; observe the actual st_dev or
            # its parent block device, never invent a network or IOPS ceiling.
            numeric=[int(x) for x in values if x and x.isdigit()]
            caps[f'{label}_{direction}_bytes_per_second']=min(numeric) if numeric else None
    return HostMeasurement(host_id=host_id,observer_id=observer_id,
        boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
        source_version='linux-host-observer-v1',source_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        observed_at=datetime.now(timezone.utc).isoformat(),os_id=release['ID'],os_version=release['VERSION_ID'],
        architecture=platform.machine(),glibc_version=libc_version if libc_name=='glibc' else None,
        python_version=platform.python_version(),python_abi=sysconfig.get_config_var('SOABI') or 'unknown',
        cpu_features=tuple(sorted(set.intersection(*features))) if features else (),cpu_affinity=affinity,
        cpu_quota_cores=int(quota)/int(period),memory_available_bytes=mem['MemAvailable'],
        controller_memory_current_bytes=integer('memory.current'),controller_memory_high_bytes=integer('memory.high'),
        controller_memory_max_bytes=integer('memory.max'),resource_controller=str(group),ssd_device_id=ssd_id,
        ssd_free_bytes=ssd_free,hdd_device_id=hdd_id,hdd_free_bytes=hdd_free,
        evidence_refs=('native:'+str(group),'native:/proc/meminfo','native:/etc/os-release'),**caps)
