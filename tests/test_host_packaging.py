from datetime import datetime,timedelta,timezone
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from meta_pipeline.host_packaging import (HostMeasurement,SignedHostMeasurement,TrustedHostKey,PackageArtifact,
    PackageCandidate,ArtifactCatalog,PackageRequest,HostPackagingPolicy,HistoricalUsage,NativeBenchmark,
    sign_measurement,derive_package_plan,artifact_set_digest,hardware_digest,forecast_error)

SHA='a'*64
NOW=datetime(2026,10,28,15,tzinfo=timezone.utc)


def setup(**measurement_changes):
    key=Ed25519PrivateKey.generate()
    pem=key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())
    public=key.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo)
    values=dict(host_id='fixture-client',observer_id='fixture-observer',boot_id='fixture-boot',source_version='fixture-v1',source_sha256=SHA,
      observed_at=NOW.isoformat(),os_id='almalinux',os_version='10.2',architecture='x86_64',glibc_version='2.39',
      python_version='3.12.15',python_abi='cpython-312-x86_64-linux-gnu',cpu_affinity=(0,2),cpu_quota_cores=2.,
      memory_available_bytes=16*1024**3,controller_memory_current_bytes=128*1024**2,
      controller_memory_high_bytes=8*1024**3,controller_memory_max_bytes=10*1024**3,resource_controller='fixture:aux-batch.slice',
      ssd_device_id='fixture-ssd',ssd_free_bytes=100*1024**3,hdd_device_id='fixture-hdd',hdd_free_bytes=200*1024**3,
      hdd_read_bytes_per_second=100000000,hdd_write_bytes_per_second=100000000,shared_reservations_verified=True,evidence_refs=('fixture-observation',))
    m=HostMeasurement(**{**values,**measurement_changes});env=sign_measurement(m,pem,'fixture-key')
    trust=(TrustedHostKey(host_id=m.host_id,key_id='fixture-key',public_key_pem=public),)
    a=PackageArtifact(id='baseline',sha256=SHA,bytes=10000,version='1',kind='python',source_sha256=SHA,evidence_ref='fixture:wheel')
    c=PackageCandidate(id='python-baseline',artifact_ids=('baseline',),capabilities=('discover','verify'),independent_verifier_id='verifier1',
       baseline_case_ids=('dev1','heldout1'),expected_cpu_seconds=1.,expected_peak_memory_bytes=1024**2,install_expansion_bytes=20000,
       forecast_evidence_refs=('fixture:declared-capacity',))
    cat=ArtifactCatalog(version='1',source_sha256=SHA,artifacts=(a,),candidates=(c,))
    req=PackageRequest(host_id=m.host_id,workload_sha256=SHA,required_capabilities=('discover','verify'),required_verifier_id='verifier1',
       required_case_ids=('dev1','heldout1'),max_payload_bytes=10000000,schedule_window_seconds=60.)
    return env,cat,req,HostPackagingPolicy(),trust,pem


def derive(parts):
    env,cat,req,pol,trust,_=parts
    return derive_package_plan(env,cat,req,pol,trusted_keys=trust,now=NOW,trusted_catalog_digests=(cat.digest,))


def test_signed_bound_deterministic_plan_minimum_registered_coverage_no_grants():
    values=setup();plan=derive(values)
    assert plan.status=='reviewable' and plan.selected_candidate_id=='python-baseline'
    assert plan.digest==derive(values).digest and not plan.grants_install_authority and not plan.native_resource_policy_changed
    assert dict(plan.cell_budgets)['nonblank_lines']<=400
    assert plan.directional_hdd_caps==( ('read_bytes_per_second',100000000),('write_bytes_per_second',100000000))
    feedback=forecast_error(plan,candidate_id='python-baseline',observed_elapsed_seconds=2.,observed_peak_memory_bytes=2000000,evidence_ref='independent-observation')
    assert feedback['elapsed_signed_error']==2.-plan.candidates[0].forecast_elapsed_seconds


def test_signed_identity_future_staleness_and_tampering_blocked():
    env,cat,req,pol,trust,pem=setup()
    for change in [{'host_id':'different'}, {'observed_at':(NOW-timedelta(hours=1)).isoformat()}, {'observed_at':(NOW+timedelta(seconds=1)).isoformat()}]:
        changed=env.measurement.model_copy(update=change)
        signed=sign_measurement(changed,pem,'fixture-key')
        assert derive_package_plan(signed,cat,req,pol,trusted_keys=trust,now=NOW,trusted_catalog_digests=(cat.digest,)).status=='blocked'
    tampered=env.model_copy(update={'measurement':env.measurement.model_copy(update={'ssd_free_bytes':9999999999999})})
    assert derive_package_plan(tampered,cat,req,pol,trusted_keys=trust,now=NOW,trusted_catalog_digests=(cat.digest,)).status=='blocked'


@pytest.mark.parametrize('changes,reason',[
 ({'ssd_free_bytes':64*1024**3},'ssd_install_peak_or_reserve_exceeded'),
 ({'memory_available_bytes':1},'aggregate_memory_pressure'),
 ({'controller_memory_current_bytes':8*1024**3},'aggregate_memory_pressure')])
def test_low_space_and_aggregate_pressure_reject(changes,reason):
    p=derive(setup(**changes));assert p.status=='blocked' and reason in p.candidates[0].reasons


def test_heterogeneous_clients_and_dependency_abi_checks():
    values=list(setup(os_id='windows',os_version='11',architecture='aarch64',glibc_version=None,python_abi='cpython-312-arm64'))
    assert derive(values).status=='reviewable'  # fixture provider, not native Windows acceptance
    cat=values[1];a=cat.artifacts[0].model_copy(update={'architecture':'x86_64','minimum_glibc':'2.39'})
    values[1]=cat.model_copy(update={'artifacts':(a,)})
    assert derive(values).status=='blocked'
    values=list(setup());cat=values[1]
    values[1]=cat.model_copy(update={'artifacts':(cat.artifacts[0].model_copy(update={'dependencies':('missing',)}),)})
    assert 'missing_dependency:baseline' in derive(values).candidates[0].reasons


def test_reduced_coverage_weaker_verifier_build_memory_and_schedule_rejected():
    for change,reason in [({'capabilities':('discover',)},'reduced_required_coverage'),
      ({'independent_verifier_id':'weaker'},'weaker_or_unknown_verification'),
      ({'baseline_case_ids':('dev1',)},'missing_required_verified_cases'),
      ({'build_required':True,'build_peak_memory_bytes':2*1024**3},'build_not_authorized_or_memory_exceeded'),
      ({'expected_cpu_seconds':1000.},'schedule_window_exceeded')]:
        values=list(setup());cat=values[1];values[1]=cat.model_copy(update={'candidates':(cat.candidates[0].model_copy(update=change),)})
        plan=derive(values);assert plan.status=='blocked' and reason in plan.candidates[0].reasons


def test_native_cell_without_exact_host_same_coverage_heldout_benchmark_never_selected():
    values=list(setup());cat=values[1];native=cat.artifacts[0].model_copy(update={'id':'rust','kind':'rust_cell','bytes':100,
      'cell_nonblank_lines':40,'cell_public_ops':1,'cell_direct_dependencies':0,'stripped_library_bytes':1000})
    c=cat.candidates[0].model_copy(update={'id':'rust-cell','artifact_ids':('rust',),'implementation':'rust_cell'})
    values[1]=cat.model_copy(update={'artifacts':cat.artifacts+(native,),'candidates':cat.candidates+(c,)})
    plan=derive(values);assert plan.selected_candidate_id=='python-baseline'
    assert any('native_requires_exact_host' in reason for reason in plan.candidates[1].reasons)
    bench=NativeBenchmark(observed_at=NOW.isoformat(),development_case_ids=('dev1',),host_id=values[0].measurement.host_id,host_hardware_sha256=hardware_digest(values[0].measurement),
      workload_sha256=SHA,incumbent_artifact_set_sha256=artifact_set_digest(cat.artifacts),candidate_artifact_set_sha256=artifact_set_digest((native,)),
      incumbent_verified_cases=('dev1','heldout1'),candidate_verified_cases=('dev1','heldout1'),heldout_case_ids=('heldout1',),
      independent_verifier_id='verifier1',incumbent_seconds=2.,candidate_seconds=1.,unsuccessful_trials=1,trial_evidence_refs=('fixture:all-trials',))
    values[1]=values[1].model_copy(update={'native_benchmarks':(bench,)})
    assert derive(values).selected_candidate_id=='rust-cell'
    observed=values[0].measurement
    changed=sign_measurement(observed.model_copy(update={'hdd_device_id':'replacement-hdd'}),values[5],'fixture-key')
    changed_values=[changed,*values[1:]]
    assert derive(changed_values).selected_candidate_id=='python-baseline'
    wrong=bench.model_copy(update={'candidate_verified_cases':('dev1',)})
    values[1]=values[1].model_copy(update={'native_benchmarks':(wrong,)})
    assert derive(values).selected_candidate_id=='python-baseline'


def test_catalog_claims_require_coordinator_pin_and_hardware_digest_covers_native_limits():
    env,cat,req,pol,trust,_=setup()
    untrusted=derive_package_plan(env,cat,req,pol,trusted_keys=trust,now=NOW)
    assert untrusted.status=='blocked' and untrusted.reasons==('artifact_catalog_not_pinned_by_coordinator',)
    original=hardware_digest(env.measurement)
    for change in [{'ssd_device_id':'different-ssd'},{'hdd_device_id':'different-hdd'},
                   {'hdd_read_bytes_per_second':1},{'hdd_write_bytes_per_second':1},
                   {'ssd_read_bytes_per_second':1},{'ssd_write_bytes_per_second':1},
                   {'controller_memory_high_bytes':4*1024**3}]:
        assert hardware_digest(env.measurement.model_copy(update=change))!=original


def test_historical_failures_retained_and_new_forecast_bound_cannot_grant_authority():
    values=list(setup());cat=values[1];aset=artifact_set_digest(cat.artifacts)
    history=tuple(HistoricalUsage(id='trial'+str(i),host_id='fixture-client',workload_sha256=SHA,artifact_set_sha256=aset,
      observed_at=(NOW-timedelta(hours=1)).isoformat(),outcome=outcome,input_bytes=100,elapsed_seconds=2.,peak_memory_bytes=2048**2,
      peak_scratch_bytes=50000,cpu_seconds=1.,cost_nusd=None,evidence_ref='fixture:'+outcome) for i,outcome in enumerate(['verified','failed','unresolved']))
    values[1]=cat.model_copy(update={'history':history});plan=derive(values)
    assert plan.candidates[0].matched_history_ids==('trial0',)
    assert plan.candidates[0].unsuccessful_history_ids==('trial1','trial2')
    assert plan.candidates[0].forecast_peak_memory_bytes>=2048**2
    assert not plan.grants_install_authority
    assert derive(setup(shared_reservations_verified=False)).status=='blocked'


def test_native_policy_workspace_is_valid_and_requires_real_artifact(tmp_path):
    import importlib.util,shutil
    from pathlib import Path
    root=Path(__file__).resolve().parents[1]/'native'
    spec=importlib.util.spec_from_file_location('cell_validator',root/'validate_cells.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    report=module.validate(root)
    assert report['source_validation']=='passed' and report['cells'][0]['public_operations']==['pack_profile']
    assert report['cells'][0]['status']=='pending_compile_and_exact_host_benchmark'
    with pytest.raises(ValueError):module.validate(root,require_artifacts=True)
    clone=tmp_path/'native';shutil.copytree(root,clone)
    (clone/'cells/stam-codec/build.rs').write_text('fn main() {}')
    with pytest.raises(ValueError):module.validate(clone)


def test_policy_hard_ceiling_and_failed_history_denominators_preserved():
    with pytest.raises(ValueError):HostPackagingPolicy(maximum_cell_nonblank_lines=401)
    values=list(setup());cat=values[1];aset=artifact_set_digest(cat.artifacts)
    history=tuple(HistoricalUsage(id='pattern'+str(i),host_id='fixture-client',workload_sha256=SHA,
        artifact_set_sha256=aset,observed_at=NOW.isoformat(),outcome='failed' if i==3 else 'verified',
        input_bytes=i+1,elapsed_seconds=float(i+1),peak_memory_bytes=100,peak_scratch_bytes=0,cpu_seconds=1.,
        evidence_ref='fixture:pattern'+str(i)) for i in range(4))
    values[1]=cat.model_copy(update={'history':history});plan=derive(values)
    assert len(plan.history_sample_ids)==4 and plan.historical_input_elapsed_correlation==1.
    assert plan.candidates[0].unsuccessful_history_ids==('pattern3',)
    assert plan.candidates[0].forecast_elapsed_interval_seconds[0]<=plan.candidates[0].forecast_elapsed_seconds


def test_native_validator_cannot_weaken_activation_or_hide_target_dependencies(tmp_path):
    import importlib.util,shutil,json
    from pathlib import Path
    source=Path(__file__).resolve().parents[1]/'native';root=tmp_path/'native';shutil.copytree(source,root)
    spec=importlib.util.spec_from_file_location('cell_validator_extra',root/'validate_cells.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    policy_path=root/'build-policy.json';original=policy_path.read_text()
    for flag,value in [('require_exact_host_independent_benchmark',False),('require_equal_correctness_coverage_and_verification',False),('default_implementation','rust')]:
        policy=json.loads(original);policy[flag]=value;policy_path.write_text(json.dumps(policy))
        with pytest.raises(ValueError):module.validate(root)
    policy_path.write_text(original)
    manifest=root/'cells/stam-codec/Cargo.toml'
    manifest.write_text(manifest.read_text()+ '\n[target.\'cfg(unix)\'.dependencies]\nhidden = "=1.2.3"\n')
    with pytest.raises(ValueError):module.validate(root)


def test_failed_peak_resource_consumption_is_not_omitted_from_forecast():
    values=list(setup());cat=values[1];sample=HistoricalUsage(id='failed-heavy',host_id='fixture-client',workload_sha256=SHA,
        artifact_set_sha256=artifact_set_digest(cat.artifacts),observed_at=NOW.isoformat(),outcome='failed',input_bytes=100,
        elapsed_seconds=50.,peak_memory_bytes=2*1024**3,peak_scratch_bytes=100000,cpu_seconds=49.,cost_nusd=2000,evidence_ref='fixture:failed-heavy')
    values[1]=cat.model_copy(update={'history':(sample,)})
    plan=derive(values)
    assert plan.candidates[0].forecast_peak_memory_bytes>=2*1024**3
    assert plan.candidates[0].forecast_elapsed_seconds>=50.
    assert plan.candidates[0].unsuccessful_history_ids==('failed-heavy',)
