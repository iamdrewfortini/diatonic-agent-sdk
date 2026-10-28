import fcntl
import hashlib
import os
import sqlite3
from pathlib import Path
import pytest
from meta_pipeline.maintenance import maintain,validate_policy


def fixture(tmp_path):
    root=tmp_path/'private';root.mkdir(mode=0o700);(root/'scratch').mkdir()
    p=root/'scratch/finished.tmp';p.write_bytes(b'verified disposable scratch')
    row={'path':'scratch/finished.tmp','bytes':p.stat().st_size,'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),
         'completed_at':100.,'state':'verified_complete','verification_ref':'independent-fixture-verifier:1'}
    policy={'version':'maintenance-v1','retention_seconds':10,'minimum_free_bytes':64*1024**3,'completed_files':[row]}
    return root,p,policy


def test_default_dryrun_retention_and_verified_cleanup(tmp_path):
    root,p,policy=fixture(tmp_path)
    assert maintain(root,policy,now=105)['results'][0]['status']=='retained_by_policy'
    assert maintain(root,policy,now=120)['results'][0]['status']=='would_delete_verified_scratch' and p.exists()
    result=maintain(root,policy,apply=True,now=120)
    assert result['reclaimed_bytes']==len(b'verified disposable scratch') and not p.exists()
    assert maintain(root,policy,apply=True,now=120)['results'][0]['status']=='already_absent'


def test_unknown_state_changed_bytes_symlinks_hardlinks_and_versions_preserved(tmp_path):
    root,p,policy=fixture(tmp_path)
    with pytest.raises(ValueError):validate_policy({**policy,'completed_files':[{**policy['completed_files'][0],'state':'unresolved'}]})
    p.write_bytes(b'changed bytes')
    assert maintain(root,policy,apply=True,now=120)['results'][0]['status']=='blocked' and p.exists()
    p.unlink();target=tmp_path/'outside';target.write_text('private')
    p.symlink_to(target)
    assert maintain(root,policy,apply=True,now=120)['results'][0]['status']=='blocked' and target.read_text()=='private'
    p.unlink();p.write_bytes(b'verified disposable scratch');os.link(p,root/'scratch/other.tmp')
    assert maintain(root,policy,apply=True,now=120)['results'][0]['status']=='blocked' and p.exists()


@pytest.mark.parametrize('name',['../outside','scratch/../ledger.sqlite3','scratch/usage.sqlite3','state/activity.sqlite3','scratch/source.tar.gz','/scratch/a','scratch//a','scratch/a\\b'])
def test_ledger_audit_sources_and_traversal_not_cleanup_candidates(tmp_path,name):
    root,p,policy=fixture(tmp_path)
    with pytest.raises(ValueError):maintain(root,{**policy,'completed_files':[{**policy['completed_files'][0],'path':name}]},apply=True)
    assert p.exists()


def test_parent_symlink_and_budget_no_work_on_unapproved_paths(tmp_path):
    root,p,policy=fixture(tmp_path);p.unlink();(root/'scratch').rmdir()
    target=tmp_path/'elsewhere';target.mkdir();(root/'scratch').symlink_to(target,target_is_directory=True)
    result=maintain(root,policy,apply=True,now=120)
    assert result['results'][0]['status']=='blocked'
    assert maintain(root,{**policy,'max_files':0},apply=True,now=120)['results'][0]['status']=='pending_budget'


def test_existing_lock_and_private_ownership_enforced(tmp_path):
    root,p,policy=fixture(tmp_path)
    with (root/'.maintenance.lock').open('w') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        assert maintain(root,policy,apply=True,now=120)['status']=='busy'
    root.chmod(0o777)
    with pytest.raises(ValueError):maintain(root,policy,apply=True,now=120)


def projection(root,*,incremental=True,ledger=False):
    (root/'index').mkdir();p=root/'index/projection.sqlite3'
    with sqlite3.connect(p) as db:
        if incremental:db.execute('PRAGMA auto_vacuum=INCREMENTAL')
        db.execute('CREATE TABLE maintenance_scope(kind TEXT)');db.execute("INSERT INTO maintenance_scope VALUES('rebuildable_projection')")
        db.execute('CREATE TABLE items(value TEXT)');db.execute("INSERT INTO items VALUES('retain this observation')")
        if ledger:db.execute('CREATE TABLE calls(reserved INTEGER)')
    return p


def test_incremental_projection_maintenance_preserves_rows_and_requires_scope(tmp_path,monkeypatch):
    from types import SimpleNamespace
    monkeypatch.setattr(os,'statvfs',lambda _:SimpleNamespace(f_bavail=200*1024**3,f_frsize=1))
    root,p,policy=fixture(tmp_path);dbpath=projection(root)
    policy={**policy,'completed_files':[],'projections':['index/projection.sqlite3']}
    assert maintain(root,policy)['results'][0]['status']=='would_checkpoint_incremental_vacuum'
    result=maintain(root,policy,apply=True)
    assert result['results'][0]['status']=='projection_maintained'
    with sqlite3.connect(dbpath) as db:assert db.execute('SELECT value FROM items').fetchall()==[('retain this observation',)]


def test_full_vacuum_not_automatic_free_space_and_ledger_database_guards(tmp_path,monkeypatch):
    from types import SimpleNamespace
    monkeypatch.setattr(os,'statvfs',lambda _:SimpleNamespace(f_bavail=200*1024**3,f_frsize=1))
    root,p,policy=fixture(tmp_path);dbpath=projection(root,incremental=False)
    policy={**policy,'completed_files':[],'projections':['index/projection.sqlite3']}
    assert maintain(root,policy,apply=True)['results'][0]['status']=='pending_offline_vacuum'
    assert maintain(root,{**policy,'minimum_free_bytes':10**30},apply=True)['results'][0]['reason']=='free_space_reserve'
    with sqlite3.connect(dbpath) as db:db.execute('CREATE TABLE events(payload TEXT)')
    assert maintain(root,policy,apply=True)['results'][0]['status']=='blocked'


def test_separate_private_runtime_lock_allows_readonly_control_root(tmp_path):
    root,p,policy=fixture(tmp_path);locks=tmp_path/'locks';locks.mkdir(mode=0o700)
    report=maintain(root,policy,now=120,lock_file=locks/'lock')
    assert report['status']=='completed' and not (root/'.maintenance.lock').exists()
    assert (locks/'lock').exists()
    locks.chmod(0o755)
    with pytest.raises(ValueError):maintain(root,policy,lock_file=locks/'lock')


def test_special_scratch_file_rejected_without_blocking(tmp_path):
    root,p,policy=fixture(tmp_path);p.unlink();os.mkfifo(p)
    result=maintain(root,policy,apply=True,now=120)
    assert result['results'][0]['status']=='blocked' and p.exists()


def test_production_reserve_cannot_be_lowered_by_policy(tmp_path):
    root,p,policy=fixture(tmp_path)
    for reserve in [0,64*1024**3-1]:
        with pytest.raises(ValueError):maintain(root,{**policy,'minimum_free_bytes':reserve},apply=True,now=120)
    assert p.exists()


def test_name_replacement_before_rename_is_quarantined_and_never_deleted(tmp_path,monkeypatch):
    root,p,policy=fixture(tmp_path);original=p.read_bytes();replacement=b'unapproved replacement bytes'
    native_rename=os.rename;replaced=False
    def replace_then_rename(src,dst,**kwargs):
        nonlocal replaced
        if src=='finished.tmp' and not replaced:
            replaced=True
            native_rename(src,'writer-retained.tmp',src_dir_fd=kwargs['src_dir_fd'],dst_dir_fd=kwargs['src_dir_fd'])
            p.write_bytes(replacement)
        return native_rename(src,dst,**kwargs)
    monkeypatch.setattr(os,'rename',replace_then_rename)
    result=maintain(root,policy,apply=True,now=120)
    assert result['status']=='completed_with_pending' and result['deleted_files']==0
    outcome=result['results'][0]
    assert outcome['status']=='unresolved_quarantine'
    assert (root/outcome['quarantine_path']).read_bytes()==replacement
    assert (root/'scratch/writer-retained.tmp').read_bytes()==original


def test_growing_scratch_hash_stops_at_admitted_size(tmp_path,monkeypatch):
    root,p,policy=fixture(tmp_path);native_read=os.read;grew=False
    def grow(fd,n):
        nonlocal grew
        chunk=native_read(fd,n)
        if chunk and not grew:
            grew=True
            with p.open('ab') as stream:stream.write(b'x'*10000)
        return chunk
    monkeypatch.setattr(os,'read',grow)
    result=maintain(root,policy,apply=True,now=120)
    assert result['results'][0]['status']=='blocked' and p.stat().st_size>policy['completed_files'][0]['bytes']


def test_policy_fifo_and_growth_rejected_without_blocking(tmp_path,monkeypatch):
    from meta_pipeline.maintenance import _read_json
    p=tmp_path/'fifo';os.mkfifo(p)
    with pytest.raises(ValueError):_read_json(p)
    p.unlink();p.write_text('{}');native_read=os.read
    def grow(fd,n):
        raw=native_read(fd,n)
        with p.open('ab') as stream:stream.write(b' '*(2*1024**2))
        return raw
    monkeypatch.setattr(os,'read',grow)
    with pytest.raises(ValueError):_read_json(p)


@pytest.mark.parametrize('path',['index/foo.sqlite3?other.sqlite3','index/foo#other.sqlite3','index/foo%3fother.sqlite3'])
def test_projection_uri_reserved_characters_cannot_redirect_bound_file(path):
    with pytest.raises(ValueError):validate_policy({'version':'maintenance-v1','projections':[path]})
