import os
from pathlib import Path
import pytest
from meta_pipeline.estate import EstateProjection, SourceSpec, ExtractionRegistry

def test_mixed_sources_resume_lineage_and_corrections(tmp_path):
    live=tmp_path/'live'; live.mkdir(); (live/'report.txt').write_text('private')
    (live/'media').mkdir(); (live/'media'/'photo.png').write_bytes(b'fixture')
    backup=tmp_path/'backup';backup.mkdir(); (backup/'report.txt').write_text('old')
    db=tmp_path/'projection.db'; p=EstateProjection(db)
    p.register(SourceSpec(source_id='live',root=str(live),volume_id='local-fixture',reliable_file_ids=True))
    p.register(SourceSpec(source_id='snapshot',root=str(backup),provider='snapshot-fixture',volume_id='backup-fixture',retained_version='2026-01-01',lineage_source_id='live'))
    first=p.scan('live',max_entries=1)
    assert first['status']=='partially-scanned' and first['remaining']
    p=EstateProjection(db)
    assert p.scan('live')['status']=='fully-scanned-within-scope'
    assert p.scan('snapshot')['status']=='fully-scanned-within-scope'
    rows=p.query(name='report.txt')['results']
    assert len(rows)==2 and rows[0]['content_sha256'] is None
    assert rows[1]['lineage_source_id']=='live'
    assert rows[0]['extraction_status']=='not-extracted'
    p.correct('live','report.txt',['personal','financial'])
    assert p.query(label='financial')['results'][0]['user_labels']==['personal','financial']
    assert p.scan('live')['processed_this_call']==0
    assert p.query(label='financial')['results'][0]['user_labels']==['personal','financial']

def test_alias_symlink_exclusion_disconnected_and_unknown(tmp_path):
    root=tmp_path/'files';root.mkdir();(root/'secret').mkdir();(root/'secret'/'hidden').write_text('x')
    (root/'loop').symlink_to(root,target_is_directory=True)
    (root/'opaque.zzunknown').write_text('x')
    p=EstateProjection(tmp_path/'p.db')
    p.register(SourceSpec(source_id='one',root=str(root),volume_id='v',exclusions=['secret']))
    p.register(SourceSpec(source_id='alias',root=str(root),volume_id='v'))
    p.register(SourceSpec(source_id='offline',root=str(tmp_path/'missing'),volume_id='removable-fixture',available=False))
    assert p.scan('one')['status']=='fully-scanned-within-scope'
    assert p.scan('alias')['status']=='alias-not-scanned'
    assert p.scan('offline')['status']=='disconnected'
    rows=p.query(source_id='one')['results']
    assert len(rows)==3 and not any('secret' in r['path'] for r in rows)
    assert next(r for r in rows if r['path']=='loop')['kind']=='symlink'
    assert next(r for r in rows if r['path'].endswith('zzunknown'))['labels']==[]

def test_partial_failure_never_complete(tmp_path,monkeypatch):
    root=tmp_path/'files';root.mkdir();(root/'a').mkdir();(root/'b').write_text('b')
    p=EstateProjection(tmp_path/'p.db');p.register(SourceSpec(source_id='s',root=str(root),volume_id='v'))
    original=os.scandir
    def deny(path):
        if (Path(os.readlink(f'/proc/self/fd/{path}')).name if isinstance(path,int) else Path(path).name)=='a':raise PermissionError('fixture')
        return original(path)
    monkeypatch.setattr(os,'scandir',deny)
    report=p.scan('s')
    assert report['status']=='partially-scanned'
    assert report['errors'][0]['error_type']=='PermissionError'
    assert len(p.query(name='b')['results'])==1

def test_bounds_and_versions(tmp_path):
    root=tmp_path/'files';root.mkdir();(root/'a').touch();(root/'b').touch()
    p=EstateProjection(tmp_path/'p.db');s=SourceSpec(source_id='s',root=str(root),volume_id='v');p.register(s)
    with pytest.raises(ValueError): p.register(s.model_copy(update={'volume_id':'other'}))
    with pytest.raises(ValueError):p.scan('s',max_entries=0)
    result=p.scan('s',max_children=1)
    assert result['status']=='partially-scanned' and result['errors']
    with pytest.raises(ValueError):p.register(SourceSpec(source_id='bad',root=str(root),volume_id='v',exclusions=['../escape']))

def test_media_requires_real_explicit_binding():
    registry=ExtractionRegistry();a={'artifact_id':'photo','mime':'image/png','content_sha256':'a'*64,'source_version':'v','version_id':'v1','source_id':'fixture','modality':'image','provenance':['fixture-source-lock']}
    assert registry.extract(a)['status']=='blocked'
    assert registry.extract(a,authorized=True)['status']=='pending'
    registry.register('image/png','fixture-v1',lambda _: {'fixture_only':True})
    with pytest.raises(ValueError):registry.register('image/png','v2',lambda _: None)
    assert registry.extract({'mime':'image/png'},authorized=True)['status']=='blocked'
    assert registry.extract(a,authorized=True)['source_content_sha256']=='a'*64

def test_full_content_identity_hardlinks_copies_and_versions(tmp_path):
    root=tmp_path/'live';root.mkdir();(root/'a.txt').write_text('same');os.link(root/'a.txt',root/'link.txt');(root/'copy.txt').write_text('same')
    retained=tmp_path/'snapshot';retained.mkdir();(retained/'a.txt').write_text('same')
    p=EstateProjection(tmp_path/'p.db')
    p.register(SourceSpec(source_id='live',root=str(root),volume_id='local',reliable_file_ids=True))
    p.register(SourceSpec(source_id='backup',root=str(retained),volume_id='snapshot-fixture',retained_version='one',lineage_source_id='live'))
    p.scan('live');p.scan('backup')
    with pytest.raises(PermissionError):p.hash_content('live','a.txt')
    for source,path in [('live','a.txt'),('live','link.txt'),('live','copy.txt'),('backup','a.txt')]:
        result=p.hash_content(source,path,authorized=True)
    copies=p.query(content_sha256=result['content_sha256'])['results']
    assert len(copies)==4
    assert len(p.query(file_id=next(x['file_id'] for x in copies if x['path']=='link.txt'))['results'])==2
    assert len(p.query(lineage_source_id='live')['results'])==2
    (root/'copy.txt').write_text('changed')
    with pytest.raises(ValueError):p.hash_content('live','copy.txt',authorized=True)

def test_concurrent_tree_changes_do_not_claim_complete(tmp_path):
    root=tmp_path/'root';root.mkdir();(root/'a').touch()
    p=EstateProjection(tmp_path/'p.db');p.register(SourceSpec(source_id='s',root=str(root),volume_id='v'))
    assert p.scan('s',max_entries=1)['status']=='partially-scanned'
    (root/'unobserved').touch()
    result=p.scan('s')
    assert result['status']=='partially-scanned' and result['errors']

def test_reconciliation_retains_failures_history_and_user_corrections(tmp_path):
    root=tmp_path/'root';root.mkdir();(root/'a.txt').write_text('a')
    p=EstateProjection(tmp_path/'p.db');p.register(SourceSpec(source_id='s',root=str(root),volume_id='v'))
    p.scan('s',max_entries=1);(root/'new.txt').write_text('b')
    assert p.scan('s')['errors']
    p.correct('s','a.txt',['personal'])
    p.reconcile('s')
    assert p.scan('s')['status']=='fully-scanned-within-scope'
    assert len(p.query(source_id='s')['results'])==3
    assert p.query(label='personal')['results'][0]['path']=='a.txt'
    assert p.history('s')['scans'][0]['errors']
    assert p.history('s')['observations']

def test_state_symlinks_rejected_and_permissions_private(tmp_path):
    external=tmp_path/'external';external.touch();linked=tmp_path/'linked';linked.symlink_to(external)
    with pytest.raises(OSError):EstateProjection(linked)
    p=EstateProjection(tmp_path/'private.db')
    assert (tmp_path/'private.db').stat().st_mode & 0o777==0o600

def test_directory_replacement_during_scan_cannot_escape(tmp_path,monkeypatch):
    root=tmp_path/'root';root.mkdir();(root/'branch').mkdir();(root/'branch'/'inside').touch()
    outside=tmp_path/'outside';outside.mkdir();(outside/'sensitive').touch()
    p=EstateProjection(tmp_path/'p.db');p.register(SourceSpec(source_id='s',root=str(root),volume_id='v'))
    original=os.scandir;swapped=False
    def replace(path):
        nonlocal swapped
        resolved=Path(os.readlink(f'/proc/self/fd/{path}')) if isinstance(path,int) else Path(path)
        if resolved.name=='branch' and not swapped:
            (root/'branch').rename(root/'old-branch');(root/'branch').symlink_to(outside,target_is_directory=True);swapped=True
        return original(path)
    monkeypatch.setattr(os,'scandir',replace)
    report=p.scan('s')
    assert report['status']=='partially-scanned' and report['errors']
    assert not p.query(name='sensitive')['results']


def test_correction_bound_to_observed_version_not_reused_path(tmp_path):
    root=tmp_path/'root';root.mkdir();file=root/'a.txt';file.write_text('original')
    p=EstateProjection(tmp_path/'p.db')
    p.register(SourceSpec(source_id='s',root=str(root),volume_id='fixture',reliable_file_ids=False));p.scan('s')
    p.correct('s','a.txt',['user-only-original'])
    original=p.query(name='a.txt')['results'][0]
    assert original['identity_uncertain'] and original['file_id'] is None
    file.rename(root/'retained-original.txt');file.write_text('replacement')
    p.reconcile('s');p.scan('s')
    replacement=p.query(name='a.txt')['results'][0]
    assert 'user-only-original' not in replacement.get('user_labels',[])
    assert replacement['pending_user_labels']==['user-only-original']
    assert replacement['user_correction_status']=='pending_confirmation_version_changed'
    assert not p.query(label='user-only-original')['results']
    assert p.corrections('s')[0]['bound_fingerprint']==original['observed_version_token']


def test_unchanged_correction_survives_reconcile_and_hash_enrichment(tmp_path):
    root=tmp_path/'root';root.mkdir();(root/'a.txt').write_text('unchanged')
    p=EstateProjection(tmp_path/'p.db')
    p.register(SourceSpec(source_id='s',root=str(root),volume_id='fixture',reliable_file_ids=False));p.scan('s')
    p.correct('s','a.txt',['confirmed-user-label'])
    before=p.query(name='a.txt')['results'][0]['observed_version_token']
    p.hash_content('s','a.txt',authorized=True)
    assert p.query(label='confirmed-user-label')['results'][0]['observed_version_token']==before
    p.reconcile('s');p.scan('s')
    after=p.query(label='confirmed-user-label')['results'][0]
    assert after['observed_version_token']==before and after['user_correction_status']=='applied'
    p.hash_content('s','a.txt',authorized=True)
    assert p.query(label='confirmed-user-label')['results'][0]['user_labels']==['confirmed-user-label']


def test_inplace_change_with_restored_mtime_requires_confirmed_rebind(tmp_path):
    root=tmp_path/'root';root.mkdir();file=root/'a.txt';file.write_text('aaaa')
    p=EstateProjection(tmp_path/'p.db');p.register(SourceSpec(source_id='s',root=str(root),volume_id='v'));p.scan('s')
    p.correct('s','a.txt',['prior-label']);before=file.stat()
    file.write_text('bbbb');os.utime(file,ns=(before.st_atime_ns,before.st_mtime_ns))
    with pytest.raises(ValueError,match='version changed'):
        p.hash_content('s','a.txt',authorized=True)
    p.reconcile('s');p.scan('s')
    assert not p.query(label='prior-label')['results']
    p.correct('s','a.txt',['newly-confirmed'])
    assert p.query(label='newly-confirmed')['results'][0]['user_labels']==['newly-confirmed']
    records=p.history('s')['corrections']
    assert any(r['record']=='history' and r['labels']==['prior-label'] for r in records)
    assert any(r['record']=='current_correction' and r['labels']==['newly-confirmed'] for r in records)


def test_path_only_legacy_corrections_migrate_pending_without_loss(tmp_path):
    import json
    import sqlite3
    root=tmp_path/'root';root.mkdir();(root/'a.txt').write_text('fixture')
    database=tmp_path/'p.db';p=EstateProjection(database)
    p.register(SourceSpec(source_id='s',root=str(root),volume_id='v'));p.scan('s')
    with sqlite3.connect(database) as db:
        db.execute('DROP TABLE estate_corrections')
        db.execute('CREATE TABLE estate_corrections(source TEXT,path TEXT,labels TEXT NOT NULL,PRIMARY KEY(source,path))')
        db.execute('INSERT INTO estate_corrections VALUES(?,?,?)',('s','a.txt',json.dumps(['legacy-confirmation'])))
    p=EstateProjection(database)
    assert not p.query(label='legacy-confirmation')['results']
    observed=p.query(name='a.txt')['results'][0]
    assert observed['pending_user_labels']==['legacy-confirmation']
    assert observed['user_correction_status']=='pending_confirmation_legacy_path_only'
    assert p.corrections('s')[0]['bound_fingerprint'] is None
    p.correct('s','a.txt',['explicitly-reconfirmed'])
    assert p.query(label='explicitly-reconfirmed')['results']
    assert any(r['labels']==['legacy-confirmation'] and r['bound_fingerprint'] is None for r in p.corrections('s'))


def test_old_observation_cannot_gain_identity_from_current_path(tmp_path):
    import json
    root=tmp_path/'root';root.mkdir();(root/'a.txt').write_text('fixture')
    p=EstateProjection(tmp_path/'p.db');p.register(SourceSpec(source_id='s',root=str(root),volume_id='v'));p.scan('s')
    with p.connect() as db:
        old=json.loads(db.execute("SELECT observation FROM estate_entries WHERE path='a.txt'").fetchone()[0])
        old.pop('ctime_ns');old.pop('source_root_identity')
        db.execute("UPDATE estate_entries SET observation=? WHERE path='a.txt'",(json.dumps(old),))
    with pytest.raises(ValueError,match='reconcile'):
        p.correct('s','a.txt',['cannot-auto-bind'])
    with pytest.raises(ValueError,match='reconcile'):
        p.hash_content('s','a.txt',authorized=True)
    p.reconcile('s');p.scan('s');p.correct('s','a.txt',['fresh-confirmation'])
    assert p.query(label='fresh-confirmation')['results']


def test_all_explicit_label_revisions_are_preserved(tmp_path):
    root=tmp_path/'root';root.mkdir();(root/'a.txt').write_text('fixture')
    p=EstateProjection(tmp_path/'p.db');p.register(SourceSpec(source_id='s',root=str(root),volume_id='v'));p.scan('s')
    p.correct('s','a.txt',['first']);p.correct('s','a.txt',['second']);p.correct('s','a.txt',['second'])
    records=p.corrections('s')
    assert len(records)==2
    assert records[0]['status']=='applied' and records[0]['labels']==['second']
    assert records[1]['status']=='preserved_prior_correction' and records[1]['labels']==['first']
