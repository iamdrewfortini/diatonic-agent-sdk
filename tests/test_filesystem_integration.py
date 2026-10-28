import hashlib
import json
import os
import sqlite3
import pytest
from meta_pipeline.filesystem import FileOperation,LocalFileAdapter

def adapter(tmp_path,auth={'copy','create'}):
    root=tmp_path/'root';root.mkdir(exist_ok=True)
    return root,LocalFileAdapter(root,authorized_operations=auth,journal=tmp_path/'journal.db')

def test_copy_create_verify_duplicate_and_stale(tmp_path):
    root,a=adapter(tmp_path);(root/'source').write_bytes(b'hello')
    op=FileOperation(operation='copy',request_id='c',source='source',destination='copy',expected_source_sha256=hashlib.sha256(b'hello').hexdigest())
    result=a.execute(op);assert a.verify(op,result)
    assert a.execute(op)==result
    with pytest.raises(ValueError): a.execute(op.model_copy(update={'destination':'different'}))
    (root/'copy').write_bytes(b'changed')
    assert not a.verify(op,result)
    create=FileOperation(operation='create',request_id='new',destination='new',content_utf8='text')
    assert a.verify(create,a.execute(create))
    stale=op.model_copy(update={'request_id':'stale','destination':'stale'})
    (root/'source').write_bytes(b'changed')
    with pytest.raises(ValueError):a.execute(stale)
    assert a.execute(stale)['status']=='unresolved'
    assert not (root/'stale').exists()

def test_authority_collision_traversal_and_symlink(tmp_path):
    root,a=adapter(tmp_path,{'create'})
    with pytest.raises(ValueError):FileOperation(operation='create',request_id='x',destination='../escape',content_utf8='x')
    op=FileOperation(operation='copy',request_id='x',source='a',destination='b',expected_source_sha256='a'*64)
    with pytest.raises(PermissionError):a.execute(op)
    (root/'exists').write_text('retain')
    c=FileOperation(operation='create',request_id='collision',destination='exists',content_utf8='replace')
    with pytest.raises(FileExistsError):a.execute(c)
    assert (root/'exists').read_text()=='retain'
    assert a.execute(c)['status']=='unresolved'
    outside=tmp_path/'outside';outside.mkdir();(root/'link').symlink_to(outside,target_is_directory=True)
    with pytest.raises(OSError):a.execute(c.model_copy(update={'request_id':'symlink','destination':'link/escaped'}))
    assert not (outside/'escaped').exists()

def test_crash_after_publication_reconciles_without_second_effect(tmp_path,monkeypatch):
    root,a=adapter(tmp_path)
    op=FileOperation(operation='create',request_id='crash',destination='result',content_utf8='payload')
    original=a.verify
    monkeypatch.setattr(a,'verify',lambda *_: (_ for _ in ()).throw(RuntimeError('injected crash')))
    with pytest.raises(RuntimeError):a.execute(op)
    inode=(root/'result').stat().st_ino
    monkeypatch.setattr(a,'verify',original)
    restarted=LocalFileAdapter(root,authorized_operations={'create'},journal=tmp_path/'journal.db')
    result=restarted.execute(op)
    assert result['status']=='completed' and restarted.verify(op,result)
    assert (root/'result').stat().st_ino==inode
    assert not list(root.glob('.meta-intent-*'))

def test_root_replacement_revokes_authorization(tmp_path):
    root,a=adapter(tmp_path)
    root.rename(tmp_path/'old');root.mkdir()
    with pytest.raises(ValueError):a.execute(FileOperation(operation='create',request_id='x',destination='x',content_utf8='x'))
    assert not (root/'x').exists()

def test_completed_crash_stage_cleanup_is_reconciled(tmp_path,monkeypatch):
    root,a=adapter(tmp_path)
    op=FileOperation(operation='create',request_id='cleanup-crash',destination='result',content_utf8='payload')
    unlink=os.unlink
    def crash_unlink(*args,**kwargs): raise RuntimeError('crash after completed journal before cleanup')
    monkeypatch.setattr(os,'unlink',crash_unlink)
    with pytest.raises(RuntimeError):a.execute(op)
    assert list(root.glob('.meta-intent-*'))
    monkeypatch.setattr(os,'unlink',unlink)
    result=a.execute(op)
    assert result['status']=='completed' and a.verify(op,result)
    assert not list(root.glob('.meta-intent-*'))
