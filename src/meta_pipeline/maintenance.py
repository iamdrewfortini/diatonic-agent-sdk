"""Bounded maintenance of explicitly approved application scratch/projections.

No recursive cleanup, retention inference, ledger/audit deletion or full VACUUM.
A completed file needs a separately supplied verifier reference and exact digest.
"""
from __future__ import annotations
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import secrets
import time


MINIMUM_SSD_RESERVE = 64*1024**3

FORBIDDEN = ('audit', 'ledger', 'usage', 'activity', 'source', 'archive', 'policy', 'claim')


def _canonical(data):
    return json.dumps(data,sort_keys=True,separators=(',',':'),allow_nan=False).encode()


def _read_json(path, limit=1024**2):
    flags=os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK
    fd=os.open(path,flags)
    try:
        info=os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size>limit:
            raise ValueError('Bounded regular maintenance policy required')
        raw=os.read(fd,limit+1)
        after=os.fstat(fd)
        if (len(raw)>limit or len(raw)!=info.st_size or
                (info.st_size,info.st_mtime_ns,info.st_ctime_ns)!=(after.st_size,after.st_mtime_ns,after.st_ctime_ns)):
            raise ValueError('Maintenance policy changed during bounded read')
        def unique(pairs):
            out={}
            for k,v in pairs:
                if k in out:raise ValueError('Duplicate policy field')
                out[k]=v
            return out
        return json.loads(raw,object_pairs_hook=unique)
    finally:os.close(fd)


def _relative(name, namespace):
    if not isinstance(name,str) or not name or '\\' in name or '\x00' in name or any(c in name for c in '?#%'):
        raise ValueError('Invalid maintenance path')
    parts=name.split('/')
    if (parts[0]!=namespace or any(p in ('','.','..') for p in parts) or len(parts)<2 or
            any(any(word in p.lower() for word in FORBIDDEN) for p in parts[1:])):
        raise ValueError('Path is outside permitted maintenance namespace')
    return parts


def _parent(rootfd,parts):
    current=os.dup(rootfd)
    try:
        for part in parts[:-1]:
            nextfd=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=current)
            os.close(current);current=nextfd
        return current
    except BaseException:
        os.close(current);raise


def validate_policy(policy):
    if not isinstance(policy,dict) or set(policy)-{'version','retention_seconds','max_files','max_bytes','minimum_free_bytes','max_projection_bytes','max_vacuum_pages','max_runtime_seconds','completed_files','projections'}:
        raise ValueError('Unknown maintenance policy fields')
    if policy.get('version')!='maintenance-v1':raise ValueError('Unknown maintenance policy version')
    defaults={'retention_seconds':86400,'max_files':100,'max_bytes':1024**3,
        'minimum_free_bytes':64*1024**3,'max_projection_bytes':256*1024**2,
        'max_vacuum_pages':1024,'max_runtime_seconds':30}
    p={**defaults,**policy}
    for name in defaults:
        if type(p[name]) is not int or p[name]<0 or (name=='max_runtime_seconds' and not 1<=p[name]<=300):
            raise ValueError('Maintenance limits must be bounded nonnegative integers')
    if p['minimum_free_bytes']<MINIMUM_SSD_RESERVE:
        raise ValueError('Production SSD reserve cannot be weakened below 64 GiB')
    if p['max_files']>10000 or p['max_vacuum_pages']>100000 or p['max_bytes']>100*1024**3:
        raise ValueError('Maintenance policy exceeds hard limits')
    for collection in ['completed_files','projections']:
        if not isinstance(p.get(collection,[]),list) or len(p.get(collection,[]))>10000:
            raise ValueError('Bounded maintenance allowlist required')
        p.setdefault(collection,[])
    paths=set()
    for row in p['completed_files']:
        if not isinstance(row,dict) or set(row)!={'path','sha256','bytes','completed_at','state','verification_ref'}:
            raise ValueError('Explicit completion record required')
        _relative(row['path'],'scratch')
        if (row['path'] in paths or row['state']!='verified_complete' or not isinstance(row['verification_ref'],str) or
                not row['verification_ref'] or len(row['sha256'])!=64 or any(c not in '0123456789abcdef' for c in row['sha256']) or
                type(row['bytes']) is not int or row['bytes']<0 or type(row['completed_at']) not in (int,float) or
                not 0<=row['completed_at']<float('inf')):
            raise ValueError('Invalid or unresolved completion record')
        paths.add(row['path'])
    for name in p['projections']:
        _relative(name,'index')
        if not name.endswith('.sqlite3') or name in paths:raise ValueError('Dedicated SQLite projection required')
        paths.add(name)
    return p


def maintain(root, policy, *, apply=False, now=None, lock_file=None):
    policy=validate_policy(policy);root=Path(root)
    now=time.time() if now is None else now
    started=time.monotonic();deadline=started+policy['max_runtime_seconds']
    rootfd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    lockfd=None;lockparent=None;rows=[];reclaimed=0;deleted=0;checked_files=0;checked_bytes=0
    try:
        info=os.fstat(rootfd)
        if info.st_uid!=os.geteuid() or info.st_mode&0o022:
            raise ValueError('Maintenance root must be privately owned by service identity')
        if lock_file is None:
            lockparent=os.dup(rootfd);lockname='.maintenance.lock'
        else:
            lockpath=Path(lock_file)
            lockparent=os.open(lockpath.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            parentinfo=os.fstat(lockparent)
            if parentinfo.st_uid!=os.geteuid() or parentinfo.st_mode&0o077:
                raise ValueError('External lock directory must be privately service-owned')
            lockname=lockpath.name
        lockfd=os.open(lockname,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600,dir_fd=lockparent)
        lockinfo=os.fstat(lockfd)
        if not stat.S_ISREG(lockinfo.st_mode) or lockinfo.st_uid!=os.geteuid() or lockinfo.st_nlink!=1:
            raise ValueError('Unsafe maintenance lock')
        try:fcntl.flock(lockfd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:return {'status':'busy','apply':apply,'results':[],'reclaimed_bytes':0}
        for record in policy['completed_files']:
            outcome={'path':record['path'],'verification_ref':record['verification_ref']}
            if time.monotonic()>=deadline or checked_files>=policy['max_files'] or checked_bytes+record['bytes']>policy['max_bytes']:
                rows.append({**outcome,'status':'pending_budget'});continue
            if now-record['completed_at']<policy['retention_seconds']:
                rows.append({**outcome,'status':'retained_by_policy'});continue
            checked_files+=1;checked_bytes+=record['bytes']
            parent=None;fd=None
            try:
                parent=_parent(rootfd,_relative(record['path'],'scratch'))
                leaf=record['path'].split('/')[-1]
                fd=os.open(leaf,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent);before=os.fstat(fd)
                if not stat.S_ISREG(before.st_mode) or before.st_uid!=os.geteuid() or before.st_nlink!=1 or before.st_size!=record['bytes']:
                    raise ValueError('Scratch identity/type/ownership changed')
                h=hashlib.sha256();readbytes=0
                while chunk:=os.read(fd,1024**2):
                    readbytes+=len(chunk)
                    if readbytes>record['bytes']:raise ValueError('Scratch grew beyond admitted hash bound')
                    if time.monotonic()>=deadline:raise TimeoutError('Maintenance runtime bound')
                    h.update(chunk)
                after=os.fstat(fd);current=os.stat(leaf,dir_fd=parent,follow_symlinks=False)
                identity=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
                if identity(before)!=identity(after) or identity(after)!=identity(current) or h.hexdigest()!=record['sha256']:
                    raise ValueError('Scratch version/digest changed')
                if apply:
                    # Atomically move the named object into a new private quarantine
                    # before deciding which inode to delete. A replacement between
                    # stat and rename is retained rather than mistaken for approval.
                    qname='.maintenance-quarantine-'+secrets.token_hex(16)
                    os.mkdir(qname,0o700,dir_fd=parent)
                    qfd=os.open(qname,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
                    qrelative='/'.join(record['path'].split('/')[:-1]+[qname,'candidate'])
                    moved=False
                    try:
                        os.rename(leaf,'candidate',src_dir_fd=parent,dst_dir_fd=qfd);moved=True
                        os.fsync(parent);os.fsync(qfd)
                        qfile=os.open('candidate',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=qfd)
                        try:
                            qbefore=os.fstat(qfile)
                            stable=lambda st:(st.st_dev,st.st_ino,st.st_size,st.st_mtime_ns)
                            if (stable(qbefore)!=stable(after) or not stat.S_ISREG(qbefore.st_mode) or
                                    qbefore.st_nlink!=1 or qbefore.st_uid!=os.geteuid()):
                                raise ValueError('Source name changed before quarantine')
                            qhash=hashlib.sha256();qbytes=0
                            while chunk:=os.read(qfile,1024**2):
                                qbytes+=len(chunk)
                                if qbytes>record['bytes'] or time.monotonic()>=deadline:
                                    raise ValueError('Quarantined object changed or exceeded budget')
                                qhash.update(chunk)
                            qafter=os.fstat(qfile);qcurrent=os.stat('candidate',dir_fd=qfd,follow_symlinks=False)
                            if (identity(qbefore)!=identity(qafter) or identity(qafter)!=identity(qcurrent) or
                                    qhash.hexdigest()!=record['sha256']):
                                raise ValueError('Quarantined object identity/digest changed')
                            os.unlink('candidate',dir_fd=qfd);os.fsync(qfd)
                        finally:os.close(qfile)
                    except (OSError,ValueError,TimeoutError) as exc:
                        rows.append({**outcome,'status':'unresolved_quarantine' if moved else 'blocked',
                            'reason':type(exc).__name__,'quarantine_path':qrelative if moved else None})
                        continue
                    finally:os.close(qfd)
                    os.rmdir(qname,dir_fd=parent);os.fsync(parent)
                    reclaimed+=before.st_size;deleted+=1
                rows.append({**outcome,'status':'deleted_verified_scratch' if apply else 'would_delete_verified_scratch','bytes':before.st_size})
            except FileNotFoundError:rows.append({**outcome,'status':'already_absent'})
            except (OSError,ValueError,TimeoutError) as exc:rows.append({**outcome,'status':'blocked','reason':type(exc).__name__})
            finally:
                if fd is not None:os.close(fd)
                if parent is not None:os.close(parent)
        for name in policy['projections']:
            if time.monotonic()>=deadline:
                rows.append({'path':name,'status':'pending_budget'});continue
            rows.append(_projection(root,rootfd,name,policy,apply,deadline))
        return {'status':'completed_with_pending' if any(r['status'] in ('blocked','pending_budget','pending_offline_vacuum','busy','unresolved_quarantine') for r in rows) else 'completed',
            'apply':apply,'results':rows,'deleted_files':deleted,'reclaimed_bytes':reclaimed,
            'policy_sha256':hashlib.sha256(_canonical(policy)).hexdigest(),'elapsed_seconds':time.monotonic()-started,
            'scope':'approved scratch and dedicated projection pages only; ledgers/audit/source retained'}
    finally:
        if lockfd is not None:os.close(lockfd)
        if lockparent is not None:os.close(lockparent)
        os.close(rootfd)


def _projection(root,rootfd,name,policy,apply,deadline):
    parent=None;db=None
    try:
        parent=_parent(rootfd,_relative(name,'index'));leaf=name.split('/')[-1]
        s=os.stat(leaf,dir_fd=parent,follow_symlinks=False)
        if (not stat.S_ISREG(s.st_mode) or s.st_uid!=os.geteuid() or s.st_nlink!=1 or
                s.st_size>policy['max_projection_bytes']):raise ValueError('Invalid projection identity')
        free=os.statvfs(root).f_bavail*os.statvfs(root).f_frsize
        if free<policy['minimum_free_bytes']+2*s.st_size:return {'path':name,'status':'blocked','reason':'free_space_reserve'}
        if not apply:return {'path':name,'status':'would_checkpoint_incremental_vacuum'}
        # Parent descriptor pins the directory; maintenance root is private to the service.
        db=sqlite3.connect(f'file:/proc/self/fd/{parent}/{leaf}?mode=rw',uri=True,timeout=0)
        db.set_progress_handler(lambda:int(time.monotonic()>=deadline),1000)
        tables={r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if (tables & {'calls','events','reservations','claims','experiments'} or
                any(any(word in table.lower() for word in FORBIDDEN) for table in tables)):
            raise ValueError('Ledger/audit/policy databases forbidden')
        if 'maintenance_scope' not in tables or db.execute('SELECT kind FROM maintenance_scope').fetchall()!=[('rebuildable_projection',)]:
            raise ValueError('Projection marker absent')
        checkpoint=db.execute('PRAGMA wal_checkpoint(PASSIVE)').fetchone()
        if checkpoint and checkpoint[0]:return {'path':name,'status':'busy'}
        if db.execute('PRAGMA auto_vacuum').fetchone()[0]!=2:
            return {'path':name,'status':'pending_offline_vacuum','reason':'projection_not_created_with_incremental_auto_vacuum'}
        db.execute('BEGIN IMMEDIATE')
        before=db.execute('PRAGMA freelist_count').fetchone()[0]
        db.execute(f'PRAGMA incremental_vacuum({policy["max_vacuum_pages"]})');db.commit()
        after=db.execute('PRAGMA freelist_count').fetchone()[0]
        return {'path':name,'status':'projection_maintained','free_pages_before':before,'free_pages_after':after,'checkpoint':checkpoint}
    except (OSError,ValueError,sqlite3.Error) as exc:return {'path':name,'status':'blocked','reason':type(exc).__name__}
    finally:
        if db is not None:db.close()
        if parent is not None:os.close(parent)


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',required=True);parser.add_argument('--policy',required=True)
    parser.add_argument('--apply',action='store_true');parser.add_argument('--lock-file');args=parser.parse_args(argv)
    report=maintain(args.root,_read_json(args.policy),apply=args.apply,lock_file=args.lock_file)
    print(json.dumps(report,sort_keys=True))
    return 0 if report['status']=='completed' else 2


if __name__=='__main__':raise SystemExit(main())
