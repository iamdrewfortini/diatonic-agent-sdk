"""Bounded host-local metadata projection; never a native catalog or transfer ledger.

Provider names describe caller supplied mounted fixtures, not tested remote adapters.
No content extraction, hash equality, atomic snapshot or deleted-file recovery is inferred.
"""
from __future__ import annotations
import hashlib
import json
import mimetypes
import os
import sqlite3
import stat
import time
from pathlib import Path, PurePosixPath
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from .evidence import Record, assess

HANDLER_VERSION = "estate-local-metadata-v2"
CORRECTION_BINDING_VERSION = "estate-observed-version-v1"


def _observation_fingerprint(observation):
    """Source-scoped observed version guard, not globally reliable inode identity.

    Hash enrichment and observation time do not alter this metadata binding.
    Legacy records without ctime/root evidence cannot acquire one by pathname.
    """
    observed_stat = observation.get('observed_stat', {})
    required = ('source_id', 'volume_id', 'source_root_identity', 'kind',
                'bytes', 'mtime_ns', 'ctime_ns')
    if any(observation.get(key) is None for key in required) or any(observed_stat.get(key) is None for key in ('device', 'inode')):
        return None
    token = {key: observation[key] for key in required}
    token['observed_stat'] = {key: observed_stat[key] for key in ('device', 'inode')}
    token['retained_version'] = observation.get('retained_version')
    return CORRECTION_BINDING_VERSION + ':' + hashlib.sha256(json.dumps(token, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def _correction_status(bound, observation):
    current = _observation_fingerprint(observation) if observation else None
    if bound is None:
        return 'pending_confirmation_legacy_path_only'
    if current is None:
        return 'pending_confirmation_observation_unavailable'
    return 'applied' if bound == current else 'pending_confirmation_version_changed'

def _secure_database(path):
    """SQLite state belongs in a trusted private directory, not a mutable shared path."""
    parent=Path(path).absolute().parent
    st=parent.stat()
    if st.st_uid!=os.geteuid() or st.st_mode & 0o022: raise ValueError('Database parent must be owned and not group/world writable')
    fd=os.open(path,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode): raise ValueError('Database must be a regular file')
        os.fchmod(fd,0o600)
    finally: os.close(fd)

def _entry_parent(root,rel,identity):
    fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        st=os.fstat(fd)
        if f'{st.st_dev}:{st.st_ino}'!=identity: raise ValueError('Source root identity changed')
        parts=PurePosixPath(rel).parts
        for part in parts[:-1]:
            nxt=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
            os.close(fd);fd=nxt
        return fd,parts[-1] if parts else '.'
    except BaseException: os.close(fd);raise

class SourceSpec(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    source_id: str = Field(min_length=1, max_length=128)
    root: str
    provider: str = "local-filesystem"
    volume_id: str = Field(min_length=1)
    retained_version: str | None = None
    lineage_source_id: str | None = None
    available: bool = True
    reliable_file_ids: bool = False
    exclusions: list[str] = Field(default_factory=list, max_length=128)

class EstateProjection:
    def __init__(self, database):
        self.database = str(database)
        _secure_database(self.database)
        with self.connect() as db:
            db.executescript('''
            CREATE TABLE IF NOT EXISTS estate_sources(id TEXT PRIMARY KEY, spec TEXT NOT NULL, status TEXT NOT NULL, observed REAL, root_identity TEXT, errors TEXT NOT NULL DEFAULT '[]');
            CREATE TABLE IF NOT EXISTS estate_frontier(source TEXT, path TEXT, PRIMARY KEY(source,path));
            CREATE TABLE IF NOT EXISTS estate_entries(source TEXT, path TEXT, observation TEXT NOT NULL, PRIMARY KEY(source,path));
            CREATE TABLE IF NOT EXISTS estate_history(source TEXT, path TEXT, observation TEXT NOT NULL, archived REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS estate_scan_history(source TEXT, coverage TEXT NOT NULL, archived REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS estate_corrections(source TEXT, path TEXT, labels TEXT NOT NULL, PRIMARY KEY(source,path));
            CREATE TABLE IF NOT EXISTS estate_correction_history(source TEXT, path TEXT, labels TEXT NOT NULL, bound_fingerprint TEXT, archived REAL NOT NULL, reason TEXT NOT NULL);
            ''')
            db.execute('BEGIN IMMEDIATE')
            columns = {row[1] for row in db.execute('PRAGMA table_info(estate_corrections)')}
            if 'bound_fingerprint' not in columns:
                # Every legacy path-only label remains present and pending. Do
                # not guess which historical artifact a pathname referred to.
                db.execute('ALTER TABLE estate_corrections ADD COLUMN bound_fingerprint TEXT')
    def connect(self):
        return sqlite3.connect(self.database)

    def register(self, source: SourceSpec):
        root = Path(source.root)
        if not root.is_absolute() or root.is_symlink():
            raise ValueError("Source requires an absolute non-symlink root")
        for exclusion in source.exclusions:
            p = PurePosixPath(exclusion)
            if p.is_absolute() or '..' in p.parts:
                raise ValueError('Exclusions must be root-relative')
        encoded = source.model_dump_json()
        with self.connect() as db:
            old = db.execute('SELECT spec FROM estate_sources WHERE id=?', (source.source_id,)).fetchone()
            if old and old[0] != encoded:
                raise ValueError('Source identity is immutable; register a new version')
            db.execute("INSERT OR IGNORE INTO estate_sources(id,spec,status) VALUES(?,?,'discovered')", (source.source_id, encoded))
            if not old:
                db.execute('INSERT INTO estate_frontier VALUES(?,?)', (source.source_id, ''))

    def reconcile(self,source_id):
        """Start an explicit fresh pass, preserving prior observations and failed coverage."""
        with self.connect() as db:
            coverage=self._coverage(db,source_id)
            now=time.time()
            db.execute('INSERT INTO estate_scan_history VALUES(?,?,?)',(source_id,json.dumps(coverage),now))
            db.execute('INSERT INTO estate_history SELECT source,path,observation,? FROM estate_entries WHERE source=?',(now,source_id))
            db.execute('DELETE FROM estate_entries WHERE source=?',(source_id,))
            db.execute('DELETE FROM estate_frontier WHERE source=?',(source_id,))
            db.execute('INSERT INTO estate_frontier VALUES(?,?)',(source_id,''))
            db.execute("UPDATE estate_sources SET status='discovered',errors='[]' WHERE id=?",(source_id,))
    def history(self,source_id):
        with self.connect() as db:
            return {'scans':[json.loads(r[0]) for r in db.execute('SELECT coverage FROM estate_scan_history WHERE source=? ORDER BY archived',(source_id,))],
                    'observations':[json.loads(r[0]) for r in db.execute('SELECT observation FROM estate_history WHERE source=? ORDER BY archived,path',(source_id,))],
                    'corrections':self._corrections(db,source_id)}

    def scan(self, source_id, *, max_entries=1000, max_children=10000):
        if not 1 <= max_entries <= 100000 or not 1 <= max_children <= 100000:
            raise ValueError('Invalid discovery bounds')
        with self.connect() as db:
            row = db.execute('SELECT spec,status FROM estate_sources WHERE id=?', (source_id,)).fetchone()
            if not row: raise ValueError('Unknown source')
            spec = SourceSpec.model_validate_json(row[0])
            root = Path(spec.root)
            if not spec.available:
                db.execute("UPDATE estate_sources SET status='disconnected',observed=? WHERE id=?", (time.time(), source_id))
                return self._coverage(db, source_id)
            try:
                rst = root.lstat()
                if not stat.S_ISDIR(rst.st_mode): raise ValueError('Source root is not a directory')
            except OSError as exc:
                self._error(db, source_id, '', exc)
                db.execute("UPDATE estate_sources SET status=?,observed=? WHERE id=?", ('permission-denied' if isinstance(exc,PermissionError) else 'unavailable',time.time(),source_id))
                return self._coverage(db, source_id)
            identity = f'{rst.st_dev}:{rst.st_ino}'
            alias = db.execute('SELECT id FROM estate_sources WHERE root_identity=? AND id!=?', (identity,source_id)).fetchone()
            if alias:
                db.execute("UPDATE estate_sources SET status='alias-not-scanned',root_identity=?,observed=? WHERE id=?",(identity,time.time(),source_id))
                return self._coverage(db,source_id)
            previous = db.execute('SELECT root_identity FROM estate_sources WHERE id=?',(source_id,)).fetchone()[0]
            if previous and previous != identity: raise ValueError('Source root changed; explicit new source version required')
            db.execute("UPDATE estate_sources SET status='partially-scanned',root_identity=?,observed=? WHERE id=?",(identity,time.time(),source_id))
            processed=0
            while processed < max_entries:
                pending=db.execute('SELECT path FROM estate_frontier WHERE source=? ORDER BY path LIMIT 1',(source_id,)).fetchone()
                if not pending: break
                rel=pending[0]; path=root/rel
                db.execute('DELETE FROM estate_frontier WHERE source=? AND path=?',(source_id,rel)); processed+=1
                try:
                    parent,name=_entry_parent(root,rel,identity)
                    try: st=os.stat(name,dir_fd=parent,follow_symlinks=False)
                    finally: os.close(parent)
                    if st.st_dev != rst.st_dev:
                        self._record(db,spec,rel,st,'filesystem-boundary'); continue
                    kind='symlink' if stat.S_ISLNK(st.st_mode) else 'directory' if stat.S_ISDIR(st.st_mode) else 'file' if stat.S_ISREG(st.st_mode) else 'special'
                    self._record(db,spec,rel,st,kind)
                    if kind == 'directory':
                        children=[]
                        parent,name=_entry_parent(root,rel,identity)
                        try: directory=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
                        finally: os.close(parent)
                        try:
                            opened=os.fstat(directory)
                            if (opened.st_dev,opened.st_ino)!=(st.st_dev,st.st_ino): raise ValueError('Directory identity changed before enumeration')
                            with os.scandir(directory) as entries:
                                for child in entries:
                                    childrel=str(Path(rel)/child.name)
                                    if any(childrel == x or childrel.startswith(x.rstrip('/')+'/') for x in spec.exclusions): continue
                                    children.append(childrel)
                                    if len(children)>max_children: raise ValueError('Directory exceeds bounded child enumeration; narrower source required')
                            if os.fstat(directory).st_mtime_ns != st.st_mtime_ns:
                                raise ValueError('Directory changed during enumeration; reconciliation required')
                        finally: os.close(directory)
                        db.executemany('INSERT OR IGNORE INTO estate_frontier VALUES(?,?)',((source_id,p) for p in children))
                except (OSError,ValueError) as exc:
                    self._error(db,source_id,rel,exc)
            remaining=db.execute('SELECT COUNT(*) FROM estate_frontier WHERE source=?',(source_id,)).fetchone()[0]
            errors=json.loads(db.execute('SELECT errors FROM estate_sources WHERE id=?',(source_id,)).fetchone()[0])
            if not remaining and not errors:
                for raw, in db.execute('SELECT observation FROM estate_entries WHERE source=?',(source_id,)).fetchall():
                    prior=json.loads(raw)
                    if prior['kind']=='directory':
                        try:
                            parent,name=_entry_parent(root,prior['path'],identity)
                            try: current=os.stat(name,dir_fd=parent,follow_symlinks=False)
                            finally: os.close(parent)
                            if not stat.S_ISDIR(current.st_mode) or (current.st_dev,current.st_ino)!=(prior['observed_stat']['device'],prior['observed_stat']['inode']) or current.st_mtime_ns!=prior['mtime_ns']: raise ValueError('Directory changed since checkpoint; reconciliation required')
                        except (OSError,ValueError) as exc:
                            self._error(db,source_id,prior['path'],exc)
                            errors.append({'status':'unresolved'})
            if not remaining and not errors:
                db.execute("UPDATE estate_sources SET status='fully-scanned-within-scope' WHERE id=?",(source_id,))
            return {**self._coverage(db,source_id),'processed_this_call':processed}

    def _record(self,db,spec,rel,st,kind):
        identity = f'{spec.volume_id}:{st.st_dev}:{st.st_ino}' if spec.reliable_file_ids else None
        root_identity=db.execute('SELECT root_identity FROM estate_sources WHERE id=?',(spec.source_id,)).fetchone()[0]
        obs={'source_id':spec.source_id,'path':rel,'provider':spec.provider,'volume_id':spec.volume_id,'source_root_identity':root_identity,'kind':kind,'observed_stat':{'device':st.st_dev,'inode':st.st_ino},'bytes':st.st_size,'mtime_ns':st.st_mtime_ns,'ctime_ns':st.st_ctime_ns,'observed_at':time.time(),'file_id':identity,'identity_uncertain':identity is None,'retained_version':spec.retained_version,'lineage_source_id':spec.lineage_source_id,'handler_version':HANDLER_VERSION,'mime':mimetypes.guess_type(rel)[0],'content_sha256':None,'extraction_status':'not-extracted'}
        obs['observed_version_token']=_observation_fingerprint(obs)
        obs['observed_version_scope']='source-scoped stat observation; inode reliability is not inferred'
        if kind=='file':
            assessment=assess([Record(scope=spec.source_id,name=rel, rse=spec.volume_id,bytes=st.st_size)])
            obs['labels']=[{**r,'confidence':0.5,'classifier_version':'existing-evidence-metadata-v1','status':'inferred'} for r in assessment['classifications']]
        else: obs['labels']=[]
        db.execute('INSERT OR REPLACE INTO estate_entries VALUES(?,?,?)',(spec.source_id,rel,json.dumps(obs,sort_keys=True)))
    def _error(self,db,source,path,exc):
        errors=json.loads(db.execute('SELECT errors FROM estate_sources WHERE id=?',(source,)).fetchone()[0])
        errors.append({'path':path,'error_type':type(exc).__name__,'status':'unresolved'})
        db.execute('UPDATE estate_sources SET errors=? WHERE id=?',(json.dumps(errors),source))
    def _coverage(self,db,source):
        spec,status,observed,errors=db.execute('SELECT spec,status,observed,errors FROM estate_sources WHERE id=?',(source,)).fetchone()
        return {'source':json.loads(spec),'status':status,'observed_at':observed,'errors':json.loads(errors),'entries':db.execute('SELECT COUNT(*) FROM estate_entries WHERE source=?',(source,)).fetchone()[0],'remaining':db.execute('SELECT COUNT(*) FROM estate_frontier WHERE source=?',(source,)).fetchone()[0],'snapshot_guarantee':'non-atomic metadata observations; reconciliation required for concurrent changes'}
    def coverage(self):
        with self.connect() as db:
            return [self._coverage(db,row[0]) for row in db.execute('SELECT id FROM estate_sources ORDER BY id').fetchall()]
    def correct(self,source,path,labels):
        """Explicitly confirm labels for this observation; preserve prior bindings."""
        if not isinstance(labels,(list,tuple)) or not labels or len(labels)>32 or any(not isinstance(x,str) or not x or len(x)>128 for x in labels): raise ValueError('Invalid user labels')
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            row=db.execute('SELECT observation FROM estate_entries WHERE source=? AND path=?',(source,path)).fetchone()
            if not row: raise ValueError('Unknown observation')
            binding=_observation_fingerprint(json.loads(row[0]))
            if binding is None: raise ValueError('Observation version incomplete; reconcile before confirming labels')
            encoded=json.dumps(labels)
            prior=db.execute('SELECT labels,bound_fingerprint FROM estate_corrections WHERE source=? AND path=?',(source,path)).fetchone()
            if prior and prior!=(encoded,binding):
                db.execute('INSERT INTO estate_correction_history VALUES(?,?,?,?,?,?)',
                           (source,path,prior[0],prior[1],time.time(),'explicit_user_reconfirmation'))
            db.execute('INSERT OR REPLACE INTO estate_corrections(source,path,labels,bound_fingerprint) VALUES(?,?,?,?)',(source,path,encoded,binding))

    def _corrections(self,db,source_id=None):
        result=[]
        for source,path,raw,bound in db.execute('SELECT source,path,labels,bound_fingerprint FROM estate_corrections ORDER BY source,path'):
            if source_id is not None and source!=source_id: continue
            row=db.execute('SELECT observation FROM estate_entries WHERE source=? AND path=?',(source,path)).fetchone()
            result.append({'source_id':source,'path':path,'labels':json.loads(raw),'bound_fingerprint':bound,
                           'status':_correction_status(bound,json.loads(row[0]) if row else None),
                           'record':'current_correction'})
        for source,path,raw,bound,archived,reason in db.execute('SELECT source,path,labels,bound_fingerprint,archived,reason FROM estate_correction_history ORDER BY archived,source,path'):
            if source_id is not None and source!=source_id: continue
            result.append({'source_id':source,'path':path,'labels':json.loads(raw),'bound_fingerprint':bound,
                           'status':'preserved_prior_correction','record':'history','archived_at':archived,'reason':reason})
        return result

    def corrections(self,source_id=None):
        """Read pending/archived labels without applying them to a pathname."""
        with self.connect() as db:
            return self._corrections(db,source_id)
    def hash_content(self,source_id,path, *, authorized=False,max_bytes=64*1024*1024):
        """Opt-in bounded content identity, separately authorized from metadata discovery."""
        if not authorized: raise PermissionError('Content reads require explicit authorization')
        if not 0<=max_bytes<=64*1024*1024: raise ValueError('Invalid content bound')
        with self.connect() as db:
            row=db.execute('SELECT observation FROM estate_entries WHERE source=? AND path=?',(source_id,path)).fetchone()
            if not row: raise ValueError('Unknown observation')
            obs=json.loads(row[0])
            if obs['kind']!='file' or obs['bytes']>max_bytes: raise ValueError('Not a bounded observed regular file')
            if _observation_fingerprint(obs) is None: raise ValueError('Observation version incomplete; reconcile before content enrichment')
            source=SourceSpec.model_validate_json(db.execute('SELECT spec FROM estate_sources WHERE id=?',(source_id,)).fetchone()[0])
            fd=os.open(source.root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            try:
                pinned=db.execute('SELECT root_identity FROM estate_sources WHERE id=?',(source_id,)).fetchone()[0]
                rootstat=os.fstat(fd)
                if pinned!=f'{rootstat.st_dev}:{rootstat.st_ino}': raise ValueError('Observed source root identity changed')
                parts=PurePosixPath(path).parts
                for part in parts[:-1]:
                    nxt=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);os.close(fd);fd=nxt
                datafd=os.open(parts[-1],os.O_RDONLY|os.O_NOFOLLOW,dir_fd=fd)
            finally: os.close(fd)
            with os.fdopen(datafd,'rb') as stream:
                before=os.fstat(stream.fileno())
                if not stat.S_ISREG(before.st_mode) or (before.st_dev,before.st_ino)!=(obs['observed_stat']['device'],obs['observed_stat']['inode']) or (before.st_size,before.st_mtime_ns,before.st_ctime_ns)!=(obs['bytes'],obs['mtime_ns'],obs['ctime_ns']): raise ValueError('Observed version changed')
                digest=hashlib.sha256();total=0
                while chunk:=stream.read(min(1024*1024,max_bytes-total+1)):
                    total+=len(chunk)
                    if total>max_bytes: raise ValueError('Content bound exceeded')
                    digest.update(chunk)
                after=os.fstat(stream.fileno())
                if (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns): raise ValueError('Content changed during hashing')
            obs.update(content_sha256=digest.hexdigest(),content_observed_at=time.time(),content_identity_status='full-read-stable-stat',version_id=hashlib.sha256(json.dumps([source_id,path,before.st_mtime_ns,digest.hexdigest()]).encode()).hexdigest())
            db.execute('UPDATE estate_entries SET observation=? WHERE source=? AND path=?',(json.dumps(obs),source_id,path))
            return obs

    def query(self, *, source_id=None, name=None, label=None, since=None, content_sha256=None, file_id=None, lineage_source_id=None):
        """Provenance-bearing cross-source observed-name/label/change query; names are not identity."""
        with self.connect() as db:
            result=[]
            for source,path,raw in db.execute('SELECT source,path,observation FROM estate_entries ORDER BY source,path'):
                obs=json.loads(raw)
                correction=db.execute('SELECT labels,bound_fingerprint FROM estate_corrections WHERE source=? AND path=?',(source,path)).fetchone()
                if correction:
                    status=_correction_status(correction[1],obs)
                    obs['user_correction_status']=status
                    if status=='applied': obs['user_labels']=json.loads(correction[0])
                    else: obs['pending_user_labels']=json.loads(correction[0])
                if content_sha256 is not None and obs.get('content_sha256')!=content_sha256: continue
                if file_id is not None and obs.get('file_id')!=file_id: continue
                if lineage_source_id is not None and obs.get('lineage_source_id')!=lineage_source_id: continue
                if source_id is not None and source!=source_id: continue
                if name is not None and Path(path).name!=name: continue
                if since is not None and obs['observed_at']<=since: continue
                if label is not None and label not in obs.get('user_labels',[]) and label not in [x['label'] for x in obs['labels']]: continue
                result.append(obs)
            return {'results':result,'coverage':self.coverage(),'authority':'read-only projection; native providers retain ownership','query_version':HANDLER_VERSION}

class ArtifactRecord(BaseModel):
    model_config=ConfigDict(extra='forbid',strict=True)
    artifact_id: str=Field(min_length=1,max_length=256)
    content_sha256: str=Field(pattern='^[0-9a-f]{64}$')
    version_id: str=Field(min_length=1,max_length=256)
    mime: str=Field(min_length=1,max_length=128)
    modality: Literal['text','image','audio','video','binary','mixed']
    source_id: str=Field(min_length=1,max_length=128)
    source_version: str=Field(min_length=1,max_length=256)
    provenance: list[str]=Field(min_length=1,max_length=32)

class ExtractionRegistry:
    """Explicit trusted bindings; MIME or metadata labels never imply media extraction."""
    def __init__(self): self.bindings={}
    def register(self,mime,version,handler):
        if mime in self.bindings or not version or not callable(handler): raise ValueError('Ambiguous or invalid extractor binding')
        self.bindings[mime]=(version,handler)
    def extract(self,artifact, *, authorized=False):
        if not authorized: return {'status':'blocked','reason':'extraction-not-authorized'}
        binding=self.bindings.get(artifact.get('mime'))
        if not binding: return {'status':'pending','reason':'native-extractor-unbound','artifact':artifact}
        try: artifact=ArtifactRecord.model_validate(artifact).model_dump()
        except ValidationError: return {'status':'blocked','reason':'artifact-content-version-provenance-required'}
        version,handler=binding
        return {'status':'extracted','extractor_version':version,'source_content_sha256':artifact['content_sha256'],'artifact':artifact,'result':handler(artifact)}
