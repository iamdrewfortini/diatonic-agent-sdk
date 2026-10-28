"""Explicitly authorized host-local effects. Managed Rucio/FTS data is out of scope.

Uses non-following directory descriptors, create-only publication and a durable intent
journal. Cross-filesystem move, overwrite, live-database copy and backup preservation
are deliberately unbound rather than silently offering weaker guarantees.
"""
from __future__ import annotations
import hashlib
import json
import os
import sqlite3
import stat
from pathlib import Path, PurePosixPath
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, model_validator
from .estate import _secure_database

HANDLER_VERSION='local-create-copy-v1'
MAX_BYTES=64*1024*1024

class FileOperation(BaseModel):
    model_config=ConfigDict(extra='forbid',strict=True)
    operation: Literal['copy','create']
    request_id: str=Field(min_length=1,max_length=128)
    source: str|None=None
    destination: str=Field(min_length=1,max_length=4096)
    expected_source_sha256: str|None=Field(default=None,pattern='^[0-9a-f]{64}$')
    content_utf8: str|None=Field(default=None,max_length=1000000)
    collision: Literal['reject']='reject'
    @model_validator(mode='after')
    def shape(self):
        if self.operation=='copy' and (self.source is None or self.expected_source_sha256 is None or self.content_utf8 is not None): raise ValueError('Copy requires pinned source content')
        if self.operation=='create' and (self.content_utf8 is None or self.source is not None or self.expected_source_sha256 is not None): raise ValueError('Create requires explicit content only')
        for value in [self.destination,self.source]:
            if value is not None:
                p=PurePosixPath(value)
                if p.is_absolute() or '..' in p.parts or not p.parts or value in {'.',''}: raise ValueError('Paths must be root relative')
        return self

class LocalFileAdapter:
    def __init__(self,root, *, authorized_operations, journal):
        self.root=Path(root)
        if not self.root.is_absolute() or self.root.is_symlink(): raise ValueError('Explicit non-symlink absolute root required')
        st=self.root.stat()
        self.root_identity=(st.st_dev,st.st_ino)
        self.authorized_operations=frozenset(authorized_operations)
        if not self.authorized_operations <= {'copy','create'}: raise ValueError('Unsupported capability')
        self.journal=str(journal)
        _secure_database(self.journal)
        with self.connect() as db:
            db.execute('CREATE TABLE IF NOT EXISTS file_intents(request TEXT PRIMARY KEY,digest TEXT,operation TEXT,state TEXT,result TEXT)')
    def connect(self): return sqlite3.connect(self.journal)
    def _parent(self,path):
        parts=PurePosixPath(path).parts
        fd=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:
            rootstat=os.fstat(fd)
            if (rootstat.st_dev,rootstat.st_ino)!=self.root_identity: raise ValueError('Authorized root identity changed')
            for part in parts[:-1]:
                nxt=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
                os.close(fd); fd=nxt
            return fd,parts[-1]
        except BaseException:
            os.close(fd);raise
    def _read(self,path):
        parent,name=self._parent(path)
        try: fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=parent)
        finally: os.close(parent)
        with os.fdopen(fd,'rb') as stream:
            before=os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_size>MAX_BYTES: raise ValueError('Not a bounded regular file')
            data=stream.read(MAX_BYTES+1)
            after=os.fstat(stream.fileno())
            if len(data)>MAX_BYTES or (before.st_ino,before.st_size,before.st_mtime_ns)!=(after.st_ino,after.st_size,after.st_mtime_ns): raise ValueError('Source changed during read')
            return data
    def execute(self,op:FileOperation):
        if op.operation not in self.authorized_operations: raise PermissionError('Operation not bound to trusted authorization')
        encoded=op.model_dump_json(); digest=hashlib.sha256(encoded.encode()).hexdigest()
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            prior=db.execute('SELECT digest,state,result FROM file_intents WHERE request=?',(op.request_id,)).fetchone()
            if prior:
                if prior[0]!=digest: raise ValueError('Idempotency key reused with changed operation')
            else:
                db.execute("INSERT INTO file_intents VALUES(?,?,?,'reserved',NULL)",(op.request_id,digest,encoded))
        if prior:
            if prior[1]=='completed': return self.recover(op)
            return self.recover(op)
        # Any exception preserves the reserved request and blocks blind retries.
        data=op.content_utf8.encode() if op.operation=='create' else self._read(op.source)
        sha=hashlib.sha256(data).hexdigest()
        if op.operation=='copy' and sha!=op.expected_source_sha256: raise ValueError('Source version precondition failed')
        parent,name=self._parent(op.destination)
        temp='.meta-intent-'+digest
        try:
            fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=parent)
            with os.fdopen(fd,'wb') as stream:
                stream.write(data);stream.flush();os.fsync(stream.fileno())
            result={'status':'completed','request_id':op.request_id,'destination':op.destination,'sha256':sha,'bytes':len(data),'handler_version':HANDLER_VERSION,'metadata_preservation':'content only; mode 0600; no ownership/ACL/xattr guarantee'}
            with self.connect() as db:
                db.execute("UPDATE file_intents SET state='prepared',result=? WHERE request=?",(json.dumps(result),op.request_id))
            # Hard-link publication is atomic and refuses existing destinations.
            os.link(temp,name,src_dir_fd=parent,dst_dir_fd=parent,follow_symlinks=False)
            os.fsync(parent)
            if not self.verify(op,result): raise ValueError('Independent content verification failed')
            with self.connect() as db: db.execute("UPDATE file_intents SET state='completed' WHERE request=?",(op.request_id,))
            os.unlink(temp,dir_fd=parent);os.fsync(parent)
            return result
        finally: os.close(parent)
    def verify(self,op,result):
        try:
            data=self._read(op.destination)
            expected=hashlib.sha256(op.content_utf8.encode()).hexdigest() if op.operation=='create' else op.expected_source_sha256
            return hashlib.sha256(data).hexdigest()==expected==result['sha256'] and len(data)==result['bytes']
        except (OSError,ValueError,KeyError): return False
    def recover(self,op):
        """Reconcile journal and retained temporary inode; never repeat an unknown effect."""
        digest=hashlib.sha256(op.model_dump_json().encode()).hexdigest()
        with self.connect() as db:
            prior=db.execute('SELECT digest,state,result FROM file_intents WHERE request=?',(op.request_id,)).fetchone()
        if not prior or prior[0]!=digest: raise ValueError('No matching admitted intent')
        result=json.loads(prior[2]) if prior[2] else None
        parent,name=self._parent(op.destination);temp='.meta-intent-'+digest
        try:
            try:
                target=os.stat(name,dir_fd=parent,follow_symlinks=False)
                staged=os.stat(temp,dir_fd=parent,follow_symlinks=False)
                proven=(target.st_dev,target.st_ino)==(staged.st_dev,staged.st_ino)
            except OSError: proven=False
            if prior[1]=='completed':
                if proven and self.verify(op,result):
                    os.unlink(temp,dir_fd=parent);os.fsync(parent)
                else:
                    try: os.stat(temp,dir_fd=parent,follow_symlinks=False)
                    except FileNotFoundError: pass
                    else: return {**result,'cleanup_status':'pending-unverified-stage'}
                return result
            if result and proven and self.verify(op,result):
                with self.connect() as db: db.execute("UPDATE file_intents SET state='completed' WHERE request=?",(op.request_id,))
                os.unlink(temp,dir_fd=parent);os.fsync(parent)
                return result
            return {'status':'unresolved','request_id':op.request_id,'reason':'native-effect-reconciliation-required','retry_permitted':False,'retained_stage':temp if result else None}
        finally: os.close(parent)
