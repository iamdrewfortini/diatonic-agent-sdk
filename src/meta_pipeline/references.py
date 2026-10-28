"""Local native-command recipe discovery. This module cannot execute recipes."""
import collections
import hashlib
import json
import re
import sqlite3
import subprocess
from pathlib import Path

class ReferenceCatalog:
    def __init__(self,path):
        self.path=Path(path)
        self.validation={}
        if self.path.name.endswith('.tar.gz'):
            from .corpus import load_corpus
            self.entries,self.validation=load_corpus(self.path)
            with self.path.open('rb') as stream:
                self.source_sha256=hashlib.file_digest(stream,'sha256').hexdigest()
        else:
            if self.path.stat().st_size>4000000:raise ValueError("Reference catalog exceeds size limit")
            raw=self.path.read_bytes()
            self.source_sha256=hashlib.sha256(raw).hexdigest()
            data=json.loads(raw)
            source=data.get('shortcuts')
            self.entries=list(source.values())if isinstance(source,dict)else source
        if not isinstance(self.entries,list)or not 1<=len(self.entries)<=10000:raise ValueError("Expected a bounded shortcut catalog")
        self.byid={}
        self.byaddress={}
        self.db=sqlite3.connect(':memory:')
        self.db.execute('CREATE VIRTUAL TABLE recipes USING fts5(id UNINDEXED,title,category,intent)')
        for e in self.entries:
            if not isinstance(e,dict)or not all(isinstance(e.get(k),str)for k in ['id','title','command']):raise ValueError("Invalid recipe shape")
            if not re.fullmatch(r'[A-Za-z0-9_-]{1,80}',e['id'])or e['id']in self.byid:raise ValueError("Invalid or duplicate recipe ID")
            if len(e['command'].encode())>16384:raise ValueError("Recipe exceeds command-text bound")
            self.byid[e['id']]=e
            if e.get('address'):
                if e['address']in self.byaddress:raise ValueError('Duplicate recipe address')
                self.byaddress[e['address']]=e['id']
            intent=e.get('use_when','')
            if not isinstance(intent,str):intent=json.dumps(intent)
            self.db.execute('INSERT INTO recipes VALUES(?,?,?,?)',(e['id'],e['title'],str(e.get('category','')),intent))

    def summary(self):
        return {'source_sha256':self.source_sha256,'source_bytes':self.path.stat().st_size,
                'entries':len(self.entries),'declared_risks':dict(collections.Counter(str(e.get('risk','unknown'))for e in self.entries)),
                'declared_kinds':dict(collections.Counter(str(e.get('kind','unknown'))for e in self.entries)),
                'execution_permission':'none; reference data only','index':'local SQLite FTS5/BM25; no model calls',
                'validation':self.validation}

    def describe(self,id,include_command=False):
        e=self.byid[id]
        result={k:e.get(k)for k in ['id','title','category','risk','kind','shell','platform']}
        result.update(command_sha256=hashlib.sha256(e['command'].encode()).hexdigest(),
                      reference_id='recipe:'+self.source_sha256+':'+e['id'],
                      verification_claim=e.get('verification'),execution_permission='none',
                      requires='approved typed native adapter and scoped preconditions before execution')
        if 'interface'in e:
            from .protocol import reference_track
            result.update(address=e.get('address'),interface=e['interface'],version_sha256=e.get('version_sha256'),
                          track=reference_track(e['category']))
        if include_command:result.update(command=e['command'],preconditions=e.get('preconditions'),limitations=e.get('limitations'))
        return result

    def search(self,query,limit=5):
        if not 1<=limit<=10 or not isinstance(query,str)or len(query)>500:raise ValueError("Invalid search window")
        exact=query.strip()
        if exact in self.byid:return [self.describe(exact)]
        if exact in self.byaddress:return [self.describe(self.byaddress[exact])]
        words=re.findall(r'[A-Za-z0-9_]+',query)[:20]
        if not words:return []
        # Literal quoted tokens: query syntax cannot become SQL or FTS operators.
        match=' OR '.join('"'+w+'"'for w in words)
        rows=self.db.execute('SELECT id FROM recipes WHERE recipes MATCH ? ORDER BY bm25(recipes) LIMIT ?',(match,limit)).fetchall()
        return [self.describe(row[0])for row in rows]

    def check_syntax(self):
        results=[]
        for e in self.entries:
            if e.get('shell')!='Bash':
                results.append({'id':e['id'],'status':'not_checked_unsupported_shell'});continue
            try:
                # -n parses only. Clear BASH_ENV and inherited shell settings.
                p=subprocess.run(['/bin/bash','--noprofile','--norc','-n'],input=e['command'].encode(),
                    env={'PATH':'/usr/bin:/bin','LC_ALL':'C'},capture_output=True,timeout=2)
                results.append({'id':e['id'],'status':'syntax_valid'if p.returncode==0 else 'syntax_invalid'})
            except subprocess.TimeoutExpired:results.append({'id':e['id'],'status':'parse_timeout'})
        return {**self.summary(),'syntax_results':dict(collections.Counter(r['status']for r in results)),
                'failures':[r for r in results if r['status']!='syntax_valid'],
                'proof_scope':'Bash parser acceptance only; does not prove command safety, performance, installed tools or correct results'}

    def close(self):self.db.close()
