"""Small application audit adapter; inference/framework loops remain upstream."""
import hashlib
import json
import os
import re
import sqlite3
import time
from pathlib import Path

SENSITIVE={"authorization","api_key","apikey","password","secret","virtual_key","access_token","token","encrypted_content"}

def scrub(value):
    if isinstance(value,dict):return {k:("[redacted]" if k.lower() in SENSITIVE else scrub(v)) for k,v in value.items()}
    if isinstance(value,list):return [scrub(v) for v in value[:128]]
    if isinstance(value,str):
        value=re.sub(r"(?i)bearer\s+\S+","Bearer [redacted]",value)
        value=re.sub(r"sk-bf-[A-Za-z0-9_-]+","[redacted-key]",value)
        return value[:4096]
    return value

class Audit:
    def __init__(self,path):
        p=Path(path);p.parent.mkdir(parents=True,mode=0o700,exist_ok=True)
        fd=os.open(p,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600);os.close(fd);os.chmod(p,0o600)
        self.path=str(p)
        with self.connect() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("""CREATE TABLE IF NOT EXISTS events (
                seq INTEGER PRIMARY KEY AUTOINCREMENT, utc REAL NOT NULL,
                run TEXT NOT NULL, agent TEXT NOT NULL, kind TEXT NOT NULL,
                detail TEXT NOT NULL, previous_hash TEXT NOT NULL, hash TEXT NOT NULL)""")
            db.execute("CREATE TRIGGER IF NOT EXISTS events_no_update BEFORE UPDATE ON events BEGIN SELECT RAISE(ABORT,'append only'); END")
            db.execute("CREATE TRIGGER IF NOT EXISTS events_no_delete BEFORE DELETE ON events BEGIN SELECT RAISE(ABORT,'append only'); END")

    def connect(self):return sqlite3.connect(self.path,timeout=30)

    def emit(self,run,agent,kind,detail=None):
        from .protocol import event_envelope
        detail=scrub(detail or {})
        if not isinstance(detail,dict) or '_communication' in detail:raise ValueError('Reserved event contract field')
        utc=time.time()
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row=db.execute("SELECT seq,hash FROM events ORDER BY seq DESC LIMIT 1").fetchone()
            previous=row[1] if row else "0"*64
            tick=row[0]+1 if row else 1
            envelope=event_envelope(kind,detail,tick,previous)
            body=json.dumps({**detail,'_communication':envelope.model_dump()},sort_keys=True,separators=(",",":"),allow_nan=False)
            if len(body.encode())>16384:raise ValueError("Audit event exceeds limit")
            canonical=json.dumps([utc,run,agent,kind,body,previous],separators=(",",":"))
            digest=hashlib.sha256(canonical.encode()).hexdigest()
            seq=db.execute("INSERT INTO events(utc,run,agent,kind,detail,previous_hash,hash) VALUES(?,?,?,?,?,?,?)",
                           (utc,run,agent,kind,body,previous,digest)).lastrowid
        return seq

    def events(self,after=0,limit=200):
        if after<0 or not 1<=limit<=500:raise ValueError("Invalid event window")
        with self.connect() as db:
            rows=db.execute("SELECT seq,utc,run,agent,kind,detail,previous_hash,hash FROM events WHERE seq>? ORDER BY seq LIMIT ?",(after,limit)).fetchall()
        return [dict(zip(("seq","utc","run","agent","kind","detail","previous_hash","hash"),r[:5]+(json.loads(r[5]),)+r[6:])) for r in rows]

    def verify(self):
        from .protocol import EventEnvelope,canonical as payload_canonical
        previous="0"*64
        count=0;contract_events=0
        with self.connect() as db:
            for seq,utc,run,agent,kind,body,prev,digest in db.execute("SELECT * FROM events ORDER BY seq"):
                canonical=json.dumps([utc,run,agent,kind,body,prev],separators=(",",":"))
                if prev!=previous or hashlib.sha256(canonical.encode()).hexdigest()!=digest:
                    return {"valid":False,"failed_sequence":seq}
                detail=json.loads(body)
                if '_communication' in detail:
                    try:
                        envelope=EventEnvelope.model_validate(detail.pop('_communication'))
                        if envelope.tick!=seq or envelope.previous_event_hash!=prev or envelope.payload_sha256!=hashlib.sha256(payload_canonical(detail)).hexdigest():
                            return {'valid':False,'failed_sequence':seq,'reason':'communication contract mismatch'}
                    except ValueError:return {'valid':False,'failed_sequence':seq,'reason':'invalid communication contract'}
                    contract_events+=1
                previous=digest;count+=1
        return {"valid":True,"events":count,"head_hash":previous,
                "contract_events":contract_events,"legacy_events":count-contract_events,
                "scope":"hash-chain consistency; external anchoring is required for tamper resistance against the database owner"}

    def snapshot(self):
        with self.connect() as db:
            rows=db.execute("SELECT seq,utc,run,agent,kind,detail FROM events ORDER BY seq DESC LIMIT 1000").fetchall()
        agents={};channels={}
        for seq,utc,run,agent,kind,body in rows:
            parsed=json.loads(body)
            channel=parsed.get('_communication',{}).get('track')
            if channel:
                summary=channels.setdefault(channel,{'track':channel,'events_in_recent_window':0,'last_event':kind,'last_sequence':seq})
                summary['events_in_recent_window']+=1
            key=run+":"+agent
            if key not in agents:
                agents[key]={"run":run,"agent":agent,"last_event":kind,"utc":utc,"detail":parsed,
                    "age_seconds":max(0,time.time()-utc),"stale":time.time()-utc>30}
        return {"utc":time.time(),"cursor":rows[0][0] if rows else 0,"agents":list(agents.values()),
                'channel_activity':sorted(channels.values(),key=lambda row:row['track']),'channel_window_events':len(rows),
                "visible_scope":"instrumented runtime and upstream notifications; private latent reasoning is not observable"}
