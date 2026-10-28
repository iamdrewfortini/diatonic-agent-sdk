"""Declarative, versioned application workflows. No generated Python or shell."""
import hashlib
import json
import os
import sqlite3
from pathlib import Path
from typing import Literal
from pydantic import BaseModel,ConfigDict,Field,model_validator

class Cell(BaseModel):
    model_config=ConfigDict(extra="forbid",strict=True)
    id: str=Field(pattern=r"^[a-z][a-z0-9_-]{0,31}$")
    kind: Literal["classification","dedup_review","planning","proof_review"]
    instructions: str=Field(min_length=1,max_length=1000)
    depends_on: list[str]=Field(max_length=16)

class Workflow(BaseModel):
    model_config=ConfigDict(extra="forbid",strict=True)
    name: str=Field(pattern=r"^[a-z][a-z0-9-]{0,60}$")
    purpose: str=Field(min_length=1,max_length=500)
    cells: list[Cell]=Field(min_length=1,max_length=16)

    @model_validator(mode="after")
    def graph(self):
        byid={c.id:c for c in self.cells}
        if len(byid)!=len(self.cells):raise ValueError("Duplicate cell ID")
        visited,active=set(),set()
        def walk(id):
            if id not in byid or id in active:raise ValueError("Unknown dependency or cyclic workflow")
            if id in visited:return
            active.add(id)
            for dependency in byid[id].depends_on:walk(dependency)
            active.remove(id);visited.add(id)
        for id in byid:walk(id)
        return self

    @property
    def digest(self):
        return hashlib.sha256(json.dumps(self.model_dump(),sort_keys=True,separators=(",",":")).encode()).hexdigest()

class WorkflowRegistry:
    def __init__(self,directory,audit):
        self.root=Path(directory)
        self.root.mkdir(parents=True,mode=0o700,exist_ok=True)
        self.audit=audit
        with audit.connect() as db:
            db.execute("CREATE TABLE IF NOT EXISTS workflow_versions (run TEXT NOT NULL, digest TEXT NOT NULL, parent TEXT, UNIQUE(run,digest))")
            db.execute("CREATE TABLE IF NOT EXISTS spawns (run TEXT NOT NULL, request TEXT NOT NULL, depth INTEGER NOT NULL, state TEXT NOT NULL, UNIQUE(run,request))")

    def deploy(self,run,workflow:Workflow,parent=None):
        # Registry mutations are coordinator-owned, never arbitrary file paths.
        if parent==workflow.digest:raise ValueError('A workflow cannot parent itself')
        self.audit.emit(run,"workflow-registry","workflow.deploy.intent",{"digest":workflow.digest,"name":workflow.name,"parent":parent})
        with self.audit.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            existing=db.execute("SELECT parent FROM workflow_versions WHERE run=? AND digest=?",(run,workflow.digest)).fetchone()
            if existing and existing[0]!=parent:raise ValueError('An immutable version cannot change its recorded parent')
            if not existing:
                count=db.execute("SELECT COUNT(*) FROM workflow_versions WHERE run=?",(run,)).fetchone()[0]
                if count>=8:raise ValueError("Root-run version limit exceeded")
                if parent and not db.execute("SELECT 1 FROM workflow_versions WHERE run=? AND digest=?",(run,parent)).fetchone():raise ValueError("Parent version not registered in this root run")
                p=self.root/(workflow.digest+".json")
                data=json.dumps(workflow.model_dump(),sort_keys=True,separators=(",",":")).encode()
                try:
                    fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
                except FileExistsError:
                    if p.is_symlink() or p.read_bytes()!=data:raise ValueError("Version artifact conflict")
                else:
                    with os.fdopen(fd,"wb") as f:f.write(data);f.flush();os.fsync(f.fileno())
                db.execute("INSERT INTO workflow_versions VALUES(?,?,?)",(run,workflow.digest,parent))
        result={"status":"definition_deployed","digest":workflow.digest,"parent":parent,
                "execution":"requires separately verified gateway runtime; no model or cluster job started"}
        self.audit.emit(run,"workflow-registry","workflow.definition.deployed",result)
        return result

    def reserve_spawn(self,run,request,depth):
        if not 1<=depth<=2:raise ValueError("Maximum spawn depth is two")
        with self.audit.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            # Never silently repeat a possibly executed child after a crash.
            if db.execute("SELECT 1 FROM spawns WHERE run=? AND request=?",(run,request)).fetchone():raise ValueError("Spawn request already admitted; inspect prior evidence")
            count=db.execute("SELECT COUNT(*) FROM spawns WHERE run=?",(run,)).fetchone()[0]
            if count>=4:raise ValueError("Root-run spawn limit exceeded")
            db.execute("INSERT INTO spawns VALUES(?,?,?,'reserved')",(run,request,depth))
        self.audit.emit(run,request,"agent.spawn.admitted",{"depth":depth,"shared_budget_run":run})
        return count+1

    def finish_spawn(self,run,request,state):
        if state not in {"completed","failed","unresolved"}:raise ValueError("Invalid terminal state")
        with self.audit.connect() as db:
            db.execute("UPDATE spawns SET state=? WHERE run=? AND request=? AND state='reserved'",(state,run,request))
        self.audit.emit(run,request,"agent.spawn."+state,{})
