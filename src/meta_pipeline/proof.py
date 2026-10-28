"""Evidence-driven experiment records. Models cannot attest their own success."""
import hashlib
import json
import math
import sqlite3
from pydantic import BaseModel,ConfigDict,Field

class Claim(BaseModel):
    model_config=ConfigDict(extra="forbid",strict=True)
    id: str=Field(pattern=r"^[a-z0-9-]{1,80}$")
    property: str=Field(min_length=1,max_length=500)
    scope: str=Field(min_length=1,max_length=500)
    metric: str=Field(pattern=r"^[a-z_]{1,60}$")
    direction: str=Field(pattern=r"^(at_least|at_most)$")
    threshold: float=Field(allow_inf_nan=False)
    maximum_experiments: int=Field(default=3,ge=1,le=10)

def wilson(successes,total,z=1.96):
    if not 0<=successes<=total or total<=0:raise ValueError("Invalid trial counts")
    p=successes/total;den=1+z*z/total
    center=(p+z*z/(2*total))/den
    half=z*math.sqrt(p*(1-p)/total+z*z/(4*total*total))/den
    return {"lower":max(0,center-half),"upper":min(1,center+half),"confidence":0.95,
            "basis":"Wilson binomial interval; assumes independent representative trials"}

class Experiments:
    def __init__(self,audit):
        self.audit=audit
        with audit.connect() as db:
            db.execute("CREATE TABLE IF NOT EXISTS experiments (claim TEXT NOT NULL, attempt INTEGER NOT NULL, candidate TEXT NOT NULL, result TEXT NOT NULL, UNIQUE(claim,attempt))")
            db.execute('CREATE TABLE IF NOT EXISTS claim_contracts (id TEXT PRIMARY KEY, document TEXT NOT NULL)')

    def _bind_claim(self,db,claim):
        document=json.dumps(claim.model_dump(),sort_keys=True,separators=(',',':'),allow_nan=False)
        row=db.execute('SELECT document FROM claim_contracts WHERE id=?',(claim.id,)).fetchone()
        if row:
            if row[0]!=document:raise ValueError('Claim metric, scope, threshold and experiment limits are immutable; version the claim')
        else:
            if db.execute('SELECT 1 FROM experiments WHERE claim=?',(claim.id,)).fetchone():
                raise ValueError('Legacy unpinned claim requires a new versioned identity')
            db.execute('INSERT INTO claim_contracts VALUES(?,?)',(claim.id,document))

    def request(self,run,claim:Claim,candidate_digest:str):
        if len(candidate_digest)!=64 or any(c not in '0123456789abcdef'for c in candidate_digest):raise ValueError("Candidate digest required")
        with self.audit.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            self._bind_claim(db,claim)
            prior=db.execute('SELECT candidate,result FROM experiments WHERE claim=? ORDER BY attempt',(claim.id,)).fetchall()
            if any(candidate==candidate_digest for candidate,_ in prior):raise ValueError('A new experiment requires a changed candidate')
            if any(json.loads(result)['state']=='requested'for _,result in prior):raise ValueError('Measure the pending experiment before starting another')
            attempt=db.execute("SELECT COUNT(*) FROM experiments WHERE claim=?",(claim.id,)).fetchone()[0]+1
            if attempt>claim.maximum_experiments:raise ValueError("Experiment budget exhausted; unresolved claim stays unverified")
            db.execute("INSERT INTO experiments VALUES(?,?,?,?)",(claim.id,attempt,candidate_digest,json.dumps({"state":"requested","claim":claim.model_dump()})))
        self.audit.emit(run,"proof-manager","experiment.requested",{"claim":claim.model_dump(),"attempt":attempt,"candidate_digest":candidate_digest})
        return attempt

    def record(self,run,claim:Claim,attempt:int,*,measured:dict,artifact:bytes,verifier:str):
        # Invoked by a trusted local verifier, never exposed as an LLM tool.
        if verifier not in {"pytest","gateway-diagnostic","deterministic-replay"}:raise ValueError("Untrusted verifier")
        metric=measured.get(claim.metric)
        if type(metric) not in (int,float) or not math.isfinite(metric):state="unverified"
        else:
            passed=metric>=claim.threshold if claim.direction=="at_least" else metric<=claim.threshold
            state="verified_in_declared_scope" if passed else "failed_replan_required"
        result={"state":state,"metric":claim.metric,"measured":measured,"verifier":verifier,
                "artifact_sha256":hashlib.sha256(artifact).hexdigest(),"scope":claim.scope}
        with self.audit.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            self._bind_claim(db,claim)
            row=db.execute("SELECT result FROM experiments WHERE claim=? AND attempt=?",(claim.id,attempt)).fetchone()
            if not row or json.loads(row[0])["state"]!="requested":raise ValueError("Experiment was not requested or is already closed")
            db.execute("UPDATE experiments SET result=? WHERE claim=? AND attempt=?",(json.dumps(result),claim.id,attempt))
        self.audit.emit(run,"proof-manager","experiment."+state,result)
        return result
