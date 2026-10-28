"""Bounded, ephemeral validation of an authoritative Rucio export.

No filesystem traversal, file hashing, replica registration, copy, or deletion.
"""
import hashlib
import json
from collections import defaultdict
from pathlib import PurePosixPath
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field

class Record(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    scope: str = Field(min_length=1, max_length=255)
    name: str = Field(min_length=1, max_length=1024)
    rse: str = Field(min_length=1, max_length=255)
    bytes: int = Field(ge=0)
    sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    checksum_kind: Literal["full", "unknown"] = "unknown"
    source_mutable: bool = True
    application_consistent: bool = False
    live_database: bool = False
    containment: bool = False

    @property
    def did(self):
        return (self.scope, self.name)

    @property
    def id(self):
        return hashlib.sha256(json.dumps([self.scope,self.name],separators=(",",":")).encode()).hexdigest()[:32]

def load_manifest(path, max_records=5000, max_bytes=8000000) -> list[Record]:
    records, total, seen = [], 0, set()
    with open(path,"rb") as source:
        while raw := source.readline(65537):
            total += len(raw)
            if len(raw) > 65536 or total > max_bytes or len(records) >= max_records:
                raise ValueError("Manifest exceeds bounded batch limits")
            rec = Record.model_validate_json(raw)
            key = (*rec.did,rec.rse)
            if key in seen:
                raise ValueError("Duplicate DID/RSE entry in batch")
            seen.add(key)
            records.append(rec)
    # Replicas of one DID must agree before any dedup inference.
    bydid = defaultdict(list)
    for r in records:
        bydid[r.did].append(r)
    for group in bydid.values():
        if len({r.bytes for r in group}) > 1 or len({r.sha256 for r in group if r.sha256}) > 1:
            raise ValueError("Conflicting replica evidence for one DID")
    return records

def digest(records):
    raw = [r.model_dump() for r in sorted(records,key=lambda r:(r.scope,r.name,r.rse))]
    return hashlib.sha256(json.dumps(raw,sort_keys=True,separators=(",",":")).encode()).hexdigest()

def assess(records: list[Record]) -> dict:
    groups, bydid = defaultdict(set), {}
    for r in records:
        bydid.setdefault(r.did,r)
        if r.sha256 and r.checksum_kind == "full" and not r.source_mutable and not r.containment and (not r.live_database or r.application_consistent):
            groups[(r.bytes,r.sha256)].add(r.did)
    candidates = [{"bytes_each":size,"sha256":sha,"dids":[list(d) for d in sorted(dids)],
                   "potential_duplicate_bytes": size*(len(dids)-1),
                   "status":"equal_content_candidate_only"}
        for (size,sha),dids in sorted(groups.items()) if len(dids)>1]
    classifications, unresolved = [], []
    suffixes = {".pdf":"documents", ".txt":"documents", ".md":"documents",
        ".py":"code", ".js":"code", ".ts":"code", ".rs":"code", ".go":"code",
        ".jpg":"media", ".jpeg":"media", ".png":"media", ".mp4":"media", ".wav":"media",
        ".iso":"software", ".log":"logs"}
    for r in bydid.values():
        ext = PurePosixPath(r.name).suffix.lower()
        label = "containment" if r.containment else "database_snapshot_required" if r.live_database and not r.application_consistent else suffixes.get(ext)
        if label:
            classifications.append({"id":r.id,"label":label,"basis":"deterministic_metadata"})
        else:
            # No source filename, DID, path or file content leaves the host.
            unresolved.append({"id":r.id,"extension":ext[:20] if ext.isascii() else "", "bytes":r.bytes,
                               "full_checksum_available":bool(r.sha256 and r.checksum_kind=="full")})
    return {"evidence_digest":digest(records), "records":len(records), "unique_dids":len(bydid),
        "source_bytes":sum(r.bytes for r in bydid.values()), "duplicate_candidates":candidates,
        "classifications":classifications,"unresolved":unresolved,
        "execution":"proposal_only", "source_authority":"caller-supplied Rucio export; freshness must be verified by caller",
        "required_before_retirement":["fresh authoritative replica and retention checks", "independent verified target replica", "policy-authorized Rucio rule retirement"],
        "ai_tokens_for_deterministic_checks":0}
