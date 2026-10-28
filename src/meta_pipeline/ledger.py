"""Atomic local budget reservations. This is NOT a file or replica catalog."""
import json
import os
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path

class Ledger:
    def __init__(self, path: str, daily_nusd: int, run_nusd: int):
        if min(daily_nusd, run_nusd) <= 0:
            raise ValueError("Positive spend limits required")
        self.path, self.daily, self.run = path, daily_nusd, run_nusd
        if path == ":memory:":
            raise ValueError("Persistent ledger required")
        p = Path(path)
        p.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd = os.open(p, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        os.chmod(p, 0o600)
        with self.connect() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("""CREATE TABLE IF NOT EXISTS calls (
                id TEXT PRIMARY KEY, run TEXT NOT NULL, day TEXT NOT NULL,
                model TEXT NOT NULL, reserved INTEGER NOT NULL, charged INTEGER,
                state TEXT NOT NULL, detail TEXT NOT NULL DEFAULT '{}')""")
            db.execute("CREATE TABLE IF NOT EXISTS reconciliations (call_id TEXT NOT NULL, before_reserved INTEGER NOT NULL, retained_reserved INTEGER NOT NULL, evidence_digest TEXT NOT NULL)")

    def connect(self):
        return sqlite3.connect(self.path, timeout=30)

    def reserve(self, run: str, model: str, amount: int) -> str:
        if not run or not isinstance(amount, int) or amount <= 0:
            raise ValueError("Positive integer reservation and run identity required")
        day = datetime.now(timezone.utc).date().isoformat()
        key = uuid.uuid4().hex
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            # Unresolved calls carry across midnight; a timeout is never free.
            daily = db.execute("SELECT COALESCE(SUM(COALESCE(charged,reserved)),0) FROM calls WHERE day=? OR charged IS NULL", (day,)).fetchone()[0]
            run_total = db.execute("SELECT COALESCE(SUM(COALESCE(charged,reserved)),0) FROM calls WHERE run=?", (run,)).fetchone()[0]
            if daily+amount > self.daily or run_total+amount > self.run:
                raise ValueError("Spend admission denied")
            db.execute("INSERT INTO calls(id,run,day,model,reserved,state) VALUES(?,?,?,?,?,'reserved')", (key,run,day,model,amount))
        return key

    def settle(self, key: str, amount: int | None, detail: dict):
        if amount is not None and (not isinstance(amount, int) or amount < 0):
            raise ValueError("Invalid charge")
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT state FROM calls WHERE id=?", (key,)).fetchone()
            if not row or row[0] != "reserved":
                raise ValueError("Unknown or already settled call")
            db.execute("UPDATE calls SET charged=?,state=?,detail=? WHERE id=?",
                (amount, "unresolved" if amount is None else "measured_derived_cost", json.dumps(detail, sort_keys=True), key))

    def summary(self) -> dict:
        with self.connect() as db:
            rows = db.execute("SELECT state,COUNT(*),SUM(COALESCE(charged,reserved)) FROM calls GROUP BY state").fetchall()
            calls = db.execute("SELECT model,reserved,charged,detail FROM calls").fetchall()
        bymodel = {}
        for model,reserved,charged,raw in calls:
            entry=bymodel.setdefault(model,{"requests":0,"direct_cache_hits":0,"input_tokens":0,
                "cached_input_tokens":0,"output_tokens":0,"source_bytes":0,"payload_bytes":0,
                "response_body_bytes":0,"http_elapsed_seconds":0,
                "known_derived_cost_nusd":0,"unresolved_reservation_nusd":0,"retry_allowance_held_nusd":0,
                "forecast_input_tokens":0,"forecast_max_output_tokens":0,"unknown_usage_calls":0})
            d=json.loads(raw)
            entry["unknown_usage_calls"]+=int(bool(d.get("usage_unknown",False)))
            u=d.get("upstream_usage",{})
            entry["requests"]+=1
            entry["direct_cache_hits"]+=d.get("gateway_cache")=="direct"
            entry["input_tokens"]+=u.get("input_tokens",0)
            entry["cached_input_tokens"]+=u.get("cached_tokens",0)
            entry["output_tokens"]+=u.get("output_tokens",0)
            entry["source_bytes"]+=d.get("source_bytes",0)
            entry["payload_bytes"]+=d.get("payload_bytes",0)
            entry["response_body_bytes"]+=d.get("response_body_bytes",0)
            entry["http_elapsed_seconds"]+=d.get("http_elapsed_seconds",0)
            entry["forecast_input_tokens"]+=d.get("forecast_input_tokens",0)
            entry["forecast_max_output_tokens"]+=d.get("forecast_output_tokens",0)
            hold=d.get("unreconciled_retry_allowance_nusd",0)
            entry["retry_allowance_held_nusd"]+=hold
            if charged is None:entry["unresolved_reservation_nusd"]+=reserved
            else:entry["known_derived_cost_nusd"]+=charged-hold
        for e in bymodel.values():
            e['model_payload_bits']=8*(e['payload_bytes']+e['response_body_bytes'])
            e["derived_usd_per_tib_of_source_metadata_reviewed"]=(e["known_derived_cost_nusd"]/1e9*1099511627776/e["source_bytes"] if e["source_bytes"] else None)
        return {"states": [{"state": s, "calls": n, "accounted_nusd": a} for s,n,a in rows],
            "by_model":bymodel,
            "daily_limit_nusd": self.daily, "run_limit_nusd": self.run,
            "cost_basis": "public rate derivation from reported usage; not invoice reconciliation"}

    def narrow_unresolved_delegation(self,key,retained,evidence_digest):
        """Trusted coordinator only: release unused delegation, retain uncertain calls.

        Evidence must enumerate all admitted child requests after the worker has
        terminated. This is not a refund or a claim that unknown requests were free.
        """
        if type(retained)is not int or retained<0 or len(evidence_digest)!=64 or any(c not in '0123456789abcdef'for c in evidence_digest):
            raise ValueError('Bounded retained reservation and evidence digest required')
        with self.connect()as db:
            db.execute('BEGIN IMMEDIATE')
            row=db.execute('SELECT reserved,charged,state,detail FROM calls WHERE id=?',(key,)).fetchone()
            if not row or row[1]is not None or row[2]!='unresolved'or retained>row[0]:raise ValueError('Only unresolved unused delegation can be narrowed')
            detail=json.loads(row[3]);detail.update(original_delegation_reserved_nusd=row[0],child_request_hold_nusd=retained,reconciliation_evidence=evidence_digest)
            db.execute('INSERT INTO reconciliations VALUES(?,?,?,?)',(key,row[0],retained,evidence_digest))
            db.execute('UPDATE calls SET reserved=?,detail=? WHERE id=?',(retained,json.dumps(detail),key))
