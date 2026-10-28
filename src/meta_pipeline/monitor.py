"""Read-only live inspection via standard FastAPI + SSE. No execution API."""
import asyncio
import hmac
import json
from importlib import metadata
from pathlib import Path
import sys
from fastapi import FastAPI,Request,HTTPException,Depends
from fastapi.responses import HTMLResponse
from fastapi.security import HTTPBearer,HTTPAuthorizationCredentials
from sse_starlette.sse import EventSourceResponse

def create_app(audit,ledger,key):
    if not key or len(key)<24:raise ValueError("Private monitor credential required")
    app=FastAPI(title="Diatonic Agent Watch",docs_url=None,redoc_url=None)
    # Capture once at process start. Resolving current/ dynamically after an
    # update would let an old process accidentally report the new release.
    runtime={"version":metadata.version("diatonic-meta-pipeline"),"wheel_sha256":None}
    release=Path(sys.prefix).resolve().parent/"release.json"
    if release.is_file() and not release.is_symlink() and release.stat().st_size<=131072:
        record=json.loads(release.read_bytes())
        value=record.get("wheel_sha256") or record.get("wheel",{}).get("sha256")
        if isinstance(value,str) and len(value)==64 and all(c in "0123456789abcdef" for c in value):
            runtime["wheel_sha256"]=value
    bearer=HTTPBearer(auto_error=False)
    async def auth(credentials:HTTPAuthorizationCredentials|None=Depends(bearer)):
        if credentials is None or not hmac.compare_digest(credentials.credentials,key):raise HTTPException(401,"Authentication required")

    @app.get("/api/state",dependencies=[Depends(auth)])
    async def state():return {**audit.snapshot(),"usage":ledger.summary(),"integrity":audit.verify()}

    @app.get('/api/protocol',dependencies=[Depends(auth)])
    async def protocol():
        from .protocol import document,digest
        return {'contract':document(),'contract_sha256':digest(),'runtime':runtime}

    @app.get("/api/events",dependencies=[Depends(auth)])
    async def events(request:Request,after:int=0):
        if after<0:raise HTTPException(400,"Invalid cursor")
        async def stream():
            cursor=after
            while not await request.is_disconnected():
                rows=audit.events(cursor)
                for row in rows:
                    cursor=row["seq"]
                    yield {"id":str(cursor),"event":"activity","data":json.dumps(row)}
                await asyncio.sleep(.5)
        return EventSourceResponse(stream(),ping=10,headers={"Cache-Control":"no-store","X-Content-Type-Options":"nosniff"})

    @app.get("/",response_class=HTMLResponse)
    async def index():return PAGE
    return app

PAGE="""<!doctype html><html><meta charset=utf-8><title>Diatonic Agent Watch</title>
<style>body{font:15px system-ui;background:#10151b;color:#dfecf5;margin:2em}input,button{font:inherit;padding:.5em}pre{white-space:pre-wrap;border:1px solid #344450;padding:1em}#status{color:#80e0ca}</style>
<h1>Diatonic Agent Watch</h1><p>Live activity, shared budgets and evidence. Display covers instrumented work only.</p>
<input id=key type=password placeholder="Monitor access key" autocomplete=off><button id=connect>Connect</button>
<p id=status>Disconnected</p><h2>13 channels</h2><pre id=protocol></pre><h2>Agents and budget</h2><pre id=state></pre><h2>Activity (most recent 200)</h2><pre id=events></pre>
<script>
let token='',timer,cursor=0,lines=[];
async function update(){try{let r=await fetch('/api/state',{headers:{Authorization:'Bearer '+token},cache:'no-store'});if(!r.ok)throw new Error('Authentication or service failure');let s=await r.json();document.getElementById('state').textContent=JSON.stringify(s,null,2);document.getElementById('status').textContent='Connected · '+new Date().toLocaleTimeString()}catch(e){document.getElementById('status').textContent=e.message}}
async function stream(){while(token){try{let r=await fetch('/api/events?after='+cursor,{headers:{Authorization:'Bearer '+token}});if(!r.ok)throw new Error('Stream refused');let reader=r.body.getReader(),decoder=new TextDecoder(),buffer='';while(true){let chunk=await reader.read();if(chunk.done)break;buffer+=decoder.decode(chunk.value,{stream:true}).replace(/\\r\\n/g,'\\n');let parts=buffer.split('\\n\\n');buffer=parts.pop();for(let p of parts){let line=p.split('\\n').find(l=>l.startsWith('data: '));if(line){let event=JSON.parse(line.slice(6));cursor=event.seq;lines.unshift(JSON.stringify(event));lines=lines.slice(0,200);document.getElementById('events').textContent=lines.join('\\n')}}}}catch(e){document.getElementById('status').textContent='Reconnecting: '+e.message}await new Promise(r=>setTimeout(r,1000))}}
document.getElementById('connect').onclick=()=>{if(token)return;token=document.getElementById('key').value;document.getElementById('key').value='';fetch('/api/protocol',{headers:{Authorization:'Bearer '+token},cache:'no-store'}).then(r=>r.json()).then(p=>{document.getElementById('protocol').textContent=JSON.stringify(p,null,2)});update();timer=setInterval(update,1000);stream()};
</script></html>"""
