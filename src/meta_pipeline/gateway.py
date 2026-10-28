"""OpenAI wire SDK -> existing Bifrost -> Meta. No direct upstream fallback."""
import hashlib
import json
import os
import stat
import subprocess
import time
from pathlib import Path
from urllib.parse import urlsplit
import httpx
from openai import AsyncOpenAI
from pydantic import BaseModel, ConfigDict, Field
from .models import Workload, route, bill_nusd, forecast, MODELS
from .ledger import Ledger
from .contracts import chat_contract
from .bifrost_compat import BifrostMetaHTTP

class GatewayConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    base_url: str = "http://bifrost.inference.svc.cluster.local:8080/openai"
    allowed_hosts: list[str] = Field(default_factory=lambda: ["bifrost.inference.svc.cluster.local"])
    key_ref: str = "env:BIFROST_VIRTUAL_KEY"
    ca_file: str | None = None
    namespace: str = "diatonic-filesystem-v1"
    daily_nusd: int = Field(default=250000000, gt=0)  # $0.25, conservative starter ceiling
    run_nusd: int = Field(default=100000000, gt=0)     # $0.10
    timeout_seconds: float = Field(default=120, gt=0, le=300)
    gateway_attempts: int = Field(default=3, ge=1, le=10) # deployed gateway max_retries=2
    allowed_models: list[str] = Field(default_factory=list) # must reflect the scoped VK, not catalog
    verified_endpoints: list[str] = Field(default_factory=list)

    def validate_origin(self):
        u = urlsplit(self.base_url)
        if u.scheme not in ("http", "https") or not u.hostname or u.hostname not in self.allowed_hosts:
            raise ValueError("Gateway origin is not allowlisted")
        if u.hostname in ("api.openai.com", "api.meta.ai", "api.anthropic.com", "nexos.ai", "router.hostinger.com") or u.hostname.endswith((".openai.com", ".anthropic.com", ".nexos.ai")):
            raise ValueError("Direct upstream API endpoints are forbidden; use Bifrost")
        if u.username or u.password or u.query or u.fragment:
            raise ValueError("Gateway URL cannot carry credentials or query parameters")
        if u.scheme == "http" and u.hostname not in ("localhost", "127.0.0.1", "::1") and not u.hostname.endswith(".svc.cluster.local"):
            raise ValueError("Use TLS outside cluster DNS or a loopback tunnel")
        if self.ca_file and not Path(self.ca_file).is_file():
            raise ValueError("CA file is missing")

def resolve_secret(ref: str) -> str:
    if ref.startswith("systemd:"):
        from .systemd_credentials import read
        return read(ref[8:]).get_secret_value()
    if ref.startswith("env:"):
        value = os.environ.get(ref[4:], "")
    elif ref.startswith("file:"):
        p = Path(ref[5:])
        flags = os.O_RDONLY | os.O_NOFOLLOW
        fd = os.open(p, flags)
        try:
            s = os.fstat(fd)
            if not stat.S_ISREG(s.st_mode) or stat.S_IMODE(s.st_mode) & 0o077 or s.st_size > 16384:
                raise ValueError("Credential file must be a small private regular file")
            value = os.read(fd, 16384).decode().strip()
        finally:
            os.close(fd)
    elif ref.startswith("op://"):
        result = subprocess.run(["op", "read", ref], capture_output=True, text=True, timeout=15)
        if result.returncode:
            raise ValueError("1Password reference could not be resolved")
        value = result.stdout.strip()
    else:
        raise ValueError("Use env:, file:, or op:// credential references")
    if not value or any(c in value for c in "\r\n"):
        raise ValueError("Gateway credential is unavailable or invalid")
    return value

def direct_hit(body: dict, headers) -> bool:
    h = {k.lower(): v for k,v in headers.items()}
    debug = body.get("extra_fields", {}).get("cache_debug", {}) or {}
    hit = h.get("x-bifrost-cache-hit", "").lower() == "true" or debug.get("cache_hit") is True
    kind = h.get("x-bifrost-cache-hit-type") or debug.get("hit_type")
    # Unqualified/semantic cache hits are not assumed to be free.
    return hit and kind == "direct"

def measured_usage(body: dict, headers, m) -> tuple[int | None, dict]:
    u = body.get("usage") or {}
    if direct_hit(body, headers):
        return 0, {"gateway_cache": "direct", "replayed_usage": u, "upstream_usage": {},
                   "cost_basis": "zero new upstream inference; gateway infrastructure excluded"}
    detail = {"gateway_cache": "miss_or_unverified", "reported_usage": u,
              "cost_basis": "Meta public prices applied to reported units; gateway retries may add cost"}
    try:
        if m.billing == "tokens":
            i = u.get("input_tokens", u.get("prompt_tokens"))
            o = u.get("output_tokens", u.get("completion_tokens"))
            c = (u.get("input_tokens_details") or u.get("prompt_tokens_details") or {}).get("cached_tokens", 0)
            if not all(type(x) is int for x in (i,o,c)):
                return None, detail
            detail["upstream_usage"] = {"input_tokens": i, "cached_tokens": c, "output_tokens": o}
            return bill_nusd(m, input_tokens=i, cached_tokens=c, output_tokens=o), detail
        if m.billing == "images":
            data = body.get("data")
            if not isinstance(data, list):
                return None, detail
            count = sum(bool(d.get("b64_json") or d.get("url")) for d in data)
            return bill_nusd(m, images=count), {**detail, "generated_images": count}
        if m.billing == "audio_seconds":
            ms = body.get("audioDurationMs")
            seconds = ms/1000 if type(ms) is int and ms>=0 else None
            if not isinstance(seconds, (int,float)):
                return None, detail
            return bill_nusd(m, audio_seconds=seconds), {**detail,"audio_seconds": seconds}
        if m.billing == "segmentation":
            frames, images = u.get("video_frames_processed"), u.get("images_processed")
            if type(frames) is int and frames > 0:
                return bill_nusd(m, video_frames=[frames]), {**detail, "video_frames_processed": frames}
            if type(images) is int and images > 0:
                return bill_nusd(m, images=images), {**detail, "images_processed": images}
    except (ValueError, TypeError, OverflowError):
        return None, detail
    return None, detail

class MetaGateway:
    def __init__(self, config: GatewayConfig, ledger: Ledger, *, key=None, transport=None):
        config.validate_origin()
        self.config, self.ledger = config, ledger
        secret = key or resolve_secret(config.key_ref)
        if config.ca_file:
            import ssl
            verify = ssl.create_default_context(cafile=config.ca_file)
        else:
            verify = True
        self.client = AsyncOpenAI(api_key=secret, base_url=config.base_url,
            max_retries=0, timeout=config.timeout_seconds,
            default_headers={"x-bf-vk": secret,"Authorization":""},
            http_client=BifrostMetaHTTP(transport=transport, verify=verify, trust_env=False))

    async def close(self):
        await self.client.close()

    async def readiness(self):
        remote = await self.client.models.list()
        advertised = {m.id for m in remote.data}
        return [{"model": mid, "hosted": m.hosted,
            "gateway_advertised": mid in advertised or f"meta/{mid}" in advertised,
            "virtual_key_allowed": mid in self.config.allowed_models,
            "status": "self_hosted_endpoint_required" if not m.hosted else
                "configured_not_inference_verified" if mid in self.config.allowed_models else "not_allowed_by_profile"}
            for mid,m in MODELS.items()]

    async def text(self, *, run: str, w: Workload, messages: list[dict], schema: dict,
                   cache_scope: str, evidence_digest: str) -> dict:
        m = route(w)
        if m.output != "text" or w.input_kind != "text":
            raise ValueError("This validation runner only sends text; use a verified media adapter")
        if m.id not in self.config.allowed_models or "chat" not in self.config.verified_endpoints:
            raise ValueError("Model or endpoint is not allowed in this gateway profile")
        if w.search_queries:
            raise ValueError("Web search is disabled for filesystem validation")
        contract=chat_contract(m.id,messages,w.max_output_tokens,schema)
        canonical=json.dumps(contract.model_dump(by_alias=True),sort_keys=True,separators=(",",":"),ensure_ascii=False)
        # UTF-8 byte length + framing is conservative, not an exact Meta tokenizer.
        estimated = len(canonical.encode()) + 1024
        if w.input_tokens < estimated:
            raise ValueError("Input token reservation is below conservative request-byte estimate")
        f = forecast(w)
        reservation = f["reserve_nusd"] * self.config.gateway_attempts
        key = self.ledger.reserve(run, m.id, reservation)
        digest = hashlib.sha256(json.dumps({"namespace":self.config.namespace,
            "scope":cache_scope,"model":m.id,"evidence":evidence_digest,"request":canonical},sort_keys=True).encode()).hexdigest()
        try:
            started=time.perf_counter_ns()
            response = await self.client.chat.completions.with_raw_response.create(
                model=f"meta/{m.id}", messages=messages,
                max_completion_tokens=contract.max_completion_tokens, temperature=0, store=False,
                reasoning_effort=contract.reasoning_effort,
                response_format={"type":"json_schema","json_schema":{"name":"validation","strict":True,"schema":schema}},
                extra_headers={"x-bf-cache-key":digest,"x-bf-cache-type":"direct","x-bf-cache-ttl":"24h",
                               "x-bf-disable-content-logging":"true"})
            parsed = response.parse()
            body = parsed.model_dump(mode="json")
        except Exception as exc:
            # Never log exception bodies: gateway errors can echo request text or secrets.
            self.ledger.settle(key,None,{"error_type": type(exc).__name__,"reservation_attempts":self.config.gateway_attempts})
            raise RuntimeError("Gateway call failed; reservation retained for reconciliation") from None
        charge, detail = measured_usage(body,response.headers,m)
        if body.get("model") not in (m.id,f"meta/{m.id}"):
            self.ledger.settle(key,None,{"error_type":"unexpected_response_model"})
            raise ValueError("Unexpected provider/model identity; reservation retained")
        detail.update({"request_id": response.headers.get("x-bf-request-id") or response.headers.get("x-request-id"),
                       "payload_bytes":len(response.http_response.request.content),
                       "response_body_bytes":len(response.http_response.content),
                       "http_elapsed_seconds":(time.perf_counter_ns()-started)/1e9,
                       "bytes_basis":"measured HTTP JSON bodies; headers/TLS and gateway upstream transformations excluded",
                       "source_bytes":w.source_bytes,
                       "forecast_input_tokens":w.input_tokens,"forecast_output_tokens":w.max_output_tokens})
        # Successful final response cannot prove earlier gateway retries weren't billed.
        # Keep that extra-attempt allowance held until a gateway log reconciliation exists.
        if charge is not None and not direct_hit(body,response.headers):
            allowance = f["reserve_nusd"] * (self.config.gateway_attempts-1)
            detail["unreconciled_retry_allowance_nusd"] = allowance
            detail["derived_final_response_nusd"] = charge
            charge += allowance
        self.ledger.settle(key,charge,detail)
        if not parsed.choices or parsed.choices[0].finish_reason != "stop":
            raise ValueError("Incomplete or tool-call output rejected; usage remains charged")
        msg = parsed.choices[0].message
        if msg.tool_calls or msg.refusal or not msg.content:
            raise ValueError("Non-text or refused output rejected; usage remains charged")
        try:
            return json.loads(msg.content)
        except ValueError:
            raise ValueError("Malformed structured output; usage remains charged") from None
