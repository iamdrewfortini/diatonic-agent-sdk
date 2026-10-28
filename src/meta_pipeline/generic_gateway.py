"""Provider-neutral, bounded inference through the existing Bifrost only.

SDK shapes are replaceable trusted ports. The gateway retains provider keys,
routing and caching. Model output is a proposal; this module cannot verify an
estate effect or accept a model's confidence as independent verification.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import hashlib
import inspect
import json
import ssl
import time
from urllib.parse import urlsplit

import httpx

from .gateway import GatewayConfig
from .model_routing import RouteAbstention
from .protocol import canonical
from .provider_contracts import BrokerRequest, BrokerResult, BrokerUsage


class SDKPorts:
    """Coordinator-owned versioned code registry, never imported from a genome."""
    def __init__(self):
        self._ports = {}

    def register(self, handler_id, handler_version, shape, adapter):
        key = (handler_id, handler_version, shape)
        if key in self._ports or not callable(getattr(adapter, "encode", None)) or not callable(getattr(adapter, "decode", None)):
            raise ValueError("Ambiguous or invalid trusted SDK port")
        self._ports[key] = adapter

    def bound(self, route):
        try:
            return self._ports[(route.sdk_handler_id, route.sdk_handler_version, route.api_shape)]
        except KeyError:
            raise ValueError("SDK shape handler unbound") from None


class GenericGateway:
    def __init__(self, config: GatewayConfig, ledger, audit, *, selector,
                 sdk_ports: SDKPorts, secret_broker, tenant: str,
                 allowed_paths=("/openai/chat/completions", "/openai/responses", "/anthropic/v1/messages"),
                 transport=None, enabled=False):
        config.validate_origin()
        if not tenant or selector.gateway_attempts != config.gateway_attempts:
            raise ValueError("Trusted tenant and matching gateway retry contract required")
        self.config, self.ledger, self.audit = config, ledger, audit
        if type(enabled) is not bool:
            raise ValueError("Explicit coordinator activation required")
        self.enabled = enabled
        self.selector, self.sdk_ports, self.secrets, self.tenant = selector, sdk_ports, secret_broker, tenant
        self.paths = frozenset(allowed_paths)
        origin = urlsplit(config.base_url)
        self.origin = f"{origin.scheme}://{origin.netloc}"
        verify = ssl.create_default_context(cafile=config.ca_file) if config.ca_file else True
        self.http = httpx.AsyncClient(transport=transport, trust_env=False, verify=verify,
            timeout=config.timeout_seconds, follow_redirects=False,
            limits=httpx.Limits(max_connections=2))

    def remaining(self, run):
        day = datetime.now(timezone.utc).date().isoformat()
        with self.ledger.connect() as db:
            daily = db.execute("SELECT COALESCE(SUM(COALESCE(charged,reserved)),0) FROM calls WHERE day=? OR charged IS NULL", (day,)).fetchone()[0]
            root = db.execute("SELECT COALESCE(SUM(COALESCE(charged,reserved)),0) FROM calls WHERE run=?", (run,)).fetchone()[0]
        return max(0, min(self.ledger.daily - daily, self.ledger.run - root))

    def _event(self, request, kind, detail):
        self.audit.emit(request.root_run_id, "provider-neutral-broker", kind,
            {"correlation_id": request.correlation_id, "request_sha256": request.digest,
             "original_request_sha256": request.original_request_sha256, **detail})

    async def generate(self, request: BrokerRequest):
        # Revalidate frozen nested values before trusting their digest.
        request = BrokerRequest.model_validate(request.model_dump())
        if not self.enabled:
            return RouteAbstention(reasons=("provider_neutral_runtime_not_activated",))
        route = self.selector.select(request, self.remaining(request.root_run_id))
        if isinstance(route, RouteAbstention):
            self._event(request, "routing.abstained", {"reason": "no_admissible_registered_binding"})
            return route
        if route.path not in self.paths or route.gateway_id != self.selector.gateway_id:
            raise ValueError("Unregistered Bifrost operation")
        adapter = self.sdk_ports.bound(route)
        payload = adapter.encode(request, route)
        if (not isinstance(payload, dict) or payload.get("model") != route.wire_model
                or any(k in payload for k in ("api_key", "base_url", "fallbacks", "provider"))):
            raise ValueError("SDK port changed model or routing authority")
        wire = canonical(payload)
        if len(wire) > 4 * 1024 * 1024:
            raise ValueError("Inference payload exceeds bound")
        quantities = {u.unit: u.quantity for u in request.usage_bounds}
        # Conservative byte estimate includes approved prompt and wire expansion;
        # not a claim to know every provider's tokenizer. Unknown media is unbound.
        if quantities.get("input_tokens", -1) < len(wire) + 1024:
            self._event(request, "routing.abstained", {"reason": "input_usage_bound_not_conservative", "payload_bytes": len(wire)})
            return RouteAbstention(reasons=("input_usage_bound_not_conservative",))
        secret = self.secrets.resolve_worker_key(route.credential_binding_id,
            gateway_id=route.gateway_id, tenant=self.tenant)
        if inspect.isawaitable(secret):
            secret = await secret
        key = secret.get_secret_value()
        if not key or len(key) > 16384 or any(c in key for c in "\r\n"):
            raise ValueError("Scoped gateway credential unavailable")
        # Resolve secrets before admission; validate source/version pins again at
        # the effect boundary in case configuration changed during SDK resolution.
        if isinstance(self.selector.validate(request, route, self.remaining(request.root_run_id)), RouteAbstention):
            self._event(request, "routing.abstained", {"reason": "stale_binding_after_secret_resolution"})
            return RouteAbstention(reasons=("stale_binding_after_secret_resolution",))
        reservation = self.ledger.reserve(request.root_run_id,
            route.provider_id + "/" + route.model_id, max(1, route.reserve_nusd))
        self._event(request, "model.request.intent", {"reservation_id": reservation,
            "provider_id": route.provider_id, "model_id": route.model_id,
            "binding_sha256": route.binding_sha256, "sdk_version": route.sdk_version,
            "flow_version": route.flow_version, "prompt_sha256": route.prompt_sha256,
            "payload_bytes": len(wire), "reserved_nusd": route.reserve_nusd})
        cache_identity = hashlib.sha256(canonical([self.tenant, hashlib.sha256(key.encode()).hexdigest(),
            route.binding_sha256, request.digest, request.artifact_sha256s])).hexdigest()
        headers = {"x-bf-vk": key, "Authorization": "", "Content-Type": "application/json",
            "x-bf-disable-content-logging": "true", "x-bf-cache-key": cache_identity,
            "x-bf-cache-type": "direct", "x-bf-cache-no-store": "true"}
        started = time.perf_counter()
        settled = False
        try:
            async with self.http.stream("POST", self.origin + route.path, content=wire, headers=headers) as response:
                chunks = []; size = 0
                async for chunk in response.aiter_bytes():
                    size += len(chunk)
                    if size > 8 * 1024 * 1024:
                        raise ValueError("Gateway response exceeds bound")
                    chunks.append(chunk)
                if response.status_code != 200:
                    raise ValueError("Gateway operation rejected")
                body = json.loads(b"".join(chunks))
                result = BrokerResult.model_validate(adapter.decode(body, response.headers, request, route))
                if (result.request_sha256 != request.digest or result.provider_id != route.provider_id
                        or result.model_id != route.model_id):
                    raise ValueError("SDK result source binding mismatch")
                # Prices are independently registered, never body.cost/confidence.
                observed = {"input_tokens": result.usage.input_tokens,
                    "output_tokens": result.usage.output_tokens, "cached_tokens": result.usage.cached_tokens}
                direct = (response.headers.get("x-bifrost-cache-hit", "").lower() == "true"
                    and response.headers.get("x-bifrost-cache-hit-type") == "direct")
                amount = 0 if direct else self.selector.registry.price_usage(route, result.usage, now=self.selector.now())
                per_attempt = route.reserve_nusd // route.gateway_attempts
                hold = 0 if direct else route.reserve_nusd - per_attempt
                detail = {"payload_bytes": len(wire), "response_body_bytes": size,
                    "upstream_usage": {"input_tokens": 0, "output_tokens": 0, "cached_tokens": 0} if direct else {k:v for k,v in observed.items() if v is not None},
                    "observed_usage": observed, "replayed_usage": observed if direct else {},
                    "usage_unknown": not direct and (result.usage.input_tokens is None or result.usage.output_tokens is None),
                    "http_elapsed_seconds": time.perf_counter() - started,
                    "gateway_cache": "direct" if direct else "unverified", "cache_state_reported": result.usage.cache_state,
                    "request_id": (response.headers.get("x-bf-request-id") or "")[:128],
                    "reported_derived_charge_nusd": amount,
                    "cost_basis": "pinned verified prices on reported units; not invoice reconciliation",
                    "automatic_retries": 0}
                if amount is None or amount > per_attempt:
                    detail["unreconciled_retry_allowance_nusd"] = hold
                    self.ledger.settle(reservation, None if amount is None else amount + hold, detail)
                    settled = True
                    self._event(request, "model.unresolved", {"reason": "unknown_usage_or_reservation_exceeded", **detail})
                    return result.model_copy(update={"status": "unresolved", "reason": "usage-reconciliation-required", "usage": result.usage.model_copy(update={"cost_nusd": None})})
                detail["unreconciled_retry_allowance_nusd"] = hold
                self.ledger.settle(reservation, amount + hold, detail)
                settled = True
                self._event(request, "model.response.measured", detail)
                return result.model_copy(update={"usage": result.usage.model_copy(update={"cost_nusd": amount,
                    **({"input_tokens": 0, "output_tokens": 0, "cached_tokens": 0, "cache_state": "bifrost_direct"} if direct else {})})})
        except BaseException as exc:
            if not settled:
                self.ledger.settle(reservation, None, {"error_type": type(exc).__name__,
                    "payload_bytes": len(wire), "http_elapsed_seconds": time.perf_counter() - started,
                    "automatic_retries": 0})
            self._event(request, "model.unresolved", {"reason_class": type(exc).__name__, "reservation_retained": True})
            raise

    async def close(self):
        await self.http.aclose()
