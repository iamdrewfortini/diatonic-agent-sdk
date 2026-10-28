"""Boot provider-neutral inference from explicit trusted operator configuration.

Defaults remain disabled. An unattended SDK service identity must be injected
by the service manager; no password, CLI login, or raw key argument is accepted.
"""
import json
import os
from pathlib import Path
import stat

from pydantic import BaseModel, ConfigDict, Field

from .audit import Audit
from .gateway import GatewayConfig
from .generic_gateway import GenericGateway, SDKPorts
from .ledger import Ledger
from .model_routing import BindingRegistry, KINDS, RouteSelector, RouteAbstention
from .provider_contracts import BrokerRequest, ChatShapeAdapter, ResponsesShapeAdapter
from .secret_broker import OnePasswordBroker, SecretBinding, SystemdCredentialToken, SecretUnavailable


APPROVED_HANDLERS = frozenset({("chat", "1"), ("responses", "1"), ("genetic-activities", "1")})


class BrokerConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    enabled: bool = False
    gateway_id: str = "bifrost"
    tenant: str = Field(min_length=1, max_length=128)
    bootstrap_credential_name: str = "onepassword-service-account"
    secret_bindings: list[dict] = Field(default_factory=list, max_length=128)


def read_bounded(path):
    p = Path(path)
    limit = 8 * 1024 * 1024
    fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as source:
        before = os.fstat(source.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
            raise ValueError("Bounded regular configuration file required")
        raw = source.read(limit + 1)
        after = os.fstat(source.fileno())
    if len(raw) > limit or (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise ValueError("Configuration changed during bounded read")
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("Duplicate configuration field")
            value[key] = item
        return value
    def invalid(_):
        raise ValueError("Nonfinite configuration value")
    json.loads(raw, object_pairs_hook=unique, parse_constant=invalid)
    return raw


def load_bindings(path):
    data = json.loads(read_bounded(path))
    if not isinstance(data, dict) or set(data) - {"version", "bindings", "activations"} or data.get("version") != "bindings-v1":
        raise ValueError("Unsupported registry configuration")
    items = data.get("bindings")
    if not isinstance(items, list) or len(items) > 1024:
        raise ValueError("Bounded binding list required")
    registry = BindingRegistry(approved_handlers=APPROVED_HANDLERS)
    for item in items:
        if not isinstance(item, dict) or set(item) != {"kind", "binding"} or item["kind"] not in KINDS:
            raise ValueError("Explicit registered binding kind required")
        registry.register(KINDS[item["kind"]].model_validate_json(json.dumps(item["binding"])))
    activations = data.get("activations", [])
    if not isinstance(activations, list) or len(activations) > 1024:
        raise ValueError("Bounded activations required")
    for item in activations:
        if not isinstance(item, dict) or set(item) != {"kind", "id", "version", "expected_version"} or item["kind"] not in KINDS:
            raise ValueError("Explicit version precondition required")
        registry.activate(item["kind"], item["id"], item["version"], expected_version=item["expected_version"])
    return registry


async def run_broker(*, gateway_config, broker_config, registry, request, ledger_path, audit_path):
    if not broker_config.enabled:
        return RouteAbstention(reasons=("provider_neutral_runtime_not_activated",))
    ledger = Ledger(str(ledger_path), gateway_config.daily_nusd, gateway_config.run_nusd)
    audit = Audit(audit_path)
    selector = RouteSelector(registry, gateway_id=broker_config.gateway_id,
        gateway_attempts=gateway_config.gateway_attempts)
    # Refuse missing routes without authenticating or reading vault data.
    if isinstance(selector.select(request, min(ledger.daily, ledger.run)), RouteAbstention):
        return RouteAbstention(reasons=("no_admissible_registered_binding",))
    try:
        secrets = await OnePasswordBroker.from_service_account(
            [SecretBinding(**row) for row in broker_config.secret_bindings],
            token_source=SystemdCredentialToken(broker_config.bootstrap_credential_name))
    except SecretUnavailable as exc:
        audit.emit(request.root_run_id, "credential-broker", "credentials.pending",
            {"reason": exc.reason, "correlation_id": request.correlation_id})
        return RouteAbstention(reasons=("pending_unattended_sdk_credentials", exc.reason))
    ports = SDKPorts()
    ports.register("chat", "1", "chat-completions-v1", ChatShapeAdapter())
    ports.register("responses", "1", "responses-v1", ResponsesShapeAdapter())
    gateway = GenericGateway(gateway_config, ledger, audit, selector=selector,
        sdk_ports=ports, secret_broker=secrets, tenant=broker_config.tenant, enabled=True)
    try:
        return await gateway.generate(request)
    finally:
        await gateway.close()
