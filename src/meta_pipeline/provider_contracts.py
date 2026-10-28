"""Provider-neutral immutable contracts; Bifrost retains routing and cache authority.

These contracts describe proposals and measured inference, never independent task
verification, credits admission, or authority to execute model-generated code.
"""
from __future__ import annotations

import hashlib
from typing import Literal, Mapping, Protocol, TYPE_CHECKING
from pydantic import BaseModel, ConfigDict, Field, model_validator
from .protocol import canonical, CODONS, PROTOCOL_ID

if TYPE_CHECKING:
    from .model_routing import SelectedRoute


class FrozenContract(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True, frozen=True)

    @property
    def digest(self) -> str:
        return hashlib.sha256(canonical(self.model_dump(mode='json'))).hexdigest()


class VersionedBinding(FrozenContract):
    id: str = Field(min_length=1, max_length=128, pattern=r'^[A-Za-z0-9_.:/-]+$')
    version: str = Field(min_length=1, max_length=64)
    source_sha256: str = Field(pattern=r'^[0-9a-f]{64}$')


class ProviderBinding(VersionedBinding):
    gateway_id: str
    routing_owner: Literal['Bifrost'] = 'Bifrost'
    enabled: bool = False
    evidence_ref: str = Field(min_length=1)


class ModelBinding(VersionedBinding):
    provider_id: str
    model_id: str = Field(min_length=1, max_length=256)
    wire_model: str = Field(min_length=1, max_length=512)
    capabilities: tuple[str, ...]
    endpoint_ids: tuple[str, ...] = ()
    input_modalities: tuple[str, ...]
    output_modalities: tuple[str, ...]
    allowed_data_classes: tuple[Literal['public', 'internal', 'private', 'restricted'], ...]
    training_opt_in_required: bool = False
    context_limit: int = Field(gt=0)
    entitlement_verified: bool = False
    evidence_ref: str = Field(min_length=1)


class EndpointBinding(VersionedBinding):
    provider_id: str
    gateway_id: str
    path: str = Field(min_length=1, max_length=256)
    api_shape: str
    credential_binding_id: str = Field(min_length=1)
    verified: bool = False
    authentication_verified: bool = False
    evidence_ref: str = Field(min_length=1)

    @model_validator(mode='after')
    def relative_path(self):
        from urllib.parse import urlsplit, unquote
        parsed = urlsplit(self.path)
        decoded = unquote(self.path)
        if (not self.path.startswith('/') or self.path.startswith('//') or
                parsed.scheme or parsed.netloc or parsed.query or parsed.fragment or '%' in self.path or
                '\\' in decoded or '%' in decoded or decoded.startswith('//') or any(p in ('.', '..') for p in decoded.split('/')) or
                any(ord(c) < 32 for c in self.path)):
            raise ValueError('Endpoint must be a bounded Bifrost-relative path')
        return self


class SDKBinding(VersionedBinding):
    api_shape: str
    handler_id: str
    handler_version: str
    verified: bool = False


class PromptBinding(VersionedBinding):
    template: str = Field(max_length=65536)
    capabilities: tuple[str, ...] = ()


class FlowBinding(VersionedBinding):
    handler_id: str
    handler_version: str
    sdk_ids: tuple[str, ...]
    capabilities: tuple[str, ...]
    allowed_gene_ids: tuple[str, ...] = ()
    maximum_steps: int = Field(default=4, ge=1, le=32)


class UnitPrice(FrozenContract):
    unit: str = Field(min_length=1)
    nusd: int = Field(ge=0)


class PricingBinding(VersionedBinding):
    provider_id: str
    model_id: str
    rates: tuple[UnitPrice, ...]
    verified: bool = False
    observed_at: str = Field(min_length=1)
    valid_until: str = Field(min_length=1)
    evidence_ref: str = Field(min_length=1)

    @model_validator(mode='after')
    def unique_rates(self):
        if len({r.unit for r in self.rates}) != len(self.rates) or not self.rates:
            raise ValueError('Distinct explicit pricing units required')
        from datetime import datetime
        first, last = (datetime.fromisoformat(x) for x in (self.observed_at, self.valid_until))
        if first.tzinfo is None or last.tzinfo is None or last <= first:
            raise ValueError('Pricing needs ordered timezone-aware validity bounds')
        return self


class CreditObservation(FrozenContract):
    provider_id: str
    quantity: int = Field(ge=0)
    unit: str
    status: Literal['user_reported_unverified'] = 'user_reported_unverified'
    spend_authority: Literal[False] = False


REPORTED_CREDITS = (
    CreditObservation(provider_id='meta', quantity=150, unit='USD'),
    CreditObservation(provider_id='anthropic', quantity=200, unit='USD'),
    CreditObservation(provider_id='nexos', quantity=100, unit='unspecified_credit_units'),
)


class UsageBound(FrozenContract):
    unit: str = Field(min_length=1, max_length=64)
    quantity: int = Field(ge=0)


class BrokerMessage(FrozenContract):
    role: Literal['system', 'developer', 'user', 'assistant']
    content: str = Field(max_length=131072)


class BrokerRequest(FrozenContract):
    contract_version: Literal['broker-v1'] = 'broker-v1'
    task: str = Field(min_length=1, max_length=128)
    messages: tuple[BrokerMessage, ...] = Field(min_length=1, max_length=32)
    capabilities: tuple[str, ...]
    input_modalities: tuple[str, ...] = ('text',)
    output_modality: str = 'text'
    data_class: Literal['public', 'internal', 'private', 'restricted'] = 'private'
    allow_training_opt_in: bool = False
    max_output_tokens: int = Field(ge=1, le=1000000)
    usage_bounds: tuple[UsageBound, ...] = Field(min_length=1, max_length=32)
    original_request_sha256: str = Field(pattern=r'^[0-9a-f]{64}$')
    artifact_sha256s: tuple[str, ...] = Field(default=(), max_length=64)
    correlation_id: str = Field(min_length=1, max_length=128)
    root_run_id: str = Field(min_length=1, max_length=128)
    flow_id: str
    flow_version: str
    prompt_id: str
    prompt_version: str

    @model_validator(mode='after')
    def usage_and_artifacts(self):
        if len({u.unit for u in self.usage_bounds}) != len(self.usage_bounds):
            raise ValueError('Duplicate usage bounds')
        if any(len(x) != 64 or any(c not in '0123456789abcdef' for c in x) for x in self.artifact_sha256s):
            raise ValueError('Artifacts require content/version SHA-256 bindings')
        units = {u.unit: u.quantity for u in self.usage_bounds}
        if units.get('output_tokens', -1) < self.max_output_tokens:
            raise ValueError('Output usage bound is below requested token cap')
        return self


class BrokerUsage(FrozenContract):
    input_tokens: int | None = Field(default=None, ge=0)
    output_tokens: int | None = Field(default=None, ge=0)
    cached_tokens: int | None = Field(default=None, ge=0)
    units: tuple[UsageBound, ...] = ()
    cost_nusd: int | None = Field(default=None, ge=0)
    cache_state: Literal['unknown', 'miss', 'provider_prefix', 'bifrost_direct'] = 'unknown'

    @model_validator(mode='after')
    def measured_bounds(self):
        if (self.cached_tokens is not None and self.input_tokens is not None and
                self.cached_tokens > self.input_tokens):
            raise ValueError('Cached tokens exceed input tokens')
        if len({u.unit for u in self.units}) != len(self.units):
            raise ValueError('Duplicate measured usage units')
        return self


class BrokerResult(FrozenContract):
    contract_version: Literal['broker-v1'] = 'broker-v1'
    status: Literal['proposed', 'abstained', 'unresolved']
    text: str | None = Field(default=None, max_length=1048576)
    usage: BrokerUsage = Field(default_factory=BrokerUsage)
    provider_id: str
    model_id: str
    request_sha256: str = Field(pattern=r'^[0-9a-f]{64}$')
    reason: str = Field(max_length=512)
    execution_verified: Literal[False] = False


class ShapeAdapter(Protocol):
    """Trusted SDK/shape port; implementations never select credentials or URL."""
    def encode(self, request: BrokerRequest, route: SelectedRoute) -> dict: ...
    def decode(self, body: dict, headers: Mapping[str, str], request: BrokerRequest,
               route: SelectedRoute) -> BrokerResult: ...


class TransportPort(Protocol):
    async def send(self, route: SelectedRoute, payload: dict, *, correlation_id: str,
                   root_run_id: str) -> tuple[dict, Mapping[str, str]]: ...


class GeneBinding(VersionedBinding):
    track: int = Field(ge=1, le=13)
    codon: str
    handler_id: str
    handler_version: str
    input_schema_sha256: str = Field(pattern=r'^[0-9a-f]{64}$')
    output_schema_sha256: str = Field(pattern=r'^[0-9a-f]{64}$')
    effects: tuple[str, ...]
    capabilities: tuple[str, ...]
    evidence_requirements: tuple[str, ...]

    @model_validator(mode='after')
    def contract_codon(self):
        if self.codon != CODONS[self.track-1]:
            raise ValueError('Gene track/codon must preserve diatonic-13-v1 profile')
        return self


class BoundStep(FrozenContract):
    gene_id: str
    gene_version: str
    gene_sha256: str
    handler_id: str
    handler_version: str
    input_schema_sha256: str
    output_schema_sha256: str
    effects: tuple[str, ...]
    evidence_requirements: tuple[str, ...]


class DerivedPlan(FrozenContract):
    protocol: Literal['diatonic-13-v1'] = PROTOCOL_ID
    adapter_version: Literal['genetic-derivation-v1'] = 'genetic-derivation-v1'
    request_sha256: str
    original_request_sha256: str
    flow_sha256: str
    prompt_sha256: str
    steps: tuple[BoundStep, ...]
    grants_authority: Literal[False] = False
    independent_verification_required: Literal[True] = True


def _text_only(request):
    if request.input_modalities != ('text',) or request.output_modality != 'text':
        raise ValueError('Shape adapter supports text only; use a registered modality adapter')


def _messages(request, route):
    messages = [m.model_dump() for m in request.messages]
    if route.prompt_template:
        messages.insert(0, {'role': 'system', 'content': route.prompt_template})
    return messages


def _usage(body, headers):
    data = body.get('usage') or {}
    if not isinstance(data, dict):
        return BrokerUsage()
    def nonnegative(value):
        return value if type(value) is int and value >= 0 else None
    input_tokens = nonnegative(data.get('input_tokens', data.get('prompt_tokens')))
    output_tokens = nonnegative(data.get('output_tokens', data.get('completion_tokens')))
    details = data.get('input_tokens_details', data.get('prompt_tokens_details'))
    cached = nonnegative(details.get('cached_tokens')) if isinstance(details, dict) else None
    if cached is not None and input_tokens is not None and cached > input_tokens:
        return BrokerUsage()
    # Only independently observed gateway headers establish response-cache replay.
    lower = {k.lower():v for k,v in headers.items()}
    cache = ('bifrost_direct' if lower.get('x-bifrost-cache-hit') == 'true' and
             lower.get('x-bifrost-cache-hit-type') == 'direct' else
             'provider_prefix' if cached is not None and cached > 0 else 'unknown')
    return BrokerUsage(input_tokens=input_tokens, output_tokens=output_tokens,
                       cached_tokens=cached, cache_state=cache)


def _result(request, route, body, headers, text, valid):
    expected = {route.model_id, route.wire_model}
    identity_ok = isinstance(body, dict) and body.get('model') in expected
    return BrokerResult(status='proposed' if valid and identity_ok else 'abstained',
        text=text if valid and identity_ok else None, usage=_usage(body, headers),
        provider_id=route.provider_id, model_id=route.model_id,
        request_sha256=request.digest,
        reason='completed inference proposal; independent task verification required' if valid and identity_ok
               else 'incomplete_refused_malformed_or_identity_mismatch')


class ChatShapeAdapter:
    """Registered OpenAI-compatible JSON shape usable through Bifrost providers.

    Capability evidence remains provider/model/endpoint-specific. This pure shape
    adapter adds no assumption that any particular provider supports this API.
    """
    def encode(self, request, route):
        _text_only(request)
        if route.api_shape != 'chat-completions-v1':
            raise ValueError('Registered API shape mismatch')
        return {'model': route.wire_model, 'messages': _messages(request, route),
                'max_completion_tokens': request.max_output_tokens, 'store': False,
                'stream': False}

    def decode(self, body, headers, request, route):
        _text_only(request)
        if not isinstance(body, dict):
            return _result(request, route, {}, headers, None, False)
        choices = body.get('choices')
        choice = choices[0] if isinstance(choices, list) and len(choices) == 1 else {}
        message = choice.get('message') or {} if isinstance(choice, dict) else {}
        text = message.get('content') if isinstance(message, dict) else None
        valid = (isinstance(choice, dict) and choice.get('finish_reason') == 'stop' and
                 isinstance(text, str) and bool(text) and not message.get('tool_calls') and
                 not message.get('refusal'))
        return _result(request, route, body, headers, text, valid)


class ResponsesShapeAdapter:
    """Stateless text Responses shape; encrypted/tool replay needs its own adapter."""
    def encode(self, request, route):
        _text_only(request)
        if route.api_shape != 'responses-v1':
            raise ValueError('Registered API shape mismatch')
        return {'model': route.wire_model, 'input': _messages(request, route),
                'max_output_tokens': request.max_output_tokens, 'store': False,
                'stream': False}

    def decode(self, body, headers, request, route):
        _text_only(request)
        if not isinstance(body, dict):
            return _result(request, route, {}, headers, None, False)
        outputs = body.get('output')
        pieces = []; valid = body.get('status') == 'completed' and isinstance(outputs, list)
        if isinstance(outputs, list):
            for output in outputs:
                if not isinstance(output, dict) or output.get('type') != 'message' or output.get('role') != 'assistant':
                    valid = False; continue
                content = output.get('content')
                if not isinstance(content, list):
                    valid = False; continue
                for block in content:
                    if isinstance(block, dict) and block.get('type') == 'output_text' and isinstance(block.get('text'), str):
                        pieces.append(block['text'])
                    else:
                        valid = False
        text = ''.join(pieces)
        return _result(request, route, body, headers, text, bool(text) and valid)
