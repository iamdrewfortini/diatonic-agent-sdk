"""Deterministic provider-neutral binding selection, never Bifrost replacement.

Registrations are trusted coordinator configuration. Selection grants no spend or
native effect authority, does not retry, and cannot invent provider credentials.
"""
from __future__ import annotations
from datetime import datetime, timezone
import hashlib
from typing import Literal
from pydantic import Field
from .protocol import canonical
from .provider_contracts import (FrozenContract, VersionedBinding, ProviderBinding,
    ModelBinding, EndpointBinding, SDKBinding, PromptBinding, FlowBinding,
    PricingBinding, GeneBinding, BrokerRequest, BrokerUsage, BoundStep, DerivedPlan)

KINDS = {c.__name__: c for c in (ProviderBinding, ModelBinding, EndpointBinding,
    SDKBinding, PromptBinding, FlowBinding, PricingBinding, GeneBinding)}


class RouteAbstention(FrozenContract):
    status: Literal['abstained'] = 'abstained'
    reasons: tuple[str, ...]


class SelectedRoute(FrozenContract):
    contract_version: Literal['route-v1'] = 'route-v1'
    provider_id: str
    provider_version: str
    model_id: str
    model_binding_id: str
    model_version: str
    wire_model: str
    endpoint_id: str
    endpoint_version: str
    path: str
    api_shape: str
    sdk_id: str
    sdk_version: str
    sdk_handler_id: str
    sdk_handler_version: str
    flow_id: str
    flow_version: str
    flow_handler_id: str
    flow_handler_version: str
    prompt_id: str
    prompt_version: str
    prompt_sha256: str
    prompt_template: str
    credential_binding_id: str
    gateway_id: str
    pricing_id: str
    pricing_version: str
    reserve_nusd: int = Field(ge=0)
    gateway_attempts: int = Field(ge=1, le=10)
    request_sha256: str
    binding_sha256: str


class BindingRegistry:
    """Immutable versions and compare-and-swap activation; no generated handlers."""
    def __init__(self, *, approved_handlers):
        self._bindings = {}; self._active = {}
        self._handlers = frozenset(tuple(v) for v in approved_handlers)

    def register(self, binding: VersionedBinding):
        kind = type(binding).__name__
        if kind not in KINDS:
            raise ValueError('Unsupported binding kind')
        # model_copy/model_construct bypass Pydantic checks: validate trusted registrations too.
        binding = type(binding).model_validate(binding.model_dump())
        key = (kind, binding.id, binding.version)
        if key in self._bindings:
            raise ValueError('Duplicate immutable binding version')
        if isinstance(binding, (SDKBinding, FlowBinding, GeneBinding)):
            if (binding.handler_id, binding.handler_version) not in self._handlers:
                raise ValueError('Handler is not approved coordinator code')
        self._bindings[key] = binding
        self._active.setdefault((kind, binding.id), binding.version)
        return binding.digest

    def get(self, kind, id, version=None):
        name = kind if isinstance(kind, str) else kind.__name__
        v = version if version is not None else self._active.get((name, id))
        try:
            return self._bindings[(name, id, v)]
        except KeyError:
            raise ValueError('Unknown versioned binding') from None

    def active(self, kind):
        name = kind if isinstance(kind, str) else kind.__name__
        return tuple(self.get(name, id, v) for (k, id), v in sorted(self._active.items()) if k == name)

    def activate(self, kind, id, version, *, expected_version):
        name = kind if isinstance(kind, str) else kind.__name__
        self.get(name, id, version)
        key = (name, id)
        if self._active.get(key) != expected_version:
            raise ValueError('Stale binding activation')
        if version == expected_version:
            raise ValueError('Duplicate binding activation')
        self._active[key] = version

    def derive(self, request: BrokerRequest, genes: tuple[tuple[str, str], ...]):
        try:
            flow = self.get(FlowBinding, request.flow_id, request.flow_version)
            prompt = self.get(PromptBinding, request.prompt_id, request.prompt_version)
        except ValueError:
            return RouteAbstention(reasons=('unknown_flow_or_prompt_version',))
        if (self.get(FlowBinding, flow.id).version != flow.version or
                self.get(PromptBinding, prompt.id).version != prompt.version):
            return RouteAbstention(reasons=('stale_flow_or_prompt_version',))
        if not set(flow.capabilities + prompt.capabilities) <= set(request.capabilities):
            return RouteAbstention(reasons=('flow_or_prompt_capability_mismatch',))
        if not isinstance(genes, tuple) or not genes or len(genes) > flow.maximum_steps:
            return RouteAbstention(reasons=('bounded_nonempty_genome_required',))
        steps = []
        try:
            for id, version in genes:
                gene = self.get(GeneBinding, id, version)
                if id not in flow.allowed_gene_ids or not set(gene.capabilities) <= set(request.capabilities):
                    return RouteAbstention(reasons=('gene_not_allowed_for_flow_or_capabilities',))
                if steps and steps[-1].output_schema_sha256 != gene.input_schema_sha256:
                    return RouteAbstention(reasons=('incompatible_gene_schema',))
                steps.append(BoundStep(gene_id=id, gene_version=version, gene_sha256=gene.digest,
                    handler_id=gene.handler_id, handler_version=gene.handler_version,
                    input_schema_sha256=gene.input_schema_sha256,
                    output_schema_sha256=gene.output_schema_sha256, effects=gene.effects,
                    evidence_requirements=gene.evidence_requirements))
        except (ValueError, TypeError):
            return RouteAbstention(reasons=('unknown_or_unsupported_gene',))
        return DerivedPlan(request_sha256=request.digest,
            original_request_sha256=request.original_request_sha256,
            flow_sha256=flow.digest, prompt_sha256=prompt.digest, steps=tuple(steps))

    def price_usage(self, route: SelectedRoute, usage: BrokerUsage, *, now=None):
        """Price observed units against pinned verified rates; unknown stays unknown.

        This computes a charge estimate, never a provider invoice or retry proof.
        Direct response-cache replay may only be asserted by trusted gateway headers
        outside a model-controlled decoder; this method does not waive costs for it.
        """
        try:
            pricing = self.get(PricingBinding, route.pricing_id, route.pricing_version)
            if (not pricing.verified or pricing.provider_id != route.provider_id or
                    pricing.model_id != route.model_id):
                return None
            current = now or datetime.now(timezone.utc)
            if not isinstance(current, datetime) or current.tzinfo is None:
                return None
            if not datetime.fromisoformat(pricing.observed_at) <= current <= datetime.fromisoformat(pricing.valid_until):
                return None
            quantities = {u.unit: u.quantity for u in usage.units}
            for unit, value in (('input_tokens', usage.input_tokens), ('output_tokens', usage.output_tokens),
                                ('cached_input_tokens', usage.cached_tokens)):
                if value is not None:
                    if unit in quantities and quantities[unit] != value:
                        return None
                    quantities[unit] = value
            cached = quantities.get('cached_input_tokens')
            if cached is not None and 'input_tokens' in quantities:
                if cached > quantities['input_tokens']:
                    return None
                if any(r.unit == 'cached_input_tokens' for r in pricing.rates):
                    quantities['input_tokens'] -= cached
            if any(rate.unit not in quantities for rate in pricing.rates):
                return None
            return sum(quantities[rate.unit] * rate.nusd for rate in pricing.rates)
        except ValueError:
            return None


class RouteSelector:
    def __init__(self, registry: BindingRegistry, *, gateway_id: str, gateway_attempts=1,
                 now=None):
        if type(gateway_attempts) is not int or not 1 <= gateway_attempts <= 10:
            raise ValueError('Bounded gateway attempts required')
        self.registry = registry; self.gateway_id = gateway_id
        self.gateway_attempts = gateway_attempts
        self.now = now or (lambda: datetime.now(timezone.utc))

    def select(self, request: BrokerRequest, remaining_nusd: int):
        if type(remaining_nusd) is not int or remaining_nusd < 0:
            raise ValueError('Explicit local admission allowance required')
        r = self.registry; rejected = []; eligible = []
        try:
            flow = r.get(FlowBinding, request.flow_id, request.flow_version)
            prompt = r.get(PromptBinding, request.prompt_id, request.prompt_version)
        except ValueError:
            return RouteAbstention(reasons=('unknown_flow_or_prompt_version',))
        if (r.get(FlowBinding, flow.id).version != flow.version or
                r.get(PromptBinding, prompt.id).version != prompt.version):
            return RouteAbstention(reasons=('stale_flow_or_prompt_version',))
        if (not set(flow.capabilities) <= set(request.capabilities) or
                not set(prompt.capabilities) <= set(request.capabilities)):
            return RouteAbstention(reasons=('flow_or_prompt_capability_mismatch',))
        for model in r.active(ModelBinding):
            reason = self._model_reason(model, request)
            if reason:
                rejected.append(f'{model.id}:{reason}'); continue
            try:
                provider = r.get(ProviderBinding, model.provider_id)
            except ValueError:
                rejected.append(f'{model.id}:unknown_provider'); continue
            if not provider.enabled or provider.gateway_id != self.gateway_id:
                rejected.append(f'{model.id}:provider_not_enabled_on_gateway'); continue
            prices = [p for p in r.active(PricingBinding) if p.provider_id == provider.id and p.model_id == model.model_id]
            if len(prices) != 1:
                rejected.append(f'{model.id}:missing_or_ambiguous_pricing'); continue
            pricing = prices[0]; quantities = {u.unit: u.quantity for u in request.usage_bounds}
            current = self.now()
            if (not pricing.verified or not datetime.fromisoformat(pricing.observed_at) <= current <= datetime.fromisoformat(pricing.valid_until)):
                rejected.append(f'{model.id}:unverified_or_expired_pricing'); continue
            if any(p.unit not in quantities for p in pricing.rates):
                rejected.append(f'{model.id}:unbounded_pricing_unit'); continue
            reserve = sum(p.nusd * quantities[p.unit] for p in pricing.rates) * self.gateway_attempts
            if reserve > remaining_nusd:
                rejected.append(f'{model.id}:local_budget_exceeded'); continue
            for endpoint_id in model.endpoint_ids:
                try:
                    endpoint = r.get(EndpointBinding, endpoint_id)
                except ValueError:
                    rejected.append(f'{model.id}:unknown_endpoint'); continue
                if (not endpoint.verified or not endpoint.authentication_verified or
                        endpoint.provider_id != provider.id or endpoint.gateway_id != self.gateway_id):
                    rejected.append(f'{model.id}:endpoint_unverified_or_mismatched'); continue
                sdks = [s for s in r.active(SDKBinding) if s.id in flow.sdk_ids and
                        s.api_shape == endpoint.api_shape and s.verified]
                for sdk in sdks:
                    bindings = (provider, model, endpoint, sdk, flow, prompt, pricing)
                    sha = hashlib.sha256(canonical([b.digest for b in bindings])).hexdigest()
                    route = SelectedRoute(provider_id=provider.id, provider_version=provider.version,
                        model_id=model.model_id, model_binding_id=model.id, model_version=model.version,
                        wire_model=model.wire_model, endpoint_id=endpoint.id, endpoint_version=endpoint.version,
                        path=endpoint.path, api_shape=endpoint.api_shape, sdk_id=sdk.id, sdk_version=sdk.version,
                        sdk_handler_id=sdk.handler_id, sdk_handler_version=sdk.handler_version,
                        flow_id=flow.id, flow_version=flow.version, flow_handler_id=flow.handler_id,
                        flow_handler_version=flow.handler_version, prompt_id=prompt.id,
                        prompt_version=prompt.version, prompt_sha256=prompt.digest, prompt_template=prompt.template,
                        credential_binding_id=endpoint.credential_binding_id, gateway_id=self.gateway_id,
                        pricing_id=pricing.id, pricing_version=pricing.version, reserve_nusd=reserve,
                        gateway_attempts=self.gateway_attempts, request_sha256=request.digest, binding_sha256=sha)
                    eligible.append(route)
        if not eligible:
            return RouteAbstention(reasons=tuple(sorted(set(rejected))) or ('no_registered_compatible_binding',))
        return min(eligible, key=lambda route: (route.reserve_nusd, route.provider_id,
                    route.model_id, route.endpoint_id, route.sdk_id, route.binding_sha256))

    @staticmethod
    def _model_reason(model, request):
        if not model.entitlement_verified:
            return 'entitlement_unverified'
        if not set(request.capabilities) <= set(model.capabilities):
            return 'unsupported_capability'
        if not set(request.input_modalities) <= set(model.input_modalities) or request.output_modality not in model.output_modalities:
            return 'unsupported_modality'
        if request.data_class not in model.allowed_data_classes:
            return 'privacy_denied'
        if model.training_opt_in_required and not request.allow_training_opt_in:
            return 'training_opt_in_required'
        units = {u.unit:u.quantity for u in request.usage_bounds}
        if units.get('input_tokens', 0) + request.max_output_tokens > model.context_limit:
            return 'context_limit_exceeded'
        if not model.endpoint_ids:
            return 'no_model_endpoint_binding'
        return None

    def validate(self, request: BrokerRequest, route: SelectedRoute, remaining_nusd: int):
        """Revalidate pins immediately before effects; no silent provider fallback."""
        current = self.select(request, remaining_nusd)
        if not isinstance(current, SelectedRoute) or current != route:
            return RouteAbstention(reasons=('stale_or_changed_route_binding',))
        return route
