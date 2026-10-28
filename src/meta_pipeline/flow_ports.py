"""Derive known genetic handlers into the existing admitted Activity engine.

There is no code generation or new executor. Versioned genes select approved
handler/schema pairs. Existing authorization, native resource gates, budgets and
independent verification still decide every stage.
"""
import hashlib
import json
from .model_routing import RouteAbstention
from .protocol import canonical
from .scheduling import Activities, Plan, Stage, StageRequest, STAGES, definition_digest, execution_key


class GeneticActivityFlow:
    def __init__(self, bindings, backend, *, handler_id="genetic-activities", handler_version="1"):
        self.bindings, self.backend = bindings, backend
        self.handler_id, self.handler_version = handler_id, handler_version

    async def run(self, request, genes, *, original_request, inputs, policy_ref,
                  root_budget_nusd, event_id):
        if hashlib.sha256(original_request.encode()).hexdigest() != request.original_request_sha256:
            raise ValueError("Original request fidelity binding mismatch")
        from .provider_contracts import FlowBinding
        flow = self.bindings.get(FlowBinding, request.flow_id, request.flow_version)
        if (flow.handler_id, flow.handler_version) != (self.handler_id, self.handler_version):
            raise ValueError("Flow interpreter version not bound")
        derived = self.bindings.derive(request, genes)
        if isinstance(derived, RouteAbstention):
            return derived
        if len(derived.steps) > 16:
            raise ValueError("Activity workflow stage bound exceeded")
        stages = []; handlers = []
        for n, gene in enumerate(derived.steps):
            binding = self.backend.registry.binding(gene.handler_id)
            if (binding.handler_version != gene.handler_version
                    or hashlib.sha256(canonical(binding.input_model.model_json_schema())).hexdigest() != gene.input_schema_sha256
                    or hashlib.sha256(canonical(binding.output_model.model_json_schema())).hexdigest() != gene.output_schema_sha256
                    or tuple(binding.effects) != tuple(gene.effects)
                    or tuple(binding.requirements) != tuple(gene.evidence_requirements)):
                raise ValueError("Gene does not bind the registered handler/schema/evidence/effects")
            stages.append(Stage("gene" + str(n), binding.stage_kind,
                depends_on=["gene" + str(n-1)] if n else []))
            handlers.append(binding)
        plan = Plan(request.root_run_id, policy_ref, definition_digest(stages),
            "artifact:" + derived.digest, event_id, stages, root_budget_nusd, max_parallel=1)
        results = {}; current = inputs
        for n, (stage, binding) in enumerate(zip(stages, handlers)):
            group, model, role = STAGES[stage.kind]
            # Paid AI stage reservations require a separately derived trusted
            # reservation, not a zero-cost gene. Keep such stages unbound here.
            if group == "ai":
                raise ValueError("Paid gene requires independently admitted inference reservation")
            req = StageRequest(plan, stage, execution_key(plan, stage),
                {p: results[p].artifact_ref for p in stage.depends_on}, model, role)
            self.backend.derive(req, task=binding.task, original_request=original_request,
                inputs=current, correlation_id=request.correlation_id,
                causal_parents=tuple(results[p].artifact_ref for p in stage.depends_on))
            outcome = await getattr(Activities(self.backend), group)(req)
            results[stage.id] = outcome
            if not outcome.proven:
                return {"status": "needs_evidence", "derived_plan_sha256": derived.digest, "completed": results}
            record = next(r for r in self.backend.records() if r["key"] == req.key)
            current = json.loads(record["output"])
        return {"status": "verified_in_declared_scope", "derived_plan_sha256": derived.digest,
            "completed": results, "output": current, "native_activation": "pending"}
