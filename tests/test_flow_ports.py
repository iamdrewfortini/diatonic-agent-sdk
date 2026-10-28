import hashlib

import pytest
from pydantic import BaseModel, ConfigDict

from meta_pipeline.audit import Audit
from meta_pipeline.execution import ContractBinding, ContractRegistry, FixturePolicy, LocalFixtureBackend, Verification
from meta_pipeline.flow_ports import GeneticActivityFlow
from meta_pipeline.protocol import CODONS, canonical
from meta_pipeline.provider_contracts import GeneBinding, BrokerMessage
from test_provider_contracts import request
from test_model_routing import registry


class Number(BaseModel):
    model_config = ConfigDict(extra="forbid",strict=True)
    value: int


@pytest.mark.asyncio
async def test_known_genes_execute_through_existing_admission_and_verifier(tmp_path):
    bindings = registry()
    schema = hashlib.sha256(canonical(Number.model_json_schema())).hexdigest()
    bindings.register(GeneBinding(id="inspect",version="1",source_sha256="a"*64,
        track=5,codon=CODONS[4],handler_id="inspect",handler_version="1",
        input_schema_sha256=schema,output_schema_sha256=schema,effects=(),
        capabilities=("classify",),evidence_requirements=()))
    calls = []
    def effect(data):
        calls.append(data.value)
        return Number(value=data.value+1)
    def verify(data,out):
        return Verification(verified=out.value==data.value+1,evidence_refs=["fixture:arithmetic"],reason="Independent exact fixture check")
    reg = ContractRegistry()
    reg.register(ContractBinding("inspect","proof_review","1",Number,Number,effect,verify,
        lambda original,data: original == "increment fixture"))
    audit = Audit(tmp_path/"audit")
    policy_ref = "artifact:"+"b"*64
    backend = LocalFixtureBackend(audit,reg,[FixturePolicy("root",policy_ref,frozenset({"inspect"}),100)])
    runtime = GeneticActivityFlow(bindings,backend,handler_id="flow",handler_version="1")
    req = request(original_request_sha256=hashlib.sha256(b"increment fixture").hexdigest())
    args=dict(original_request="increment fixture",inputs={"value":1},policy_ref=policy_ref,root_budget_nusd=100,event_id="fixture")
    out = await runtime.run(req,(("inspect","1"),),**args)
    assert out["status"] == "verified_in_declared_scope" and out["output"] == {"value":2}
    assert calls == [1]
    again = await runtime.run(req,(("inspect","1"),),**args)
    assert again["output"] == out["output"] and calls == [1]
    assert audit.verify()["valid"]
    with pytest.raises(ValueError,match="Original"):
        await runtime.run(req,(("inspect","1"),),**{**args,"original_request":"different"})
    with pytest.raises(ValueError,match="interpreter"):
        await GeneticActivityFlow(bindings,backend).run(req,(("inspect","1"),),**args)
    bindings.register(GeneBinding(id="inspect",version="2",source_sha256="a"*64,
        track=5,codon=CODONS[4],handler_id="inspect",handler_version="1",
        input_schema_sha256="f"*64,output_schema_sha256=schema,effects=(),
        capabilities=("classify",),evidence_requirements=()))
    with pytest.raises(ValueError,match="Gene"):
        await runtime.run(req,(("inspect","2"),),**args)
    assert calls == [1]
