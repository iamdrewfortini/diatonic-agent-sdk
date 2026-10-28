import meta_pipeline
from meta_pipeline.generic_gateway import GenericGateway
from meta_pipeline.model_routing import BindingRegistry, RouteSelector
from meta_pipeline.models import MODELS, Workload
from meta_pipeline.provider_contracts import BrokerRequest


def test_primary_provider_neutral_ports_and_legacy_identity_are_public():
    assert meta_pipeline.GenericGateway is GenericGateway
    assert meta_pipeline.BindingRegistry is BindingRegistry
    assert meta_pipeline.RouteSelector is RouteSelector
    assert meta_pipeline.BrokerRequest is BrokerRequest
    assert meta_pipeline.MODELS is MODELS and meta_pipeline.Workload is Workload
    assert "Provider-neutral" in meta_pipeline.__doc__
