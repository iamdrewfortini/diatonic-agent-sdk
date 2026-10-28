"""Provider-neutral Bifrost agents with compatible legacy Meta interfaces."""

from importlib import import_module

from .models import MODELS, Workload, route, forecast
from .ledger import Ledger

_PORTS = {
    "BrokerRequest": ("provider_contracts", "BrokerRequest"),
    "BrokerResult": ("provider_contracts", "BrokerResult"),
    "BindingRegistry": ("model_routing", "BindingRegistry"),
    "RouteSelector": ("model_routing", "RouteSelector"),
    "GenericGateway": ("generic_gateway", "GenericGateway"),
    "SDKPorts": ("generic_gateway", "SDKPorts"),
    "GeneticActivityFlow": ("flow_ports", "GeneticActivityFlow"),
    "OnePasswordBroker": ("secret_broker", "OnePasswordBroker"),
    "derive_package_plan": ("host_packaging", "derive_package_plan"),
}

# Keep transport/SDK/native integrations lazy; importing the public contract
# does not authenticate, resolve a key, execute a flow or select a provider.
def __getattr__(name):
    if name not in _PORTS:
        raise AttributeError(name)
    module, symbol = _PORTS[name]
    value = getattr(import_module("." + module, __name__), symbol)
    globals()[name] = value
    return value

__all__ = [*_PORTS, "MODELS", "Workload", "route", "forecast", "Ledger"]

