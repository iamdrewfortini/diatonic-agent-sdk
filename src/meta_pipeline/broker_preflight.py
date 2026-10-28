"""Side-effect-free broker configuration checks; never authentication or admission."""
from importlib import metadata

from .model_routing import RouteAbstention, RouteSelector
from .secret_broker import OnePasswordBroker, SecretBinding, SecretUnavailable, SystemdCredentialToken


def inspect_broker(*, gateway_config, broker_config, registry, request=None,
                   remaining_nusd=0, token_source=None):
    if type(remaining_nusd) is not int or remaining_nusd < 0:
        raise ValueError('nonnegative_forecast_budget_required')
    checks = {'runtime_enabled': broker_config.enabled}
    try:
        gateway_config.validate_origin()
        checks['gateway_origin_valid'] = True
    except ValueError:
        checks['gateway_origin_valid'] = False
    try:
        checks['official_sdk_version_available'] = metadata.version('onepassword-sdk') == '0.4.2'
    except metadata.PackageNotFoundError:
        checks['official_sdk_version_available'] = False
    source = token_source or SystemdCredentialToken(broker_config.bootstrap_credential_name)
    try:
        checks['bootstrap_metadata_available'] = source.available() is True
    except (OSError, SecretUnavailable):
        checks['bootstrap_metadata_available'] = False
    bindings = [SecretBinding(**row) for row in broker_config.secret_bindings]
    broker = OnePasswordBroker(bindings)
    workers = [b for b in bindings if b.purpose == 'gateway_virtual_key'
               and b.scope_verified and b.gateway_id == broker_config.gateway_id
               and b.tenant == broker_config.tenant]
    checks['scoped_worker_binding_configured'] = bool(workers)
    if request is not None:
        selection = RouteSelector(registry, gateway_id=broker_config.gateway_id,
                                  gateway_attempts=gateway_config.gateway_attempts).select(request, remaining_nusd)
        checks['request_has_eligible_route'] = not isinstance(selection, RouteAbstention)
        checks['selected_route_has_scoped_worker_binding'] = False
        if checks['request_has_eligible_route']:
            try:
                broker._worker_binding(selection.credential_binding_id, broker_config.gateway_id,
                                       broker_config.tenant)
                checks['selected_route_has_scoped_worker_binding'] = True
            except SecretUnavailable:
                pass
    blockers = [name for name, passed in checks.items() if not passed]
    return {'status': 'blocked' if blockers else 'configuration_ready_unverified',
            'checks': checks, 'blockers': blockers,
            'production_acceptance': 'unverified', 'spend_admission': False,
            'secret_values_read': False, 'sdk_authentication_attempted': False,
            'provider_requests_made': False, 'state_written': False}
