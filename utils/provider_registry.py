"""Provider metadata and opt-in infrastructure adapters.

Legacy providers keep their existing dispatch until a neutral infrastructure
adapter is implemented. Registration never implies support for every workload.
"""

from collections import namedtuple
from importlib import import_module


class WorkloadAdapter:
    """Minimum lifecycle contract for a provider/workload implementation."""

    def gather_config(self):
        raise NotImplementedError

    def deploy(self, config):
        raise NotImplementedError

    def cleanup(self, config):
        raise NotImplementedError


class InfrastructureAdapter(WorkloadAdapter):
    """Recoverable infrastructure contract; importable by legacy controllers."""

    def validate_config(self, config, require_key=True):
        raise NotImplementedError

    def prepare_key(self, config):
        raise NotImplementedError

    def playbook(self, config):
        raise NotImplementedError

    def health(self, config):
        raise NotImplementedError

    def load_state(self, deployment_id):
        raise NotImplementedError

    def list_states(self):
        raise NotImplementedError


class ProviderSpec(namedtuple('_ProviderSpec', 'directory ssh_user legacy_menu config_loader routes')):
    __slots__ = ()

    def __new__(cls, directory, ssh_user, legacy_menu=True, config_loader=None, routes=None):
        return super(ProviderSpec, cls).__new__(cls, directory, ssh_user, legacy_menu,
                                               config_loader, dict(routes or {}))

    @property
    def capabilities(self):
        return frozenset(self.routes)


_AWS_TRANSITION = 'utils.legacy_provider_adapter:aws_adapter'
_LINODE_TRANSITION = 'utils.legacy_provider_adapter:linode_adapter'
_FLOKINET_TRANSITION = 'utils.legacy_provider_adapter:flokinet_adapter'


PROVIDER_SPECS = {
    'aws': ProviderSpec('AWS', 'kali', config_loader='utils.aws_utils:gather_aws_config',
                        routes={workload: _AWS_TRANSITION for workload in (
                            'attack_box', 'c2', 'payload_server', 'phishing',
                            'redirector', 'webrunner')}),
    'linode': ProviderSpec('Linode', 'root', config_loader='utils.linode_utils:gather_linode_config',
                           routes={workload: _LINODE_TRANSITION for workload in (
                               'attack_box', 'c2', 'payload_server', 'phishing',
                               'redirector', 'webrunner')}),
    'flokinet': ProviderSpec('FlokiNET', 'root', config_loader='utils.flokinet_utils:gather_flokinet_config',
                             routes={workload: _FLOKINET_TRANSITION for workload in (
                                 'c2', 'payload_server', 'phishing', 'redirector',
                                 'webrunner')}),
    'azure': ProviderSpec('Azure', 'azureuser', False,
                          config_loader='utils.azure_utils:gather_azure_config',
                          routes={
                              'infrastructure': 'utils.azure_adapter:AzureInfrastructureAdapter',
                              'phantom': 'utils.azure_phantom_adapter:AzurePhantomAdapter',
                              'chat': 'utils.azure_phantom_adapter:AzurePhantomAdapter',
                          }),
}


def _load(reference):
    module, name = reference.split(':', 1)
    return getattr(import_module(module), name)


class ProviderDispatcher:
    """The common entry point for every provider; legacy is a missing-route fallback."""

    def __init__(self, provider):
        self.provider = provider
        self.spec = PROVIDER_SPECS[provider]

    def route(self, workload):
        if workload not in self.spec.routes:
            return None
        reference = self.spec.routes[workload]
        if not reference:
            raise ValueError(f'Registered route is missing for {self.provider}/{workload}')
        return _load(reference)()

    def gather_config(self, capability=None, legacy_fallback=False):
        if capability is not None:
            route = self.route(capability)
            if route is not None:
                return route.gather_config()
            if not (legacy_fallback and self.spec.legacy_menu):
                raise ValueError(f'No configuration route for {self.provider}/{capability}')
        if not self.spec.config_loader:
            raise ValueError(f'Configuration loader is missing for {self.provider}')
        return _load(self.spec.config_loader)()


def provider_dispatcher(provider):
    return ProviderDispatcher(provider) if provider in PROVIDER_SPECS else None


def providers_for(capability=None, legacy_fallback=False):
    """Return providers that can service a workload through a new or legacy route."""
    return [key for key, spec in PROVIDER_SPECS.items()
            if (spec.legacy_menu if capability is None else
                capability in spec.capabilities or
                (legacy_fallback and spec.legacy_menu))]


def infrastructure_adapter(provider):
    dispatcher = provider_dispatcher(provider)
    return dispatcher.route('infrastructure') if dispatcher is not None else None


def workload_route(config):
    """Select a new route by workload, not merely by provider registration."""
    dispatcher = provider_dispatcher(config.get('provider'))
    if dispatcher is not None:
        return dispatcher.route(requested_workload(config))
    return None


def composite_workload_routes(config):
    """Resolve every provider participating in one composite workload."""
    providers = config.get('providers')
    if not isinstance(providers, (list, tuple)) or not providers:
        raise ValueError('Composite workload requires at least one provider')
    workload = requested_workload(config)
    routes = []
    seen = set()
    for provider in providers:
        if not isinstance(provider, str) or not provider or provider in seen:
            raise ValueError('Composite workload providers must be unique names')
        seen.add(provider)
        dispatcher = provider_dispatcher(provider)
        routes.append((provider, dispatcher.route(workload)
                       if dispatcher is not None else None))
    return routes


def requested_workload(config):
    """Recognize the existing selectors without changing legacy precedence."""
    if isinstance(config.get('provider_workload'), str) and config['provider_workload']:
        return config['provider_workload']
    if isinstance(config.get('deployment_type'), str) and config['deployment_type']:
        return config['deployment_type']
    for flag, workload in (
        ('attack_box_deployment', 'attack_box'), ('redirector_only', 'redirector'),
        ('tracker_deployment', 'tracker'), ('phishing_deployment', 'phishing'),
        ('chat_deployment', 'chat'),
    ):
        if config.get(flag):
            return workload
    # The original shared engine's final/default route is c2. Keeping that
    # name here does not implement a new handler or alter its legacy execution.
    return 'c2'


def uses_legacy_routes(provider):
    spec = PROVIDER_SPECS.get(provider)
    # Preserve legacy handling of previously accepted, unregistered providers.
    return spec is None or spec.legacy_menu


def list_infrastructure_states():
    states = []
    for provider in providers_for('infrastructure'):
        for state in infrastructure_adapter(provider).list_states():
            if state.get('provider') != provider:
                raise ValueError('Recovery state does not match its provider adapter')
            states.append(state)
    return states


def load_infrastructure_state(deployment_id):
    matches = []
    for provider in providers_for('infrastructure'):
        state = infrastructure_adapter(provider).load_state(deployment_id)
        if state is not None:
            if state.get('provider') != provider:
                raise ValueError('Recovery state does not match its provider adapter')
            matches.append(state)
    if len(matches) > 1:
        raise ValueError('Deployment ID exists in multiple providers; select a specific deployment')
    return matches[0] if matches else None


def infrastructure_health():
    """Read actual provider state; never treat an unavailable check as healthy."""
    reports = []
    for state in list_infrastructure_states():
        identity = {'provider': state['provider'], 'deployment_id': state['deployment_id']}
        try:
            result = infrastructure_adapter(state['provider']).health(state)
            if not isinstance(result, dict) or type(result.get('healthy')) is not bool:
                raise ValueError('Provider returned an invalid health result')
            reports.append(dict(result, **identity))
        except NotImplementedError:
            reports.append(dict(identity, healthy=False, detail='Health check is not implemented'))
        except Exception as error:
            reports.append(dict(identity, healthy=False, detail=str(error)))
    return reports
