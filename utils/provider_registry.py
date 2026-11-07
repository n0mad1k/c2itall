"""Provider metadata and opt-in infrastructure adapters.

Legacy providers keep their existing dispatch until a neutral infrastructure
adapter is implemented. Registration never implies support for every workload.
"""

from collections import namedtuple
from importlib import import_module
import os


class WorkloadAdapter:
    """Minimum lifecycle contract for a provider/workload implementation."""

    # Native handlers that create a durable, provider-owned recovery key set
    # this explicitly. Module controllers otherwise retain their established
    # legacy key generation behavior.
    manages_ssh_key = False

    def gather_config(self):
        raise NotImplementedError

    def deploy(self, config):
        raise NotImplementedError

    def cleanup(self, config):
        raise NotImplementedError

    def apply_profile(self, config, profile, value):
        """Apply an optional provider-specific workload tuning profile."""
        return config


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


class ProviderRuntime:
    """Optional controller runtime for provider-specific process execution."""

    def execute_playbook(self, playbook, config, output_filter):
        raise NotImplementedError

    def create_extra_vars(self, config):
        raise NotImplementedError


class ProviderSpec(namedtuple(
        '_ProviderSpec',
        'directory ssh_user legacy_menu config_loader routes runtime_loader '
        'environment_loader profile_loader credential_environment teardown_keys')):
    __slots__ = ()

    def __new__(cls, directory, ssh_user, legacy_menu=True, config_loader=None,
                routes=None, runtime_loader=None, environment_loader=None,
                profile_loader=None, credential_environment=None,
                teardown_keys=None):
        return super(ProviderSpec, cls).__new__(cls, directory, ssh_user, legacy_menu,
                                               config_loader, dict(routes or {}),
                                               runtime_loader,
                                               environment_loader,
                                               profile_loader,
                                               tuple(credential_environment or ()),
                                               tuple(teardown_keys or ()))

    @property
    def capabilities(self):
        return frozenset(self.routes)


_AWS_TRANSITION = 'utils.legacy_provider_adapter:aws_adapter'
_LINODE_TRANSITION = 'utils.legacy_provider_adapter:linode_adapter'
_FLOKINET_TRANSITION = 'utils.legacy_provider_adapter:flokinet_adapter'
LEGACY_TRANSITION_CAPABILITIES = {
    'aws': frozenset({
        'attack_box', 'c2', 'payload_server', 'phishing', 'redirector',
        'webrunner',
    }),
    'linode': frozenset({
        'attack_box', 'c2', 'payload_server', 'phishing', 'redirector',
        'webrunner',
    }),
    'flokinet': frozenset({
        'c2', 'payload_server', 'phishing', 'redirector', 'webrunner',
    }),
}
CANONICAL_WORKLOADS = (
    'infrastructure', 'attack_box', 'c2', 'redirector', 'phishing',
    'payload_server', 'webrunner', 'phantom', 'chat',
)
LEGACY_FALLBACK_WORKLOADS = frozenset({
    'attack_box', 'c2', 'redirector', 'phishing', 'payload_server',
    'webrunner', 'phantom', 'chat',
})
_TRANSITION_REFERENCES = frozenset({
    _AWS_TRANSITION, _LINODE_TRANSITION, _FLOKINET_TRANSITION,
})


PROVIDER_SPECS = {
    'aws': ProviderSpec('AWS', 'kali', config_loader='utils.aws_utils:gather_aws_config',
                        environment_loader='utils.aws_utils:prepare_aws_environment',
                        credential_environment=(
                            ('aws_access_key', 'AWS_ACCESS_KEY_ID'),
                            ('aws_secret_key', 'AWS_SECRET_ACCESS_KEY'),
                        ),
                        teardown_keys=(
                            'aws_access_key', 'aws_secret_key', 'aws_region'),
                        routes={workload: _AWS_TRANSITION for workload in
                                LEGACY_TRANSITION_CAPABILITIES['aws']}),
    'linode': ProviderSpec('Linode', 'root', config_loader='utils.linode_utils:gather_linode_config',
                           environment_loader='utils.linode_utils:prepare_linode_environment',
                           profile_loader='utils.linode_utils:apply_linode_profile',
                           credential_environment=(
                               ('linode_token', 'LINODE_TOKEN'),),
                           teardown_keys=('linode_token', 'linode_region'),
                           routes={workload: _LINODE_TRANSITION for workload in
                                   LEGACY_TRANSITION_CAPABILITIES['linode']}),
    'flokinet': ProviderSpec('FlokiNET', 'root', config_loader='utils.flokinet_utils:gather_flokinet_config',
                             environment_loader='utils.flokinet_utils:prepare_flokinet_environment',
                             credential_environment=(
                                 ('flokinet_api_key', 'FLOKINET_API_KEY'),),
                             routes={workload: _FLOKINET_TRANSITION for workload in
                                     LEGACY_TRANSITION_CAPABILITIES['flokinet']}),
    'azure': ProviderSpec('Azure', 'azureuser', False,
                          config_loader='utils.azure_utils:gather_azure_config',
                          runtime_loader='utils.azure_runtime:azure_runtime',
                          routes={
                              'infrastructure': 'utils.azure_adapter:AzureInfrastructureAdapter',
                              'attack_box': 'utils.azure_workload_adapter:azure_attack_box_adapter',
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
                config = route.gather_config()
                if not isinstance(config, dict):
                    raise TypeError(
                        f'Configuration route returned invalid data for '
                        f'{self.provider}/{capability}')
                manages_ssh_key = getattr(route, 'manages_ssh_key', False)
                if type(manages_ssh_key) is not bool:
                    raise TypeError('Adapter manages_ssh_key capability must be a boolean')
                if manages_ssh_key:
                    config = dict(config)
                    config['provider_manages_ssh_key'] = True
                return config
            if not (legacy_fallback and self.spec.legacy_menu):
                raise ValueError(f'No configuration route for {self.provider}/{capability}')
        if not self.spec.config_loader:
            raise ValueError(f'Configuration loader is missing for {self.provider}')
        return _load(self.spec.config_loader)()


def provider_dispatcher(provider):
    return ProviderDispatcher(provider) if provider in PROVIDER_SPECS else None


def provider_runtime(provider):
    """Load an optional provider-specific controller runtime lazily."""
    spec = PROVIDER_SPECS.get(provider)
    if spec is None or not spec.runtime_loader:
        return None
    runtime = _load(spec.runtime_loader)()
    if not isinstance(runtime, ProviderRuntime):
        raise TypeError(f'Invalid provider runtime for {provider}')
    return runtime


def prepare_provider_environment(config, teardown=False):
    """Delegate controller credential setup to provider-owned utility code."""
    spec = PROVIDER_SPECS.get(config.get('provider'))
    if spec is None or not spec.environment_loader:
        return None
    prepare = _load(spec.environment_loader)
    if not callable(prepare):
        raise TypeError('Provider environment loader must be callable')
    return prepare(config, teardown=teardown)


def apply_transition_profile(provider, config, workload, profile, value):
    """Apply optional provider-owned tuning for a preserved transition route."""
    spec = PROVIDER_SPECS.get(provider)
    if spec is None or not spec.profile_loader:
        return config
    apply_profile = _load(spec.profile_loader)
    if not callable(apply_profile):
        raise TypeError('Provider profile loader must be callable')
    result = apply_profile(config, workload, profile, value)
    if result is not config:
        raise TypeError('Provider profile loader must return the original config')
    return config


def provider_secret_vars(config):
    """Return only the active provider's controller credentials."""
    spec = PROVIDER_SPECS.get(config.get('provider'))
    if spec is None:
        return {}
    result = {}
    for item in spec.credential_environment:
        if (not isinstance(item, tuple) or len(item) != 2 or
                not all(isinstance(value, str) and value for value in item)):
            raise ValueError('Invalid provider credential environment mapping')
        config_key, environment_key = item
        value = os.environ.get(environment_key) or config.get(config_key)
        if value is not None and value != '':
            result[config_key] = value
    return result


def provider_credential_keys():
    """Return every registered provider credential key for isolation checks."""
    return frozenset(config_key
                     for spec in PROVIDER_SPECS.values()
                     for config_key, _ in spec.credential_environment)


def provider_teardown_vars(config):
    """Return the selected provider's preserved legacy cleanup inputs."""
    spec = PROVIDER_SPECS.get(config.get('provider'))
    if spec is None:
        return {}
    return {key: config[key] for key in spec.teardown_keys
            if config.get(key) is not None}


def providers_for(capability=None, legacy_fallback=False):
    """Return providers that can service a workload through a new or legacy route."""
    return [key for key, spec in PROVIDER_SPECS.items()
            if (spec.legacy_menu if capability is None else
                capability in spec.capabilities or
                (legacy_fallback and spec.legacy_menu))]


def provider_route_kind(provider, workload):
    """Classify the route actually available to one canonical workload."""
    if workload not in CANONICAL_WORKLOADS:
        raise ValueError('Unknown canonical workload: ' + str(workload))
    spec = PROVIDER_SPECS.get(provider)
    if spec is None:
        raise ValueError('Unknown provider: ' + str(provider))
    reference = spec.routes.get(workload)
    if reference in _TRANSITION_REFERENCES:
        return 'transition'
    if reference:
        return 'native'
    if workload in LEGACY_FALLBACK_WORKLOADS and spec.legacy_menu:
        return 'legacy_fallback'
    return 'unsupported'


def provider_support_matrix():
    """Return deterministic provider/workload coverage from dispatch metadata."""
    return [
        {'provider': provider, 'workload': workload,
         'route_kind': provider_route_kind(provider, workload)}
        for provider in PROVIDER_SPECS
        for workload in CANONICAL_WORKLOADS
    ]


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
