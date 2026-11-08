"""Provider metadata and opt-in infrastructure adapters.

Legacy providers keep their existing dispatch until a neutral infrastructure
adapter is implemented. Registration never implies support for every workload.
"""

from collections import namedtuple
from importlib import import_module
import os
from pathlib import Path


class WorkloadAdapter:
    """Minimum lifecycle contract for a provider/workload implementation."""

    # Staged adapters set this false and remain outside active dispatch. The
    # registry validates them without making them selectable or executable.
    deployment_enabled = True

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


class WorkloadSpec(namedtuple(
        '_WorkloadSpec', 'entrypoint legacy_fallback variants')):
    """Canonical controller ownership and preserved fallback policy."""

    __slots__ = ()

    def __new__(cls, entrypoint, legacy_fallback, variants=None):
        return super(WorkloadSpec, cls).__new__(
            cls, entrypoint, legacy_fallback, frozenset(variants or ()))


class ProviderSpec(namedtuple(
        '_ProviderSpec',
        'directory ssh_user legacy_menu legacy_capabilities variant_support '
        'config_loader routes staged_routes runtime_loader '
        'environment_loader profile_loader credential_environment teardown_keys '
        'cleanup_automated cleanup_guidance')):
    __slots__ = ()

    def __new__(cls, directory, ssh_user, legacy_menu=True,
                legacy_capabilities=None, variant_support=None,
                config_loader=None, routes=None, staged_routes=None,
                runtime_loader=None,
                environment_loader=None, profile_loader=None,
                credential_environment=None, teardown_keys=None,
                cleanup_automated=True,
                cleanup_guidance=None):
        normalized_variants = {
            workload: frozenset(variants)
            for workload, variants in dict(variant_support or {}).items()
        }
        return super(ProviderSpec, cls).__new__(cls, directory, ssh_user, legacy_menu,
                                               frozenset(legacy_capabilities or ()),
                                               normalized_variants,
                                               config_loader, dict(routes or {}),
                                               dict(staged_routes or {}),
                                               runtime_loader,
                                               environment_loader,
                                               profile_loader,
                                               tuple(credential_environment or ()),
                                               tuple(teardown_keys or ()),
                                               cleanup_automated,
                                               tuple(cleanup_guidance or ()))

    @property
    def capabilities(self):
        return frozenset(self.routes)

    @property
    def staged_capabilities(self):
        return frozenset(self.staged_routes)


_AWS_TRANSITION = 'utils.legacy_provider_adapter:aws_adapter'
_LINODE_TRANSITION = 'utils.legacy_provider_adapter:linode_adapter'
_FLOKINET_TRANSITION = 'utils.legacy_provider_adapter:flokinet_adapter'
LEGACY_TRANSITION_CAPABILITIES = {
    'aws': frozenset({
        'attack_box', 'c2', 'chat', 'payload_server', 'phishing', 'phantom',
        'redirector', 'webrunner',
    }),
    'linode': frozenset({
        'attack_box', 'c2', 'chat', 'payload_server', 'phishing', 'phantom',
        'redirector', 'webrunner',
    }),
    'flokinet': frozenset({
        'c2', 'chat', 'payload_server', 'phishing', 'phantom', 'redirector',
        'webrunner',
    }),
}
WORKLOAD_SPECS = {
    'infrastructure': WorkloadSpec(
        'modules/infrastructure/deploy_infrastructure.py', False),
    'attack_box': WorkloadSpec(
        'modules/attack-box/deploy_attack_box.py', True,
        {'quick_recon', 'kali', 'ubuntu', 'parrot'}),
    'c2': WorkloadSpec('modules/c2/deploy_c2.py', True),
    'redirector': WorkloadSpec(
        'modules/redirectors/deploy_redirector.py', True),
    'phishing': WorkloadSpec(
        'modules/phishing/deploy_phishing.py', True),
    'payload_server': WorkloadSpec(
        'modules/payload-server/deploy_payload.py', True),
    'webrunner': WorkloadSpec(
        'modules/webrunner/deploy_webrunner.py', True),
    'phantom': WorkloadSpec('ghost_protocol/phantom/phantom.py', True),
    'chat': WorkloadSpec('modules/chat-server/deploy_chat.py', True),
}
CANONICAL_WORKLOADS = tuple(WORKLOAD_SPECS)
LEGACY_FALLBACK_WORKLOADS = frozenset(
    workload for workload, spec in WORKLOAD_SPECS.items()
    if spec.legacy_fallback)
_TRANSITION_REFERENCES = frozenset({
    _AWS_TRANSITION, _LINODE_TRANSITION, _FLOKINET_TRANSITION,
})


PROVIDER_SPECS = {
    'aws': ProviderSpec('AWS', 'kali', config_loader='utils.aws_utils:gather_aws_config',
                        legacy_capabilities=(
                            LEGACY_TRANSITION_CAPABILITIES['aws'] |
                            frozenset({'phantom', 'chat'})),
                        environment_loader='utils.aws_utils:prepare_aws_environment',
                        profile_loader='utils.aws_utils:apply_aws_profile',
                        credential_environment=(
                            ('aws_access_key', 'AWS_ACCESS_KEY_ID'),
                            ('aws_secret_key', 'AWS_SECRET_ACCESS_KEY'),
                        ),
                        teardown_keys=(
                            'aws_access_key', 'aws_secret_key', 'aws_region'),
                        cleanup_guidance=(
                            'Open the AWS EC2 Console',
                            'Check instances with tags containing: {deployment_id}',
                            'Delete instances and associated resources',
                            'Check security groups, key pairs and elastic IPs',
                        ),
                        routes={workload: _AWS_TRANSITION for workload in
                                LEGACY_TRANSITION_CAPABILITIES['aws']}),
    'linode': ProviderSpec('Linode', 'root', config_loader='utils.linode_utils:gather_linode_config',
                           legacy_capabilities=(
                               LEGACY_TRANSITION_CAPABILITIES['linode'] |
                               frozenset({'phantom', 'chat'})),
                           environment_loader='utils.linode_utils:prepare_linode_environment',
                           profile_loader='utils.linode_utils:apply_linode_profile',
                           credential_environment=(
                               ('linode_token', 'LINODE_TOKEN'),),
                           teardown_keys=('linode_token', 'linode_region'),
                           cleanup_guidance=(
                               'Open the Linode Cloud Manager: https://cloud.linode.com/',
                               'Check Linodes with labels containing: {deployment_id}',
                               'Delete matching Linodes and NodeBalancers',
                               'Check and delete matching firewalls',
                           ),
                           routes={workload: _LINODE_TRANSITION for workload in
                                   LEGACY_TRANSITION_CAPABILITIES['linode']}),
    'flokinet': ProviderSpec('FlokiNET', 'root', config_loader='utils.flokinet_utils:gather_flokinet_config',
                             legacy_capabilities=(
                                 LEGACY_TRANSITION_CAPABILITIES['flokinet'] |
                                 frozenset({'phantom', 'chat'})),
                             environment_loader='utils.flokinet_utils:prepare_flokinet_environment',
                             credential_environment=(
                                 ('flokinet_api_key', 'FLOKINET_API_KEY'),),
                             cleanup_automated=False,
                             cleanup_guidance=(
                                 'Open the FlokiNET control panel',
                                 'Check for servers containing: {deployment_id}',
                                 'Delete any matching resources',
                             ),
                             routes={workload: _FLOKINET_TRANSITION for workload in
                                     LEGACY_TRANSITION_CAPABILITIES['flokinet']}),
    'azure': ProviderSpec('Azure', 'azureuser', False,
                          variant_support={'attack_box': {'quick_recon'}},
                          config_loader='utils.azure_utils:gather_azure_config',
                          runtime_loader='utils.azure_runtime:azure_runtime',
                          routes={
                              'infrastructure': 'utils.azure_adapter:AzureInfrastructureAdapter',
                              'attack_box': 'utils.azure_workload_adapter:azure_attack_box_adapter',
                              'redirector': 'utils.azure_workload_adapter:azure_redirector_adapter',
                              'phantom': 'utils.azure_phantom_adapter:AzurePhantomAdapter',
                              'chat': 'utils.azure_phantom_adapter:AzurePhantomAdapter',
                          },
                          staged_routes={
                              workload: 'utils.azure_staged_adapter:azure_{0}_staged_adapter'.format(
                                  workload)
                              for workload in (
                                  'c2', 'phishing', 'payload_server', 'webrunner')
                          }),
}


def _load(reference):
    module, name = _reference_parts(reference)
    return getattr(import_module(module), name)


def _reference_parts(reference):
    if not isinstance(reference, str) or reference.count(':') != 1:
        raise ValueError('Provider import reference must use module:name')
    module, name = reference.split(':', 1)
    if not module or not name or module.strip() != module or name.strip() != name:
        raise ValueError('Provider import reference must use module:name')
    return module, name


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

    def staged_route(self, workload):
        """Load inert provider preparation without entering active dispatch."""
        if workload not in self.spec.staged_routes:
            return None
        reference = self.spec.staged_routes[workload]
        if not reference:
            raise ValueError(
                f'Registered staged route is missing for '
                f'{self.provider}/{workload}')
        return _load(reference)()

    def gather_config(self, capability=None, legacy_fallback=False,
                      variant=None):
        if capability is not None:
            if not provider_supports_variant(
                    self.provider, capability, variant):
                raise ValueError(
                    'No configuration route for {0}/{1} variant {2}'.format(
                        self.provider, capability, variant))
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
            if not (legacy_fallback and
                    capability in self.spec.legacy_capabilities):
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


def provider_cleanup_guidance(provider, deployment_id):
    """Render provider-owned recovery hints for an incomplete legacy cleanup."""
    spec = PROVIDER_SPECS.get(provider)
    if spec is None:
        return ()
    return tuple(
        item.format(deployment_id=deployment_id)
        for item in spec.cleanup_guidance
    )


def provider_cleanup_is_automated(provider):
    """Report whether legacy cleanup can prove provider-side deletion."""
    spec = PROVIDER_SPECS.get(provider)
    return bool(spec and spec.cleanup_automated)


def providers_for(capability=None, legacy_fallback=False, variant=None):
    """Return providers that can service a workload through a new or legacy route."""
    return [key for key, spec in PROVIDER_SPECS.items()
            if (spec.legacy_menu if capability is None else
                capability in spec.capabilities or
                (legacy_fallback and capability in spec.legacy_capabilities))
            and provider_supports_variant(key, capability, variant)]


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
    if (workload in LEGACY_FALLBACK_WORKLOADS and
            workload in spec.legacy_capabilities):
        return 'legacy_fallback'
    if spec.staged_routes.get(workload):
        return 'staged'
    return 'unsupported'


def provider_supported_variants(provider, workload):
    """Return the declared workload variants a provider can actually service."""
    if workload not in CANONICAL_WORKLOADS:
        raise ValueError('Unknown canonical workload: ' + str(workload))
    if provider not in PROVIDER_SPECS:
        raise ValueError('Unknown provider: ' + str(provider))
    variants = WORKLOAD_SPECS[workload].variants
    if (not variants or provider_route_kind(provider, workload) not in
            ('native', 'transition', 'legacy_fallback')):
        return frozenset()
    return PROVIDER_SPECS[provider].variant_support.get(workload, variants)


def provider_supports_variant(provider, workload, variant=None):
    """Check an optional workload subtype before configuration or provisioning."""
    if variant is None or workload is None:
        return True
    if workload not in CANONICAL_WORKLOADS:
        raise ValueError('Unknown canonical workload: ' + str(workload))
    variants = WORKLOAD_SPECS[workload].variants
    if not variants:
        raise ValueError('Workload does not define variants: ' + workload)
    if variant not in variants:
        raise ValueError(
            'Unknown workload variant: {0}/{1}'.format(workload, variant))
    return variant in provider_supported_variants(provider, workload)


def provider_support_matrix():
    """Return deterministic provider/workload coverage from dispatch metadata."""
    rows = []
    for provider in PROVIDER_SPECS:
        for workload in CANONICAL_WORKLOADS:
            variants = WORKLOAD_SPECS[workload].variants
            supported = provider_supported_variants(provider, workload)
            if not variants:
                coverage = 'not_applicable'
            elif supported == variants:
                coverage = 'full'
            elif supported:
                coverage = 'partial'
            else:
                coverage = 'none'
            rows.append({
                'provider': provider,
                'workload': workload,
                'route_kind': provider_route_kind(provider, workload),
                'variants': sorted(variants),
                'supported_variants': sorted(supported),
                'missing_variants': sorted(variants - supported),
                'variant_coverage': coverage,
            })
    return rows


def validate_provider_registry(load_references=True):
    """Validate every provider/workload route without invoking a deployment."""
    if type(load_references) is not bool:
        raise TypeError('load_references must be a boolean')
    if not PROVIDER_SPECS:
        raise ValueError('Provider registry is empty')
    if not CANONICAL_WORKLOADS or len(set(CANONICAL_WORKLOADS)) != len(CANONICAL_WORKLOADS):
        raise ValueError('Canonical workloads must be nonempty and unique')
    if tuple(WORKLOAD_SPECS) != CANONICAL_WORKLOADS:
        raise ValueError('Canonical workload catalog drift')
    if LEGACY_FALLBACK_WORKLOADS != frozenset(
            workload for workload, spec in WORKLOAD_SPECS.items()
            if spec.legacy_fallback):
        raise ValueError('Legacy fallback workload catalog drift')

    project_root = Path(__file__).resolve().parents[1]
    entrypoints = set()
    expected_module_controllers = set()
    for workload, spec in WORKLOAD_SPECS.items():
        if not isinstance(spec, WorkloadSpec):
            raise TypeError('Invalid workload specification: ' + workload)
        if type(spec.legacy_fallback) is not bool:
            raise TypeError('Workload legacy_fallback must be a boolean: ' + workload)
        if (not isinstance(spec.variants, frozenset) or
                any(not isinstance(variant, str) or not variant or
                    variant.strip() != variant
                    for variant in spec.variants)):
            raise ValueError('Invalid workload variants: ' + workload)
        if (not isinstance(spec.entrypoint, str) or not spec.entrypoint or
                Path(spec.entrypoint).is_absolute() or '..' in Path(spec.entrypoint).parts):
            raise ValueError('Invalid workload controller entrypoint: ' + workload)
        if spec.entrypoint in entrypoints:
            raise ValueError('Duplicate workload controller entrypoint: ' + workload)
        entrypoints.add(spec.entrypoint)
        if not (project_root / spec.entrypoint).is_file():
            raise ValueError('Workload controller is missing: {0}/{1}'.format(
                workload, spec.entrypoint))
        if spec.entrypoint.startswith('modules/'):
            expected_module_controllers.add(spec.entrypoint)

    discovered_module_controllers = set()
    for controller in (project_root / 'modules').glob('*/deploy_*.py'):
        source = controller.read_text()
        if 'gather_provider_config(' in source:
            discovered_module_controllers.add(
                str(controller.relative_to(project_root)))
    if discovered_module_controllers != expected_module_controllers:
        missing = sorted(discovered_module_controllers - expected_module_controllers)
        stale = sorted(expected_module_controllers - discovered_module_controllers)
        raise ValueError('Provider workload controller catalog drift; missing={0}, stale={1}'.format(
            missing, stale))

    credential_keys = set()
    environment_keys = set()
    reference_fields = (
        'config_loader', 'runtime_loader', 'environment_loader',
        'profile_loader',
    )
    for provider, spec in PROVIDER_SPECS.items():
        if (not isinstance(provider, str) or not provider or
                provider.lower() != provider or provider.strip() != provider):
            raise ValueError('Provider keys must be lowercase names')
        if not isinstance(spec, ProviderSpec):
            raise TypeError('Invalid provider specification: ' + provider)
        if (not isinstance(spec.directory, str) or not spec.directory or
                not isinstance(spec.ssh_user, str) or not spec.ssh_user):
            raise ValueError('Provider directory and SSH user are required: ' + provider)
        if type(spec.legacy_menu) is not bool:
            raise TypeError('Provider legacy_menu must be a boolean: ' + provider)
        if (any(workload not in CANONICAL_WORKLOADS
                for workload in spec.legacy_capabilities) or
                (spec.legacy_capabilities and not spec.legacy_menu)):
            raise ValueError('Invalid provider legacy capabilities: ' + provider)
        if not isinstance(spec.variant_support, dict):
            raise ValueError('Invalid provider variant support: ' + provider)
        for workload, variants in spec.variant_support.items():
            if workload not in CANONICAL_WORKLOADS:
                raise ValueError(
                    'Unknown provider variant workload: {0}/{1}'.format(
                        provider, workload))
            declared = WORKLOAD_SPECS[workload].variants
            if (not isinstance(variants, frozenset) or not variants or
                    not variants.issubset(declared) or
                    (workload not in spec.routes and
                     workload not in spec.legacy_capabilities)):
                raise ValueError(
                    'Invalid provider variant support: {0}/{1}'.format(
                        provider, workload))

        for field in reference_fields:
            reference = getattr(spec, field)
            if reference is None:
                continue
            _reference_parts(reference)
            if load_references and not callable(_load(reference)):
                raise TypeError('Provider loader is not callable: {0}/{1}'.format(
                    provider, field))

        if set(spec.routes) & set(spec.staged_routes):
            raise ValueError('Active and staged provider routes overlap: ' + provider)

        for workload, reference in spec.routes.items():
            if workload not in CANONICAL_WORKLOADS:
                raise ValueError('Unknown provider route workload: {0}/{1}'.format(
                    provider, workload))
            _reference_parts(reference)
            if load_references:
                factory = _load(reference)
                if not callable(factory):
                    raise TypeError('Provider route factory is not callable: {0}/{1}'.format(
                        provider, workload))
                adapter = factory()
                if not isinstance(adapter, WorkloadAdapter):
                    raise TypeError('Provider route returned an invalid adapter: {0}/{1}'.format(
                        provider, workload))
                if type(adapter.deployment_enabled) is not bool or not adapter.deployment_enabled:
                    raise TypeError(
                        'Active provider route is disabled: {0}/{1}'.format(
                            provider, workload))

        for workload, reference in spec.staged_routes.items():
            if workload not in CANONICAL_WORKLOADS:
                raise ValueError(
                    'Unknown staged provider workload: {0}/{1}'.format(
                        provider, workload))
            _reference_parts(reference)
            if load_references:
                factory = _load(reference)
                if not callable(factory):
                    raise TypeError(
                        'Staged provider route factory is not callable: '
                        '{0}/{1}'.format(provider, workload))
                adapter = factory()
                if not isinstance(adapter, WorkloadAdapter):
                    raise TypeError(
                        'Staged provider route returned an invalid adapter: '
                        '{0}/{1}'.format(provider, workload))
                if (type(adapter.deployment_enabled) is not bool or
                        adapter.deployment_enabled):
                    raise TypeError(
                        'Staged provider route must be disabled: '
                        '{0}/{1}'.format(provider, workload))

        local_config_keys = set()
        local_environment_keys = set()
        for item in spec.credential_environment:
            if (not isinstance(item, tuple) or len(item) != 2 or
                    not all(isinstance(value, str) and value for value in item)):
                raise ValueError('Invalid provider credential mapping: ' + provider)
            config_key, environment_key = item
            if config_key in local_config_keys or environment_key in local_environment_keys:
                raise ValueError('Duplicate provider credential mapping: ' + provider)
            local_config_keys.add(config_key)
            local_environment_keys.add(environment_key)
            if config_key in credential_keys or environment_key in environment_keys:
                raise ValueError('Provider credential mapping is not isolated: ' + provider)
            credential_keys.add(config_key)
            environment_keys.add(environment_key)

        if (any(not isinstance(key, str) or not key for key in spec.teardown_keys) or
                len(set(spec.teardown_keys)) != len(spec.teardown_keys)):
            raise ValueError('Invalid provider teardown keys: ' + provider)
        if type(spec.cleanup_automated) is not bool:
            raise TypeError('Provider cleanup_automated must be a boolean: ' + provider)
        for guidance in spec.cleanup_guidance:
            if not isinstance(guidance, str) or not guidance:
                raise ValueError('Invalid provider cleanup guidance: ' + provider)
            try:
                guidance.format(deployment_id='validation')
            except (KeyError, IndexError, ValueError) as exc:
                raise ValueError(
                    'Invalid provider cleanup guidance template: ' + provider) from exc

    for provider, workloads in LEGACY_TRANSITION_CAPABILITIES.items():
        if provider not in PROVIDER_SPECS:
            raise ValueError('Transition provider is not registered: ' + provider)
        if not workloads or not workloads.issubset(LEGACY_FALLBACK_WORKLOADS):
            raise ValueError('Invalid transition capability set: ' + provider)
        if not workloads.issubset(PROVIDER_SPECS[provider].legacy_capabilities):
            raise ValueError('Transition capabilities are not legacy-enabled: ' + provider)
        for workload in workloads:
            if provider_route_kind(provider, workload) != 'transition':
                raise ValueError('Transition route metadata drift: {0}/{1}'.format(
                    provider, workload))

    counts = {kind: 0 for kind in (
        'native', 'transition', 'legacy_fallback', 'staged', 'unsupported')}
    rows = provider_support_matrix()
    for row in rows:
        provider = row['provider']
        workload = row['workload']
        route_kind = row['route_kind']
        counts[route_kind] += 1
        available = provider in providers_for(
            workload, legacy_fallback=workload in LEGACY_FALLBACK_WORKLOADS)
        if available != (route_kind in (
                'native', 'transition', 'legacy_fallback')):
            raise ValueError('Provider selection disagrees with coverage: {0}/{1}'.format(
                provider, workload))
        route = PROVIDER_SPECS[provider].routes.get(workload)
        if (route_kind in ('native', 'transition')) != bool(route):
            raise ValueError('Provider route classification drift: {0}/{1}'.format(
                provider, workload))
        staged_route = PROVIDER_SPECS[provider].staged_routes.get(workload)
        if (route_kind == 'staged') != bool(staged_route):
            raise ValueError(
                'Provider staged route classification drift: {0}/{1}'.format(
                    provider, workload))
        for variant in row['variants']:
            available = provider in providers_for(
                workload,
                legacy_fallback=workload in LEGACY_FALLBACK_WORKLOADS,
                variant=variant)
            supported = variant in row['supported_variants']
            if available != supported:
                raise ValueError(
                    'Provider variant selection disagrees with coverage: '
                    '{0}/{1}/{2}'.format(provider, workload, variant))

    return {
        'providers': len(PROVIDER_SPECS),
        'workloads': len(CANONICAL_WORKLOADS),
        'controllers': len(entrypoints),
        'pairs': len(rows),
        'routes': sum(len(spec.routes) for spec in PROVIDER_SPECS.values()),
        'staged_routes': sum(
            len(spec.staged_routes) for spec in PROVIDER_SPECS.values()),
        'counts': counts,
    }


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


def uses_legacy_routes(provider, workload=None):
    spec = PROVIDER_SPECS.get(provider)
    # Preserve legacy handling of previously accepted, unregistered providers.
    if spec is None:
        return True
    if workload is None or workload not in CANONICAL_WORKLOADS:
        return spec.legacy_menu
    return workload in spec.legacy_capabilities


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
