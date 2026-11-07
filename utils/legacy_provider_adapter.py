"""Registered transition route for providers whose executor is still legacy.

The bridge gives every migrated provider a single dispatcher entry without
copying or changing workload internals. A missing route remains the only place
where the deployment engine may select its legacy fallback directly.
"""

from .provider_registry import WorkloadAdapter


MIGRATED_CAPABILITIES = {
    "aws": frozenset({
        "attack_box", "c2", "payload_server", "phishing", "redirector",
        "webrunner",
    }),
    "linode": frozenset({
        "attack_box", "c2", "payload_server", "phishing", "redirector",
        "webrunner",
    }),
    "flokinet": frozenset({
        "c2", "payload_server", "phishing", "redirector", "webrunner",
    }),
}


class LegacyProviderAdapter(WorkloadAdapter):
    """Explicit, one-call bridge used while a workload gains a native route."""

    def __init__(self, provider):
        if provider not in MIGRATED_CAPABILITIES:
            raise ValueError(f"Unsupported transition provider: {provider}")
        self.provider = provider

    def gather_config(self):
        # Import lazily so legacy-only commands do not load unrelated adapters.
        from .provider_registry import PROVIDER_SPECS, _load
        loader = PROVIDER_SPECS[self.provider].config_loader
        if not loader:
            raise ValueError(f"Configuration loader is missing for {self.provider}")
        return _load(loader)()

    def deploy(self, config):
        raise RuntimeError("Transition routes require the module's preserved executor")

    def deploy_with_legacy(self, config, legacy_deploy):
        self._validate(config)
        if not callable(legacy_deploy):
            raise TypeError("Legacy executor must be callable")
        # Exactly one call: an error or False result is never retried elsewhere.
        return legacy_deploy(config)

    def cleanup(self, config):
        from .cleanup_engine import execute_legacy_teardown
        return self.cleanup_with_legacy(config, execute_legacy_teardown)

    def cleanup_with_legacy(self, config, legacy_cleanup):
        self._validate(config, require_workload=False)
        if not callable(legacy_cleanup):
            raise TypeError("Legacy cleanup executor must be callable")
        # Preserve the caller's established cleanup behavior exactly once.
        return legacy_cleanup(config)

    def _validate(self, config, require_workload=True):
        providers = config.get("providers")
        if providers is not None:
            if not isinstance(providers, (list, tuple)) or self.provider not in providers:
                raise ValueError("Provider route is not part of composite deployment")
        elif config.get("provider") != self.provider:
            raise ValueError("Provider route does not match deployment provider")
        if require_workload:
            from .provider_registry import requested_workload
            workload = requested_workload(config)
            if workload not in MIGRATED_CAPABILITIES[self.provider]:
                raise ValueError(
                    f"Transition route does not support {self.provider}/{workload}")


def aws_adapter():
    return LegacyProviderAdapter("aws")


def linode_adapter():
    return LegacyProviderAdapter("linode")


def flokinet_adapter():
    return LegacyProviderAdapter("flokinet")
