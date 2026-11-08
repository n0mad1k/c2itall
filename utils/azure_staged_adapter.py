"""Fail-closed Azure preparation for workloads that are not activated yet.

These adapters deliberately live outside ``ProviderSpec.routes``. They provide
the shared Azure configuration and cleanup boundary without advertising or
executing a workload deployment.
"""

from .azure_workload_adapter import AzureSingleVmWorkloadAdapter


STAGED_AZURE_WORKLOADS = frozenset({'phishing', 'webrunner'})


class AzureStagedWorkloadAdapter(AzureSingleVmWorkloadAdapter):
    """Prepared Azure lifecycle that cannot provision a service."""

    deployment_enabled = False
    address_key = 'target_host'
    playbook_name = None
    service_config_keys = ()

    activation_requirements = (
        'provider-owned service playbook',
        'least-privilege inbound rule contract',
        'remote service health verification',
        'repeat-deployment and teardown live evidence',
    )

    def __init__(self, workload):
        if workload not in STAGED_AZURE_WORKLOADS:
            raise ValueError('Unknown staged Azure workload: ' + str(workload))
        self.workload = workload
        self.service_log_suffix = workload.replace('_', '-')

    @property
    def readiness(self):
        return {
            'provider': 'azure',
            'workload': self.workload,
            'deployment_enabled': False,
            'configuration_ready': True,
            'cleanup_ready': True,
            'activation_requirements': self.activation_requirements,
        }

    def deploy(self, config):
        raise RuntimeError(
            'Azure staged route is disabled: ' + self.workload)

    def _validate_workload(self, config):
        raise RuntimeError(
            'Azure staged route is disabled: ' + self.workload)


def azure_phishing_staged_adapter():
    return AzureStagedWorkloadAdapter('phishing')


def azure_webrunner_staged_adapter():
    return AzureStagedWorkloadAdapter('webrunner')
