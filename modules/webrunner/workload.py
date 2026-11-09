"""WEBRUNNER node profile: scan nodes any VM provider can supply.

Every provider provisions its nodes through the recoverable single-VM
lifecycle before the scan playbook runs; the nodes join it as pre-provisioned
hosts and are removed once it returns. Every node keeps its own durable state.
"""

from utils.workloads import WorkloadProfile


class WebrunnerNodes(WorkloadProfile):
    kind = 'nodes'
    workload = 'webrunner'
    manages_ssh_key = False

    def node_id(self, deployment_id, index):
        return '{0}-n{1:02d}'.format(deployment_id, int(index) + 1)


PROFILE = WebrunnerNodes()
