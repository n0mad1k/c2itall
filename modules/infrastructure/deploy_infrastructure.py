#!/usr/bin/env python3
"""Standalone infrastructure-only VM entry point."""

from pathlib import Path
import argparse
import json
import sys

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from utils.common import generate_deployment_id, setup_logging
from utils.provider_utils import select_provider, gather_provider_config
from utils.deployment_engine import deploy_infrastructure
from utils.provider_registry import infrastructure_adapter


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    recovery = parser.add_mutually_exclusive_group()
    recovery.add_argument('--teardown-id')
    recovery.add_argument('--teardown-all', action='store_true')
    recovery.add_argument('--health', action='store_true', help='Read health of tracked infrastructure without deploying')
    args = parser.parse_args(argv)
    if args.health:
        from utils.provider_registry import infrastructure_health
        reports = infrastructure_health()
        print(json.dumps(reports, indent=2))
        return all(report['healthy'] for report in reports)
    if args.teardown_id:
        from utils.cleanup_engine import teardown_by_deployment_id
        return teardown_by_deployment_id(args.teardown_id)
    if args.teardown_all:
        from utils.cleanup_engine import teardown_all_infrastructure
        return teardown_all_infrastructure()
    provider = select_provider('infrastructure')
    if provider is None:
        return False
    adapter = infrastructure_adapter(provider)
    if adapter is None:
        raise ValueError('Selected provider has no infrastructure adapter')
    deployment_id = generate_deployment_id()
    config = gather_provider_config(provider, capability='infrastructure')
    config.update(provider=provider, deployment_id=deployment_id,
                  infrastructure_deployment=True, deployment_type='infrastructure')
    public_key = input('SSH public key path (blank to generate deployment key): ').strip()
    if public_key:
        config.update(ssh_key_path=public_key, ssh_key_generated=False)
    else:
        private = Path.home() / '.ssh' / f'c2deploy_{deployment_id}'
        if private.exists() or Path(str(private) + '.pub').exists():
            raise ValueError('Deployment key already exists; supply its public path explicitly')
        config.update(ssh_key_path=str(private) + '.pub', ssh_private_key_path=str(private),
                      ssh_key_generated=True)
    config.update(adapter.validate_config(config, require_key=False))
    setup_logging(deployment_id)
    if not adapter.prepare_key(config):
        return False
    print(f'Deployment ID: {deployment_id}; recover with modules/infrastructure/deploy_infrastructure.py --teardown-id {deployment_id}')
    return deploy_infrastructure(config)


if __name__ == '__main__':
    try:
        sys.exit(0 if main() else 1)
    except (ValueError, OSError) as exc:
        print(f'Infrastructure configuration failed: {exc}', file=sys.stderr)
        sys.exit(1)
