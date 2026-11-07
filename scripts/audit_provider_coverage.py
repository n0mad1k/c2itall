#!/usr/bin/env python3
"""Report provider/workload dispatch coverage without cloud mutation."""

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from utils.provider_registry import PROVIDER_SPECS, provider_support_matrix


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--json', action='store_true')
    parser.add_argument('--require-provider', choices=tuple(PROVIDER_SPECS))
    args = parser.parse_args(argv)
    rows = provider_support_matrix()
    if args.json:
        print(json.dumps(rows, indent=2))
    else:
        print('{0:<10} {1:<18} {2}'.format(
            'PROVIDER', 'WORKLOAD', 'ROUTE'))
        for row in rows:
            print('{provider:<10} {workload:<18} {route_kind}'.format(**row))
    if args.require_provider:
        missing = [row['workload'] for row in rows
                   if row['provider'] == args.require_provider and
                   row['route_kind'] == 'unsupported']
        if missing:
            print('{0} lacks: {1}'.format(
                args.require_provider, ', '.join(missing)), file=sys.stderr)
            return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
