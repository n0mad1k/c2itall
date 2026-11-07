#!/usr/bin/env python3
"""Report provider/workload dispatch coverage without cloud mutation."""

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from utils.provider_registry import (
    PROVIDER_SPECS, provider_support_matrix, validate_provider_registry,
)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--json', action='store_true')
    parser.add_argument('--require-provider', choices=tuple(PROVIDER_SPECS))
    args = parser.parse_args(argv)
    try:
        validation = validate_provider_registry(load_references=True)
    except Exception as exc:
        print('Provider registry invalid: ' + str(exc), file=sys.stderr)
        return 2
    rows = provider_support_matrix()
    if args.json:
        print(json.dumps(rows, indent=2))
    else:
        print('Registry valid: {providers} providers, {workloads} workloads, '
              '{controllers} controllers, {pairs} pairs, {routes} routes'.format(
                  **validation))
        print('{0:<10} {1:<18} {2:<18} {3}'.format(
            'PROVIDER', 'WORKLOAD', 'ROUTE', 'VARIANTS'))
        for row in rows:
            variant_summary = ('-' if not row['variants'] else
                               '{0}/{1}'.format(
                                   len(row['supported_variants']),
                                   len(row['variants'])))
            print('{provider:<10} {workload:<18} {route_kind:<18} '
                  '{variant_summary}'.format(
                      variant_summary=variant_summary, **row))
    if args.require_provider:
        missing = [row['workload'] for row in rows
                   if row['provider'] == args.require_provider and
                   row['route_kind'] == 'unsupported']
        partial = [row for row in rows
                   if row['provider'] == args.require_provider and
                   row['variant_coverage'] == 'partial']
        if missing or partial:
            details = []
            if missing:
                details.append('lacks: ' + ', '.join(missing))
            for row in partial:
                details.append('partial: {0} (missing {1})'.format(
                    row['workload'], ', '.join(row['missing_variants'])))
            print('{0} {1}'.format(
                args.require_provider, '; '.join(details)), file=sys.stderr)
            return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
