# countries.yaml — Format Specification

## Purpose
Defines which countries to scan and scan parameters per country.
This file is read by WEBRUNNER at runtime. The scanner resolves each
country code to its CIDR ranges using RIR delegated stats files.

## Schema

```yaml
scan_profile:
  name: string                  # Label for this profile (used in logs/reports)
  rate: integer                 # masscan packets/sec (default: 1000, max: 100000)
  max_hosts_per_country: integer|null  # Cap IPs per country. null = no limit

countries:
  - code: string                # ISO 3166-1 alpha-2 (e.g. US, VE, NL, GB, NG)
    priority: high|medium|low   # Scan order. high = first
    exclude_cidrs:              # Optional CIDR blocks to skip within this country
      - "x.x.x.x/xx"
    notes: string               # Optional context (not used by scanner)
```

## Rules

- `code` must be a valid ISO 3166-1 alpha-2 code
- GB is the correct code for United Kingdom (not UK)
- `rate` applies globally to the masscan run, not per-country
- `exclude_cidrs` entries must be valid CIDR notation
- Countries are scanned in priority order: high → medium → low
- Within same priority, order in the list is preserved

## Valid priority values
`high` | `medium` | `low`

## Common country codes
| Country | Code |
|---------|------|
| United States | US |
| United Kingdom | GB |
| Venezuela | VE |
| Netherlands | NL |
| Canada | CA |
| Nigeria | NG |
| Russia | RU |
| Germany | DE |
| China | CN |
| Brazil | BR |
| Iran | IR |
| India | IN |
| France | FR |
| Australia | AU |

## Example

```yaml
scan_profile:
  name: "latam-europe-sweep"
  rate: 2000
  max_hosts_per_country: 100000

countries:
  - code: VE
    priority: high
    exclude_cidrs: []
    notes: "Primary target"

  - code: US
    priority: medium
    exclude_cidrs:
      - "10.0.0.0/8"
      - "172.16.0.0/12"
      - "192.168.0.0/16"

  - code: NL
    priority: low
```
