# targets.yaml — Format Specification

## Purpose
Defines what to look for during a scan. Each target is a fingerprint with
one or more probes. The scanner runs masscan to find open ports, then fires
each probe against matching hosts, and applies pattern/version matching.

## Schema

```yaml
targets:
  - name: string                # Human-readable label (appears in results)
    tags: [string, ...]         # Free-form tags for grouping/filtering results
    ports: [integer, ...]       # Ports masscan will scan for this target
    probes:
      - type: tcp_banner|http|https|rtsp|udp
        # --- For http/https ---
        path: string            # URL path (e.g. "/", "/login.asp", "/api/version")
        method: GET|POST        # Default: GET
        headers:                # Optional extra request headers
          Header-Name: value
        body: string            # POST body (optional)
        match_in: body|headers|[body, headers]  # Where to search for patterns
        # --- For tcp_banner ---
        # (no extra fields — reads the raw TCP banner on connect)
        # --- For rtsp ---
        # (sends OPTIONS * RTSP/1.0 and matches banner)
        # --- Pattern matching (all probe types) ---
        patterns:               # At least one must match (OR logic)
          - "regex or plain string"
        all_patterns:           # All must match (AND logic, optional)
          - "regex or plain string"
        # --- Version extraction (optional) ---
        version_extract: "regex with one capture group"
        version_compare:        # Optional — filter by version
          operator: "<="|">="|"=="|"!="|"<"|">"
          value: "string or number"
        # --- Confidence ---
        confidence: high|medium|low   # Default: medium
```

## Rules

- A target matches a host if ANY probe matches
- Within a probe, `patterns` uses OR logic (any one pattern is enough)
- `all_patterns` uses AND logic — use when you need multiple strings to co-occur
- `version_extract` must contain exactly one regex capture group `()`
- Version comparison is string-aware for dotted versions (e.g. "20.3" < "20.17")
- `match_in` defaults to `body` for http/https probes
- For `tcp_banner` type, the banner is the raw bytes received on connect
- Patterns are case-insensitive by default; prefix with `(?-i)` to force case-sensitive
- Tags are free-form strings — use them for filtering with `--tag` at runtime

## Probe types
| Type | Description |
|------|-------------|
| `tcp_banner` | Connect and read raw banner |
| `http` | HTTP GET/POST, match response |
| `https` | HTTPS GET/POST, match response (cert errors ignored) |
| `rtsp` | RTSP OPTIONS probe, match response |
| `udp` | Send empty UDP, match response |

## Common port reference
| Service | Ports |
|---------|-------|
| HTTP | 80, 8080, 8000, 8888 |
| HTTPS | 443, 8443 |
| SSH | 22 |
| Telnet | 23 |
| FTP | 21 |
| RTSP (cameras) | 554, 8554 |
| ONVIF (cameras) | 80, 8080 |
| DVR/NVR | 37777, 34567 |
| RDP | 3389 |
| SMB | 445 |
| Redis | 6379 |
| Elasticsearch | 9200 |
| MongoDB | 27017 |
| MySQL | 3306 |
| PostgreSQL | 5432 |

## Examples

### D-Link DIR-823X firmware 240126 or 240802
```yaml
- name: "D-Link DIR-823X fw 240126/240802"
  tags: [router, d-link, cpe, iot]
  ports: [80, 443, 8080]
  probes:
    - type: http
      path: "/"
      match_in: body
      patterns: ["DIR-823X"]
      all_patterns: []
    - type: http
      path: "/"
      match_in: body
      patterns: ["240126", "240802"]
      confidence: high
```

### Exposed IP cameras (any brand)
```yaml
- name: "Exposed IP Camera"
  tags: [camera, iot, surveillance]
  ports: [80, 554, 8080, 8443, 37777, 34567]
  probes:
    - type: http
      path: "/"
      match_in: [body, headers]
      patterns:
        - "(?i)hikvision"
        - "(?i)dahua"
        - "(?i)ip camera"
        - "(?i)ipcam"
        - "(?i)webcam"
        - "(?i)nvr"
        - "(?i)dvr"
        - "(?i)axis"
        - "(?i)reolink"
        - "(?i)amcrest"
    - type: rtsp
      patterns: ["RTSP/1.0 200"]
      confidence: medium
```

### Cisco Catalyst SD-WAN Manager <= 20.17
```yaml
- name: "Cisco SD-WAN vManage <= 20.17"
  tags: [cisco, sdwan, network, cve]
  ports: [443, 8443]
  probes:
    - type: https
      path: "/dataservice/client/server"
      method: GET
      match_in: body
      patterns: ["vmanage", "platformVersion"]
      version_extract: '"platformVersion":"([0-9.]+)"'
      version_compare:
        operator: "<="
        value: "20.17"
      confidence: high
    - type: https
      path: "/"
      match_in: [body, headers]
      patterns: ["vManage", "Cisco SD-WAN"]
      confidence: low
```

### Ubuntu 24.04 SSH
```yaml
- name: "Ubuntu 24.04 SSH"
  tags: [linux, ubuntu, ssh]
  ports: [22]
  probes:
    - type: tcp_banner
      patterns:
        - "Ubuntu-24"
        - "OpenSSH.*Ubuntu"
      version_extract: "SSH-2.0-OpenSSH_([0-9p.]+)"
      confidence: high
```

### Open Redis (unauthenticated)
```yaml
- name: "Open Redis"
  tags: [database, redis, exposed]
  ports: [6379]
  probes:
    - type: tcp_banner
      patterns: ["redis_version"]
      version_extract: "redis_version:([0-9.]+)"
      confidence: high
```
