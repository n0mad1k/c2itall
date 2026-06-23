#!/usr/bin/env python3
import ipaddress
import math
import time
from pathlib import Path
from urllib.request import urlretrieve
from urllib.error import URLError

CACHE_DIR = Path.home() / '.cache' / 'c2itall' / 'cidr'
CACHE_TTL = 86400  # 24 hours

RIR_URLS = {
    'arin':    'https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest',
    'ripe':    'https://ftp.ripe.net/ripe/stats/delegated-ripencc-extended-latest',
    'apnic':   'https://ftp.apnic.net/stats/apnic/delegated-apnic-extended-latest',
    'lacnic':  'https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-extended-latest',
    'afrinic': 'https://ftp.afrinic.net/stats/delegated-afrinic-extended-latest',
}


def _cache_path(rir: str) -> Path:
    return CACHE_DIR / f'{rir}.txt'


def _is_stale(path: Path) -> bool:
    if not path.exists():
        return True
    return (time.time() - path.stat().st_mtime) > CACHE_TTL


def _fetch_rir(rir: str, url: str) -> Path:
    path = _cache_path(rir)
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    if _is_stale(path):
        try:
            urlretrieve(url, path)
        except (URLError, OSError):
            pass  # use stale cache if download fails
    return path


def _count_to_cidrs(start: str, count: int) -> list[str]:
    try:
        start_addr = ipaddress.IPv4Address(start)
        end_addr = ipaddress.IPv4Address(int(start_addr) + count - 1)
        return [str(n) for n in ipaddress.summarize_address_range(start_addr, end_addr)]
    except (ipaddress.AddressValueError, ValueError):
        return []


def _parse_rir_file(path: Path, target_ccs: set[str]) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {cc: [] for cc in target_ccs}
    try:
        with open(path, encoding='latin-1') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                parts = line.split('|')
                if len(parts) < 7:
                    continue
                _, cc, type_, start, count_str, _, status = parts[:7]
                if type_ != 'ipv4':
                    continue
                if status not in ('allocated', 'assigned'):
                    continue
                cc = cc.upper()
                if cc not in target_ccs:
                    continue
                try:
                    count = int(count_str)
                except ValueError:
                    continue
                result[cc].extend(_count_to_cidrs(start, count))
    except OSError:
        pass
    return result


def get_country_cidrs(country_codes: list[str], exclude_map: dict[str, list] | None = None) -> dict[str, list[str]]:
    if exclude_map is None:
        exclude_map = {}
    target_ccs = {cc.upper() for cc in country_codes}
    combined: dict[str, list[str]] = {cc: [] for cc in target_ccs}

    for rir, url in RIR_URLS.items():
        path = _fetch_rir(rir, url)
        partial = _parse_rir_file(path, target_ccs)
        for cc, cidrs in partial.items():
            combined[cc].extend(cidrs)

    for cc, excludes in exclude_map.items():
        cc = cc.upper()
        if cc not in combined or not excludes:
            continue
        exclude_nets = []
        for ex in excludes:
            try:
                exclude_nets.append(ipaddress.ip_network(ex, strict=False))
            except ValueError:
                pass
        if not exclude_nets:
            continue
        filtered = []
        for cidr in combined[cc]:
            try:
                net = ipaddress.ip_network(cidr, strict=False)
                if not any(net.overlaps(ex) for ex in exclude_nets):
                    filtered.append(cidr)
            except ValueError:
                filtered.append(cidr)
        combined[cc] = filtered

    return combined
