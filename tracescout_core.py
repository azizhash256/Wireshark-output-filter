"""
Core runner shared by CLI and GUI.
Adds:
- JSON cache for rDNS / RDAP with TTL
- Simple heuristics: DoT/DoH/QUIC hints
"""
import os, json, time
from typing import Optional
from ipaddress import ip_address, IPv6Address

from cacheutil import Cache
from ip_inspector import (
    load_known_cidrs, load_known_sites, parse_pcap, parse_text_like,
    ip_in_known, domain_in_known, reverse_dns as _reverse_dns, rdap_lookup as _rdap_lookup,
)

CACHE_PATH = os.path.join(".cache", "tracescout_cache.json")

def _heuristics(record, ports_seen_for_ip: set[int] | None):
    """
    Add lightweight protocol hints.
    - DoT: TCP/853
    - DoH: HTTPS with '/dns-query' host observed (from HTTP) or port mapping to known DNS CIDRs
    - QUIC: UDP/443 (no SNI)
    """
    hints = set(record.get("hints", []))
    if not ports_seen_for_ip:
        record["hints"] = sorted(hints)
        return record
    if 853 in ports_seen_for_ip:
        hints.add("DoT-like (853)")
    if 443 in ports_seen_for_ip and record.get("domains"):
        for d in record["domains"]:
            if "/dns-query" in d:
                hints.add("DoH-like")
                break
    if 443 in ports_seen_for_ip and record["version"] in (4,6):
        # UDP/443 likely QUIC (cannot extract SNI)
        hints.add("QUIC-like (UDP/443)")
    record["hints"] = sorted(hints)
    return record

def run_tracescout(input_path: str,
                   known: Optional[str] = None,
                   sites: Optional[str] = None,
                   reverse_dns: bool = False,
                   rdap: bool = False,
                   limit: Optional[int] = None,
                   cache_ttl: int = 86400):
    os.makedirs(os.path.dirname(CACHE_PATH), exist_ok=True)
    cache = Cache(CACHE_PATH, ttl=cache_ttl)

    known_cidrs = load_known_cidrs(known) if known and os.path.exists(known) else []
    known_sites = load_known_sites(sites) if sites and os.path.exists(sites) else []

    ext = os.path.splitext(input_path)[1].lower()
    ip_to_domains = {}
    ports_for_ip = {}
    if ext in [".pcap", ".pcapng"]:
        ip_set, ip_to_domains, ports_for_ip = parse_pcap(input_path, limit=limit)  # parse_pcap now returns ports
    else:
        ip_set = parse_text_like(input_path)

    records = []
    for ip in sorted(ip_set, key=lambda x: (isinstance(ip_address(x), IPv6Address), ip_address(x))):
        rec = {
            "ip": ip,
            "version": 6 if isinstance(ip_address(ip), IPv6Address) else 4,
            "domains": sorted({d.strip().lower().rstrip(".") for d in ip_to_domains.get(ip, set()) if d}),
            "known_providers": [],
            "known_sites": [],
            "rDNS": None,
            "rdap": None,
        }
        if known_cidrs:
            rec["known_providers"] = sorted(set(ip_in_known(ip, known_cidrs)))
        for d in rec["domains"]:
            rec["known_sites"].extend(domain_in_known(d, known_sites))
        rec["known_sites"] = sorted(set(rec["known_sites"]))

        # cached lookups
        if reverse_dns:
            rec["rDNS"] = cache.get_or_set(f"rdns:{ip}", lambda: _reverse_dns(ip))
            if rec["rDNS"]:
                rec["known_sites"].extend(domain_in_known(rec["rDNS"], known_sites))
                rec["known_sites"] = sorted(set(rec["known_sites"]))
        if rdap:
            rec["rdap"] = cache.get_or_set(f"rdap:{ip}", lambda: _rdap_lookup(ip))

        # heuristics
        rec = _heuristics(rec, ports_for_ip.get(ip))

        records.append(rec)

    cache.flush()
    return records
