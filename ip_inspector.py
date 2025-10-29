#!/usr/bin/env python3
"""
TraceScout — Unique IP Extractor for Wireshark Captures

- Parses PCAP/PCAPNG with Scapy (IPv4/IPv6 src/dst)
- Or parses text/CSV/JSON exports via regex
- Best-effort HTTP Host / TLS SNI extraction (PCAP only)
- Checks IPs against known CIDR ranges + known domain patterns
- Optional reverse DNS + RDAP org/ASN lookup
- Outputs to console + out/ips.json + out/ips.csv
"""
import argparse
import json
import os
import re
import csv
import socket
from ipaddress import ip_address, ip_network, IPv4Address, IPv6Address
from collections import defaultdict

from rich import print as rprint
from rich.table import Table
from rich.console import Console
from rich.progress import track

from scapy.all import PcapReader, TCP, UDP, Raw, IP, IPv6
import yaml
from ipwhois import IPWhois
import tldextract

OUT_DIR = "out"
DEFAULT_JSON = os.path.join(OUT_DIR, "ips.json")
DEFAULT_CSV  = os.path.join(OUT_DIR, "ips.csv")

IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
# Basic IPv6 (compressed forms included)
IPV6_RE = re.compile(r"\b(?:(?:[A-Fa-f0-9]{1,4}:){1,7}:?|:(?::[A-Fa-f0-9]{1,4}){1,7})\b")

HTTP_HOST_RE = re.compile(rb"\bHost:\s*([^\r\n]+)", re.IGNORECASE)
# TLS SNI: parse ClientHello manually (best-effort minimal)
def extract_tls_sni(payload: bytes) -> str | None:
    # Very minimal TLS ClientHello parsing (content type 22, handshake 1)
    try:
        if len(payload) < 5 or payload[0] != 0x16:  # TLS Handshake
            return None
        # Skip TLS record header (5 bytes)
        hs = payload[5:]
        if len(hs) < 4 or hs[0] != 0x01:  # ClientHello
            return None
        # Skip fixed parts in ClientHello to reach extensions (this is simplified)
        # Safer: search for SNI extension id (0x00 0x00) in the blob
        # Heuristic search
        i = 0
        # Find "server_name" extension id bytes
        idx = hs.find(b"\x00\x00")
        while idx != -1 and idx + 7 < len(hs):
            # ext_type(2) ext_len(2) list_len(2) name_type(1=0) name_len(2) name
            ext_len = int.from_bytes(hs[idx+2:idx+4], "big")
            ex_end = idx + 4 + ext_len
            if ex_end > len(hs):
                break
            block = hs[idx:ex_end]
            # try to parse list_len and name
            try:
                list_len = int.from_bytes(block[4:6], "big")
                # name_type at 6
                if block[6] == 0:
                    name_len = int.from_bytes(block[7:9], "big")
                    name = block[9:9+name_len]
                    return name.decode(errors="ignore")
            except Exception:
                pass
            idx = hs.find(b"\x00\x00", ex_end)
    except Exception:
        return None
    return None

def load_known_cidrs(path: str | None):
    if not path:
        return []
    with open(path, "r") as f:
        data = yaml.safe_load(f) or []
    cidr_entries = []
    for item in data:
        label = item.get("label", "unknown")
        for cidr in item.get("cidrs", []):
            try:
                cidr_entries.append((label, ip_network(cidr, strict=False)))
            except Exception:
                pass
    return cidr_entries

def load_known_sites(path: str | None):
    if not path:
        return []
    with open(path, "r") as f:
        data = yaml.safe_load(f) or []
    patterns = []
    for item in data:
        label = item.get("label", "site")
        for pat in item.get("patterns", []):
            try:
                patterns.append((label, re.compile(pat, re.IGNORECASE)))
            except re.error:
                pass
    return patterns

def ip_in_known(ip: str, networks) -> list[str]:
    addr = ip_address(ip)
    hits = []
    for label, net in networks:
        if addr in net:
            hits.append(label)
    return hits

def domain_in_known(domain: str, patterns) -> list[str]:
    hits = []
    for label, regex in patterns:
        if regex.search(domain):
            hits.append(label)
    return hits

def reverse_dns(ip: str) -> str | None:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None

def rdap_lookup(ip: str) -> dict | None:
    try:
        obj = IPWhois(ip)
        res = obj.lookup_rdap(asn_methods=["dns", "whois", "http"])
        out = {
            "asn": res.get("asn"),
            "asn_description": res.get("asn_description"),
            "network": (res.get("network") or {}).get("name"),
            "org": (res.get("objects") or {}).get(res.get("asn_cidr"), {}),
        }
        return {k: v for k, v in out.items() if v}
    except Exception:
        return None

def parse_pcap(path: str, limit: int | None = None):
    unique_ips: set[str] = set()
    ip_domains: defaultdict[str, set[str]] = defaultdict(set)  # ip -> domains seen (HTTP host / SNI)
    count = 0
    with PcapReader(path) as pcap:
        for pkt in pcap:
            if limit and count >= limit:
                break
            count += 1
            try:
                if IP in pkt:
                    unique_ips.add(pkt[IP].src)
                    unique_ips.add(pkt[IP].dst)
                if IPv6 in pkt:
                    unique_ips.add(pkt[IPv6].src)
                    unique_ips.add(pkt[IPv6].dst)

                if Raw in pkt:
                    payload: bytes = bytes(pkt[Raw].load)

                    # HTTP Host
                    m = HTTP_HOST_RE.search(payload)
                    if m:
                        host = m.group(1).strip().decode(errors="ignore")
                        # Try to attach to IP endpoints for this packet
                        if IP in pkt:
                            ip_domains[pkt[IP].dst].add(host)
                            ip_domains[pkt[IP].src].add(host)
                        elif IPv6 in pkt:
                            ip_domains[pkt[IPv6].dst].add(host)
                            ip_domains[pkt[IPv6].src].add(host)

                    # TLS SNI (ClientHello)
                    sni = extract_tls_sni(payload)
                    if sni:
                        if IP in pkt:
                            ip_domains[pkt[IP].dst].add(sni)
                        elif IPv6 in pkt:
                            ip_domains[pkt[IPv6].dst].add(sni)

            except Exception:
                continue
    # clean empty strings
    for k in list(ip_domains.keys()):
        ip_domains[k] = {d for d in ip_domains[k] if d}
        if not ip_domains[k]:
            del ip_domains[k]
    return unique_ips, ip_domains

def parse_text_like(path: str):
    text = open(path, "rb").read()
    ips = set()
    for m in IPV4_RE.finditer(text.decode(errors="ignore")):
        ips.add(m.group(0))
    for m in IPV6_RE.finditer(text.decode(errors="ignore")):
        try:
            # Validate
            ip_address(m.group(0))
            ips.add(m.group(0))
        except Exception:
            pass
    return ips

def normalize_domain(d: str) -> str:
    d = d.strip().lower()
    # remove trailing dot
    if d.endswith("."):
        d = d[:-1]
    return d

def main():
    ap = argparse.ArgumentParser(description="Extract unique IPs from Wireshark outputs and mark known ones.")
    ap.add_argument("input", help="Path to .pcap/.pcapng OR text/csv/json export")
    ap.add_argument("--known", help="YAML of known provider CIDRs", default="config/known_providers.yml")
    ap.add_argument("--sites", help="YAML of known site domain patterns", default="config/known_sites.yml")
    ap.add_argument("--reverse-dns", action="store_true", help="Do reverse DNS lookups")
    ap.add_argument("--rdap", action="store_true", help="Do RDAP whois lookups (org/ASN)")
    ap.add_argument("--limit", type=int, help="Max packets to parse (PCAP only)")
    ap.add_argument("--no-save", action="store_true", help="Do not write out/ips.json/.csv")
    args = ap.parse_args()

    os.makedirs(OUT_DIR, exist_ok=True)

    known_cidrs = load_known_cidrs(args.known) if args.known and os.path.exists(args.known) else []
    known_sites = load_known_sites(args.sites) if args.sites and os.path.exists(args.sites) else []

    ext = os.path.splitext(args.input)[1].lower()
    ip_to_domains: dict[str, set[str]] = {}
    if ext in [".pcap", ".pcapng"]:
        rprint(f"[bold]PCAP mode[/bold]: parsing {args.input}")
        ip_set, ip_to_domains = parse_pcap(args.input, limit=args.limit)
    else:
        rprint(f"[bold]Text mode[/bold]: parsing {args.input}")
        ip_set = parse_text_like(args.input)

    # Build records
    records = []
    for ip in sorted(ip_set, key=lambda x: (isinstance(ip_address(x), IPv6Address), ip_address(x))):
        rec = {
            "ip": ip,
            "version": 6 if isinstance(ip_address(ip), IPv6Address) else 4,
            "domains": sorted({normalize_domain(d) for d in ip_to_domains.get(ip, set())}),
            "known_providers": [],
            "known_sites": [],
            "rDNS": None,
            "rdap": None
        }

        # known memberships
        if known_cidrs:
            rec["known_providers"] = ip_in_known(ip, known_cidrs)
        # sites (via mapped domains)
        for d in rec["domains"]:
            hits = domain_in_known(d, known_sites)
            rec["known_sites"].extend(hits)
        # also try rDNS domain matching if we have it
        if args.reverse_dns:
            rec["rDNS"] = reverse_dns(ip)
            if rec["rDNS"]:
                rec["known_sites"].extend(domain_in_known(rec["rDNS"], known_sites))

        # RDAP
        if args.rdap:
            rec["rdap"] = rdap_lookup(ip)

        # dedupe & sort flags
        rec["known_providers"] = sorted(set(rec["known_providers"]))
        rec["known_sites"] = sorted(set(rec["known_sites"]))

        records.append(rec)

    # Console table
    table = Table(show_header=True, header_style="bold")
    table.add_column("IP", style="cyan", no_wrap=True)
    table.add_column("v")
    table.add_column("Domains (HTTP/SNI)", overflow="fold")
    table.add_column("Known Providers", overflow="fold")
    table.add_column("Known Sites", overflow="fold")
    table.add_column("rDNS", overflow="fold")
    table.add_column("ASN/Org (RDAP)", overflow="fold")

    for rec in records:
        rdap_str = ""
        if isinstance(rec["rdap"], dict):
            parts = []
            if rec["rdap"].get("asn"):
                parts.append(f"ASN {rec['rdap']['asn']}")
            if rec["rdap"].get("asn_description"):
                parts.append(rec["rdap"]["asn_description"])
            if rec["rdap"].get("network"):
                parts.append(rec["rdap"]["network"])
            rdap_str = " | ".join(parts)

        table.add_row(
            rec["ip"],
            str(rec["version"]),
            ", ".join(rec["domains"]) if rec["domains"] else "",
            ", ".join(rec["known_providers"]) if rec["known_providers"] else "",
            ", ".join(rec["known_sites"]) if rec["known_sites"] else "",
            rec["rDNS"] or "",
            rdap_str
        )

    Console().print(table)

    if not args.no_save:
        with open(DEFAULT_JSON, "w", encoding="utf-8") as f:
            json.dump(records, f, ensure_ascii=False, indent=2)
        with open(DEFAULT_CSV, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["ip", "version", "domains", "known_providers", "known_sites", "rDNS", "rdap_asn", "rdap_desc", "rdap_net"])
            for r in records:
                asn = (r["rdap"] or {}).get("asn") if isinstance(r.get("rdap"), dict) else ""
                desc = (r["rdap"] or {}).get("asn_description") if isinstance(r.get("rdap"), dict) else ""
                net = (r["rdap"] or {}).get("network") if isinstance(r.get("rdap"), dict) else ""
                w.writerow([
                    r["ip"], r["version"],
                    "|".join(r["domains"]),
                    "|".join(r["known_providers"]),
                    "|".join(r["known_sites"]),
                    r["rDNS"] or "",
                    asn or "", desc or "", net or ""
                ])
        rprint(f"[green]Saved[/green] {DEFAULT_JSON} and {DEFAULT_CSV}")
    else:
        rprint("[yellow]Skipped saving files (--no-save)[/yellow]")

if __name__ == "__main__":
    main()
