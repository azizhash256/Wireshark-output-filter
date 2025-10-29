#!/usr/bin/env python3
"""
TraceScout — Unique IP Extractor for Wireshark Captures

Enhancements in this version:
- Parses PCAP/PCAPNG with Scapy (IPv4/IPv6 src/dst)
- Or parses text/CSV/JSON exports via regex
- Best-effort HTTP Host / TLS SNI extraction (PCAP only)
- Tracks observed ports per IP for lightweight heuristics (e.g., DoT/DoH/QUIC hints)
- Checks IPs against known CIDR ranges + known domain patterns
- Optional reverse DNS + RDAP org/ASN lookup (shared engine handles caching)
- Outputs to console + out/ips.json + out/ips.csv
- Exposes helpers so tracescout_core.py can import and reuse logic
"""
import argparse
import json
import os
import re
import csv
import socket
from ipaddress import ip_address, ip_network, IPv6Address
from collections import defaultdict

from rich import print as rprint
from rich.table import Table
from rich.console import Console

from scapy.all import PcapReader, TCP, UDP, Raw, IP, IPv6
import yaml
from ipwhois import IPWhois

OUT_DIR = "out"
DEFAULT_JSON = os.path.join(OUT_DIR, "ips.json")
DEFAULT_CSV  = os.path.join(OUT_DIR, "ips.csv")

IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
# Basic IPv6 (compressed forms included)
IPV6_RE = re.compile(r"\b(?:(?:[A-Fa-f0-9]{1,4}:){1,7}:?|:(?::[A-Fa-f0-9]{1,4}){1,7})\b")

HTTP_HOST_RE = re.compile(rb"\bHost:\s*([^\r\n]+)", re.IGNORECASE)

# -----------------------------
# TLS SNI: minimal ClientHello parse (best-effort)
# -----------------------------
def extract_tls_sni(payload: bytes) -> str | None:
    try:
        # TLS record header: ContentType(1)=0x16 (Handshake), Version(2), Length(2)
        if len(payload) < 5 or payload[0] != 0x16:
            return None
        hs = payload[5:]
        # Handshake type 0x01 = ClientHello
        if len(hs) < 4 or hs[0] != 0x01:
            return None

        # Heuristic: search for extension type 0x0000 (server_name)
        idx = hs.find(b"\x00\x00")
        while idx != -1 and idx + 7 < len(hs):
            ext_len = int.from_bytes(hs[idx+2:idx+4], "big")
            ex_end = idx + 4 + ext_len
            if ex_end > len(hs):
                break
            block = hs[idx:ex_end]
            try:
                # block layout: 00 00 | ext_len(2) | list_len(2) | name_type(1=0) | name_len(2) | name
                list_len = int.from_bytes(block[4:6], "big")
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

# -----------------------------
# Config loaders / matchers
# -----------------------------
def load_known_cidrs(path: str | None):
    if not path:
        return []
    with open(path, "r", encoding="utf-8") as f:
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
    with open(path, "r", encoding="utf-8") as f:
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

# -----------------------------
# Parsers
# -----------------------------
def parse_pcap(path: str, limit: int | None = None):
    """
    Returns:
      unique_ips: set[str]
      ip_domains: dict[str, set[str]]    (Domains from HTTP Host / TLS SNI)
      ports_for_ip: dict[str, set[int]]  (Observed src/dst ports per IP for heuristics)
    """
    unique_ips: set[str] = set()
    ip_domains: defaultdict[str, set[str]] = defaultdict(set)
    ports_for_ip: defaultdict[str, set[int]] = defaultdict(set)
    count = 0

    with PcapReader(path) as pcap:
        for pkt in pcap:
            if limit and count >= limit:
                break
            count += 1
            try:
                src_ip, dst_ip = None, None
                sport, dport = None, None

                if IP in pkt:
                    src_ip, dst_ip = pkt[IP].src, pkt[IP].dst
                elif IPv6 in pkt:
                    src_ip, dst_ip = pkt[IPv6].src, pkt[IPv6].dst

                if src_ip:
                    unique_ips.add(src_ip)
                if dst_ip:
                    unique_ips.add(dst_ip)

                if TCP in pkt:
                    sport, dport = int(pkt[TCP].sport), int(pkt[TCP].dport)
                elif UDP in pkt:
                    sport, dport = int(pkt[UDP].sport), int(pkt[UDP].dport)

                if src_ip and sport:
                    ports_for_ip[src_ip].add(sport)
                if dst_ip and dport:
                    ports_for_ip[dst_ip].add(dport)

                if Raw in pkt:
                    payload: bytes = bytes(pkt[Raw].load)

                    # HTTP Host
                    m = HTTP_HOST_RE.search(payload)
                    if m:
                        host = m.group(1).strip().decode(errors="ignore")
                        if src_ip:
                            ip_domains[src_ip].add(host)
                        if dst_ip:
                            ip_domains[dst_ip].add(host)

                    # TLS SNI (ClientHello)
                    sni = extract_tls_sni(payload)
                    if sni and dst_ip:
                        ip_domains[dst_ip].add(sni)

            except Exception:
                continue

    # Clean empties
    for k in list(ip_domains.keys()):
        ip_domains[k] = {d for d in ip_domains[k] if d}
        if not ip_domains[k]:
            del ip_domains[k]

    return unique_ips, ip_domains, ports_for_ip

def parse_text_like(path: str):
    text = open(path, "rb").read()
    ips = set()
    # IPv4
    for m in IPV4_RE.finditer(text.decode(errors="ignore")):
        ips.add(m.group(0))
    # IPv6 (validate candidates)
    for m in IPV6_RE.finditer(text.decode(errors="ignore")):
        try:
            ip_address(m.group(0))
            ips.add(m.group(0))
        except Exception:
            pass
    return ips

# -----------------------------
# Helpers
# -----------------------------
def normalize_domain(d: str) -> str:
    d = d.strip().lower()
    return d[:-1] if d.endswith(".") else d

# -----------------------------
# CLI (delegates to shared engine)
# -----------------------------
def main():
    # Use the shared engine so GUI and CLI behave identically (caching, heuristics, etc.)
    from tracescout_core import run_tracescout

    ap = argparse.ArgumentParser(description="Extract unique IPs from Wireshark outputs and mark known ones.")
    ap.add_argument("input", help="Path to .pcap/.pcapng OR text/csv/json export")
    ap.add_argument("--known", help="YAML of known provider CIDRs", default="config/known_providers.yml")
    ap.add_argument("--sites", help="YAML of known site domain patterns", default="config/known_sites.yml")
    ap.add_argument("--reverse-dns", action="store_true", help="Do reverse DNS lookups")
    ap.add_argument("--rdap", action="store_true", help="Do RDAP whois lookups (org/ASN)")
    ap.add_argument("--limit", type=int, help="Max packets to parse (PCAP only)")
    ap.add_argument("--no-save", action="store_true", help="Do not write out/ips.json/.csv")
    ap.add_argument("--cache-ttl", type=int, default=86400, help="Cache TTL seconds for rDNS/RDAP (default 86400)")
    args = ap.parse_args()

    # Run
    records = run_tracescout(
        input_path=args.input,
        known=args.known,
        sites=args.sites,
        reverse_dns=args.reverse_dns,
        rdap=args.rdap,
        limit=args.limit,
        cache_ttl=args.cache_ttl,
    )

    # Console table
    table = Table(show_header=True, header_style="bold")
    table.add_column("IP", style="cyan", no_wrap=True)
    table.add_column("v")
    table.add_column("Domains (HTTP/SNI)", overflow="fold")
    table.add_column("Known Providers", overflow="fold")
    table.add_column("Known Sites", overflow="fold")
    table.add_column("rDNS", overflow="fold")
    table.add_column("Hints", overflow="fold")

    for r in records:
        table.add_row(
            r["ip"],
            str(r["version"]),
            ", ".join(r["domains"]),
            ", ".join(r["known_providers"]),
            ", ".join(r["known_sites"]),
            r.get("rDNS") or "",
            ", ".join(r.get("hints", [])),
        )

    Console().print(table)

    # Save
    if args.no_save:
        rprint("[yellow]Skipped saving files (--no-save).[/yellow]")
        return

    os.makedirs(OUT_DIR, exist_ok=True)
    with open(DEFAULT_JSON, "w", encoding="utf-8") as f:
        json.dump(records, f, ensure_ascii=False, indent=2)

    with open(DEFAULT_CSV, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["ip", "version", "domains", "known_providers", "known_sites", "rDNS", "hints"])
        for r in records:
            w.writerow([
                r["ip"], r["version"],
                "|".join(r["domains"]),
                "|".join(r["known_providers"]),
                "|".join(r["known_sites"]),
                r.get("rDNS") or "",
                "|".join(r.get("hints", [])),
            ])

    rprint(f"[green]Saved[/green] {DEFAULT_JSON} and {DEFAULT_CSV}")

if __name__ == "__main__":
    main()
