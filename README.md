# Wireshark-output-filter
# TraceScout — Unique IP Extractor for Wireshark Captures

**TraceScout** parses a Wireshark/tshark capture (PCAP/PCAPNG) or a text/CSV/JSON export, extracts **unique IPv4/IPv6 addresses**, and tells you:
- Which IPs appeared (no duplicates)
- Any **domains** observed (HTTP Host / TLS SNI) for those IPs when a PCAP is provided
- Whether each IP matches your **known networks** (CIDR lists) or **known websites** (domain patterns)
- Optional **reverse DNS** and **RDAP** (org / ASN) lookups

> Use this post-test to quickly see “what talked to what” and spot outliers.

## Features
- Input: `.pcap` / `.pcapng` (preferred) or Wireshark text/CSV/JSON export.
- Collects unique IPv4/IPv6 from packet addresses **or** by regex on text exports.
- PCAP mode: extracts **HTTP Host** and **TLS SNI** to map IP ↔ domain (best-effort).
- Checks membership against `config/known_providers.yml` (CIDRs) and `config/known_sites.yml` (domains / regex).
- Optional `--reverse-dns` and `--rdap` (needs internet).
- Outputs: pretty console table, plus `out/ips.json` and `out/ips.csv`.

## Quick start
bash
git clone https://github.com/<azizhash256>/tracescout.git
cd tracescout

python -m venv venv
# Windows: venv\Scripts\activate
source venv/bin/activate

Run

PCAP:

python ip_inspector.py samples/sample.pcapng --known config/known_providers.yml --sites config/known_sites.yml --reverse-dns --rdap


Text export:

python ip_inspector.py exports/session.txt --known config/known_providers.yml --sites config/known_sites.yml

Output

Console: table with IP, versions, matched domain (if seen), known provider/site flags, org/ASN (if RDAP).

Files:

out/ips.json

out/ips.csv

Config (customize what’s “known”)

config/known_providers.yml: CIDR ranges (e.g., Cloudflare, Google DNS, your company networks)

config/known_sites.yml: exact/regex domain patterns to mark IPs as “related to <site>”

You can add your own ranges/patterns without touching the code.

Notes / Tips

No duplicates in results; we dedupe across sources.

PCAP parsing uses Scapy — fast, no tshark dependency.

HTTP Host & TLS SNI extraction is best-effort and only available when you pass a PCAP/PCAPNG.

--rdap and --reverse-dns do live lookups. Disable if you need fully offline.

Large captures: use --limit to cap processed packets for a quick skim.

Examples

Flag Google DNS / Cloudflare:

python ip_inspector.py samples/dns_traffic.pcap --known config/known_providers.yml --rdap

## GUI
Launch the simple GUI:

```bash
python gui.py



Only print table, skip files:

python ip_inspector.py exports/log.json --no-save

pip install -r requirements.txt
