# TPCRM Findings Scanner

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A Python CLI for investigating **third-party cyber risk management (TPCRM)** findings and building evidence-backed responses. Scan a target, determine whether you are looking at an origin server or a CDN/WAF edge, collect compensating-controls evidence, and produce ticket-ready language for disputing false positives.

The same investigative workflow applies across rating platforms — external scanners often flag CDN edges, backported packages, or compensating controls as if they were direct origin issues. This tool helps security teams validate what a finding actually represents before accepting or remediating it.

**Supported use cases include findings from SecurityScorecard, BitSight, UpGuard, Black Kite, and similar TPCRM vendors.**

Built to replace a pile of one-off probe scripts with one modular tool. Stdlib + PyYAML only.

## What it does

Given an IP or hostname (and optional `--host` override on IP targets), the scanner:

1. **Discovers** — reverse DNS, TCP port scan with banners, TLS cert/SAN extraction, HTTP/HTTPS probes, forward DNS/CNAME chain hints
2. **Classifies** — origin server vs managed edge (CDN, cloud WAF, load balancer) with evidence
3. **Assesses** — security headers, WAF/CDN fingerprinting (wafw00f-style patterns), server version/backport indicators, optional TLS cipher-suite enumeration (`--cipher`)
4. **Documents** — JSON + Markdown reports, optional CSV evidence, finding-response narratives

The main question it answers: *"Should we remediate against this IP, or is this a CDN/WAF edge (or other false-positive context)?"*

## Quick start

```bash
pip install -r requirements.txt
cp config.example.yaml config.yaml   # then edit contact details
python cli.py config --contact "security@example.com"
python cli.py scan example.com -y     # IP or hostname (apex/subdomain)
```

`config.yaml` is local-only (gitignored). The repo ships `config.example.yaml` as the template.

Linux/macOS: `chmod +x cli.py` if you want `./cli.py` directly.

### Common commands

```bash
# Scan by hostname (apex or subdomain); Host/SNI set automatically
python cli.py scan example.com --profile web -y
python cli.py scan www.example.com -y

# Full scan with explicit hostname override on an IP target
python cli.py scan 192.168.1.100 --host app.example.com

# Web-only, skip port scan (assumes 80/443/8080/8443)
python cli.py scan 192.168.1.100 --only-web --no-port-scan

# Evidence + backport analysis with CSV/JSON artifacts
python cli.py scan 192.168.1.100 --evidence --backports

# Set a real contact first (required for identified scans), then confirm signature; -y skips prompt
python cli.py config --contact "security@example.com"
python cli.py scan 192.168.1.100
python cli.py scan 192.168.1.100 -y

# Local testing with template config contact
python cli.py scan 192.168.1.100 --allow-placeholder -y

# Stealth mode (no identifying scan headers)
python cli.py scan 192.168.1.100 --stealth

# Scan profiles: quick (web + common services), web (HTTP/S only), full (config port list)
python cli.py scan 192.168.1.100 --profile web
python cli.py scan 192.168.1.100 --profile quick --evidence

# Batch scan from a file (one IP or hostname per line); -y skips signature confirmation
python cli.py batch targets.txt --threads 5 --profile quick --output-csv -y

# Batch with the same enrichment flags as single-target scan
python cli.py batch targets.txt --only-web --evidence --backports --output-csv -y

# Enumerate TLS cipher suites and validate weak-cipher findings
python cli.py scan example.com --cipher -y
python cli.py scan 192.168.1.100 --cipher --evidence -y

# Re-run evidence analysis on an existing scan (no network)
python cli.py evidence example.com --type all
python cli.py evidence 192.168.1.100 --scan-file outputs/reports/scan_....json --type backports

# Compare two reports for the same target (re-check after remediation or vendor re-scan)
python cli.py diff outputs/reports/scan_203.0.113.10_old.json outputs/reports/scan_203.0.113.10_new.json
python cli.py diff older.json newer.json --json

# Configuration
python cli.py config --show
python cli.py config --contact "security@example.com"
```

## Scan pipeline

```
Target IP or hostname
  → reverse DNS
  → port scan + banners
  → TLS analysis (cert, versions, SANs)
  → TLS cipher enumeration (optional, --cipher)
  → HTTP/HTTPS probes (smart host selection, capped)
  → security analysis (headers, WAF/CDN, classification)
  → origin discovery (DNS chain, hostname hints)
  → finding-response narrative
  → JSON / Markdown / CSV reports
```

### HTTP probing behavior

Probes are intentionally conservative:

- **Host order:** `--host` → target IP → PTR/SAN fallbacks (only if earlier attempts fail)
- **Per port:** stop after the first successful response
- **Global cap:** `max_http_probes` (default 8) across the whole scan

This keeps CDN targets like `1.1.1.1` at ~4 probes instead of 30+.

### Scan profiles

| Profile | Ports scanned | HTTP probing |
|---------|---------------|--------------|
| `web` | 80, 443, 8080, 8443 | Web ports only |
| `quick` | Web + 22, 25, 53, 3389 | Web ports from open set |
| `full` | `scan.default_ports` in config | Web ports from open set |

Use `--profile` on `scan` or `batch`. `--ports` overrides the profile port list.

### Scan session confirmation

Before the first target in a `scan` or `batch` run, the CLI prints the active HTTP signature (User-Agent, `X-Security-Scan`, `X-Contact`) and prompts:

```
Proceed with scan using the signature above? [y/N]:
```

Pass `-y` / `--yes` to skip the prompt (recommended for CI and `validate_live.py`).

Identified scans (`--stealth` off) require a **non-placeholder contact** in `config.yaml`. The default template values are blocked until you run `config --contact`. Use `--allow-placeholder` for local testing only.

### Domain targets

`scan`, `batch`, and `evidence` accept **IP addresses or hostnames** (apex and subdomains are treated the same):

```bash
python cli.py scan example.com --profile web -y
python cli.py scan www.example.com --profile web -y
```

When you pass a hostname:

1. The scanner resolves it to an IP (IPv4 preferred).
2. That hostname is used for HTTP `Host` and TLS SNI automatically.
3. Scan metadata records both `input_target` (what you typed) and `target_ip` (resolved address).

Use `--host` to override the hostname when scanning a raw IP (existing behavior). On a hostname target, `--host` replaces the auto-selected SNI/Host value.

Batch target files can mix IPs and hostnames:

```text
# targets.txt (copy from targets.example.txt)
1.1.1.1
example.com
www.example.com
203.0.113.10
```

Reports and logs are still named by resolved IP (`scan_<ip>_<ts>.json`). The `evidence` command resolves hostnames the same way when locating the latest report.

### Scan diff

Compare two JSON reports for the same target to see what changed between scans (ports, classification, WAF/CDN, security grade, TLS expiry, etc.):

```bash
python cli.py diff outputs/reports/scan_1.1.1.1_older.json outputs/reports/scan_1.1.1.1_newer.json
```

Add `--json` for machine-readable output. The diff warns if the reports appear to be for different targets.

## Reports

Outputs land in `outputs/`:

| Path | Contents |
|------|----------|
| `outputs/reports/scan_<ip>_<ts>.json` | Full structured scan data + top-level `summary` |
| `outputs/reports/scan_<ip>_<ts>.md` | Human-readable report with finding-response narrative |
| `outputs/logs/scan_<ip>_<ts>.log` | Per-target scan log (console output mirrored with timestamps) |
| `outputs/evidence/evidence_*.csv` | Backport/security/cipher evidence (with `--evidence` / `--backports` / `--cipher`) |
| `outputs/reports/batch_summary_*.json` | Batch run index |
| `outputs/evidence/batch_summary_*.csv` | Batch CSV rollup (with `--output-csv`) |

### JSON summary fields

Every scan JSON includes a compact `summary` block:

```json
{
  "summary": {
    "environment": {
      "classification": "managed_edge",
      "provider": "cloudflare",
      "role": "cloud-waf",
      "confidence": "high"
    },
    "open_port_count": 2,
    "open_ports": [80, 443],
    "web_services": ["HTTP 80", "HTTPS 443"],
    "security_score": { "grade": "C", "percentage": 66.7 },
    "backport_confidence": "medium",
    "evidence_assessment": { "overall": "strong", "confidence": "high", "evidence_count": 12 },
    "cipher_summary": { "accepted_total": 14, "weak_count": 1, "categories": ["3des-sweet32"] },
    "origin_discovery": {
      "query_hostname": "www.example.com",
      "edge_detected_in_chain": true,
      "top_hints": ["origin.internal.example.com"]
    },
    "remediation_narrative": {
      "summary": "Target 203.0.113.10 shows indicators of edge or WAF protection...",
      "recommended_actions": ["Do not remediate against this IP alone..."],
      "evidence_bullets": ["Reverse DNS: ...", "HTTP headers indicate Cloudflare: ..."],
      "suitable_for_remediation_response": true
    }
  }
}
```

### Finding-response narrative

Markdown reports include a **Remediation Narrative** section — plain-language text suitable for pasting into a TPCRM platform dispute or remediation ticket (SecurityScorecard, BitSight, UpGuard, Black Kite, etc.). It covers:

- Whether the target is likely origin vs edge/WAF
- Origin hostname hints and DNS/CNAME chain context
- Compensating controls (WAF, security headers)
- Backport/false-positive context when `--backports` is used
- TLS cipher-suite findings (confirm or refute weak-cipher findings) when `--cipher` is used
- Numbered recommended actions and supporting evidence bullets

## Configuration

`config.yaml` controls scan behavior and output. Key options:

```yaml
signature:
  enabled: true
  user_agent: "TPCRM Findings Validation Scan (Contact: your@email.com)"
  contact_value: "your@email.com"

scan:
  default_ports: [80, 443, 8080, 8443, 22, 25, 53, 3389, ...]
  default_profile: null   # optional: quick, web, or full
  timeout: 1.5
  max_workers: 200
  max_http_probes: 8
  max_host_candidates_per_port: 3
  capture_body: false
  capture_body_bytes: 0
  cipher_enum: false              # enable --cipher by default
  cipher_max_per_protocol: 64     # cap on ciphers enumerated per TLS version

output:
  base_dir: "outputs"
  logs_dir: "logs"
  include_markdown: true
  include_json: true
  include_csv: false
```

CLI flags override config at runtime (`--timeout`, `--capture-body`, etc.).

## Architecture

```
scanner/
├── cli.py                         # Orchestrator + CLI
├── config.yaml
├── scripts/
│   ├── validate_offline.py        # Offline test suite (no network)
│   └── validate_live.py           # Live CDN/origin checks (auto-confirms signature)
└── ssc/                           # internal package name (historical)
    ├── scan_profiles.py           # quick / web / full port presets
    ├── scanners/
    │   ├── port_scanner.py        # TCP scan + banners
    │   ├── tls_scanner.py         # Cert/SAN/TLS versions
    │   ├── cipher_enumerator.py   # TLS cipher-suite enumeration + weak-cipher tags
    │   ├── http_scanner.py        # HTTP probes + optional body capture
    │   ├── backport_detector.py   # Linux backport evidence
    │   └── evidence_collector.py  # Compensating-controls aggregation
    ├── analyzers/
    │   ├── security_headers.py    # Header scoring
    │   ├── waf_cdn.py             # WAF/CDN fingerprinting
    │   ├── server_tokens.py       # Server banner parsing
    │   ├── cloud_classifier.py    # Origin vs edge/LB/WAF
    │   ├── origin_discovery.py    # DNS chain + origin hostname hints
    │   ├── remediation_narrative.py  # Ticket-ready language
    │   └── scan_diff.py              # Compare two scan JSON reports
    ├── reporters/
    │   ├── json_reporter.py
    │   ├── markdown_reporter.py
    │   └── csv_reporter.py
    └── utils/
        ├── network.py
        ├── dns_chain.py
        ├── signatures.py          # SIEM-friendly headers + session banner
        └── scan_log.py            # Per-target log files (thread-local)
```

## Use cases

**Edge/CDN false positives** — Classification + narrative explain why findings on a Cloudflare or CloudFront IP may not apply to the origin.

**Vendor-agnostic dispute evidence** — Same scan output supports responses across TPCRM platforms; the focus is technical truth (origin vs edge, controls present) rather than vendor-specific ticket formats.

**Backport challenges** — Detect Debian/RHEL/Ubuntu backport patterns in server headers and banners; generate evidence when version-string CVEs are likely false positives.

**Compensating controls** — `--evidence` collects security headers, WAF/CDN presence, TLS config, and version indicators into structured CSV/JSON.

**Cipher-suite findings** — `--cipher` enumerates the TLS cipher suites the target accepts (ports 443/8443), classifies weak ones (RC4, 3DES/SWEET32, export, NULL, anonymous, weak key, CBC-on-TLS1.0, no-PFS), and feeds the result into the narrative + evidence to confirm or refute vendor "weak cipher" findings. Native stdlib `ssl`; SSLv2/SSLv3 and ciphers your OpenSSL omits are reported as untested, never as "absent".

**Batch triage** — Scan IP/hostname lists exported from TPCRM findings, produce per-target reports and a CSV summary for prioritization.

## Validation

Offline tests (no network required):

```bash
python scripts/validate_offline.py
```

Live tests (network required; scans real targets; auto-confirms signature like `-y`):

```bash
python scripts/validate_live.py
python scripts/validate_live.py --cdn-ip 1.1.1.1 --origin-host scanme.nmap.org
python scripts/validate_live.py --skip-origin   # CDN check only
```

Offline suite covers classifier, HTTP parsing, reporters, probe limits, evidence wiring, origin discovery, and finding-response narratives. Live suite validates CDN edge detection, origin-like behavior, TLS extraction, probe caps, and report output against `1.1.1.1` and `scanme.nmap.org`.

## Security notes

- Scan only systems you own or have explicit permission to test.
- Default mode sends identifying headers (`User-Agent`, `X-Security-Scan`, `X-Contact`) for SIEM correlation. The CLI blocks placeholder contacts, shows the active signature, and asks for confirmation before scanning. Use `config --contact`, `--stealth`, `--allow-placeholder`, or `-y` when appropriate.
- Optional body capture is off by default; enable only when needed (`--capture-body`).
- Reports may contain headers, cert SANs, and banners from live targets — treat outputs accordingly.

## Legacy migration

Replaces: `ssc_probe.py`, `debian-scanner.py`, `ssc_server_token_batch.py`, `rdp_port_scanner.py`.

## License

TPCRM Findings Scanner is licensed under the [MIT License](LICENSE).

WAF/CDN detection signatures in `ssc/analyzers/waf_cdn.py` are adapted from
[wafw00f](https://github.com/EnableSecurity/wafw00f) (BSD-3-Clause). See
[NOTICE](NOTICE) for the required attribution and license text.