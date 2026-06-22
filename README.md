# waf-origin-check

A multi-signal tool for **verifying** candidate origin IPs behind a WAF/CDN during authorized penetration testing engagements.

Unlike a typical "origin scanner," this tool is built for **targeted verification**, not mass discovery. It assumes you already have one or more candidate IPs (from ASN/WHOIS lookups, Certificate Transparency logs, DNS history, Shodan/Censys, etc.) and need to confirm — with evidence you can put in a report — whether a given IP is actually serving the target domain's origin content, or whether it's a false positive (shared hosting, default vhost, WAF edge node reflecting your Host header, etc.).

## Why not just `curl -H "Host: ..."` and grep?

Because that approach produces false positives. A single keyword match against raw HTML can hit on:

- Shared hosting boxes that happen to contain unrelated cached/templated content
- WAF/CDN edge nodes that reflect any `Host` header back with a generic page
- Default vhost responses that coincidentally contain your search string
- Stale or minified JS bundles that include matching strings without representing the actual site

This tool was built after running into exactly that problem — a keyword match on an IP that, on manual inspection via `view-source:`, didn't actually contain the string. See [Methodology](#methodology) for why.

## How it works

For each candidate IP, the tool collects **independent signals** and reports a confidence breakdown — not a single opaque score:

| Signal | Weight | Why it's hard to fake |
|---|---|---|
| TLS certificate SAN/CN match | 40 | Requires the matching private key; can't be spoofed by a reflecting edge node |
| Structural content similarity | 30 | Full HTML diff ratio against baseline, not a single substring |
| HTTP header fingerprint | 15 | Compares `Server`, cookie names, `ETag` presence, etc. |
| Favicon hash | 15 | Binary asset hash, rarely coincidentally identical |

A **negative control** option lets you fetch the same checks against IPs you know are *not* the origin (e.g. neighboring IPs in the same subnet). If those also score high, the environment is noisy and your "match" on the real candidate should be treated with suspicion too.

## Installation

```bash
git clone https://github.com/muhammadhikmah/waf-origin-check.git
cd origin-verify
pip install aiohttp --break-system-packages   # or use a virtualenv
```

Requires Python 3.9+.

## Usage

### Verify specific candidate IPs

```bash
python3 verify_origin.py --domain example.com --candidates 1.2.3.4,1.2.3.5
```

### Verify candidates from a file (one IP per line)

```bash
python3 verify_origin.py --domain example.com --candidates-file ips.txt
```

### Verify a /24 subnet

```bash
python3 verify_origin.py --domain example.com --subnet 1.2.3.0/24
```

**Note:** subnet input is capped at `/24` (256 hosts) by design — see [Scope by design](#scope-by-design) below. Larger ranges are rejected; split them into multiple `/24` runs instead.

### With negative control (recommended)

```bash
python3 verify_origin.py \
  --domain example.com \
  --candidates 1.2.3.4 \
  --control 1.2.3.10,1.2.3.200
```

### JSON output (for reports / further tooling)

```bash
python3 verify_origin.py --domain example.com --candidates 1.2.3.4 --json > result.json
```

### All options

```
-h, --help                    Show this help message and exit

--domain DOMAIN              Target domain, no scheme
--candidates IPs             Comma-separated candidate IPs
--candidates-file FILE       One IP per line
--subnet CIDR                /24 or smaller only (max 256 hosts)
--control IPs                Comma-separated negative-control IPs (recommended)
--concurrency N              Parallel requests (default: 20)
--show-all                   Include unreachable hosts in output
--verdict TYPE               Filter results: likely, possible, unlikely, or all
--json                       JSON output instead of text report
--no-banner                  Skip the ASCII banner
```

## Example output

<img width="1122" height="526" alt="image" src="https://github.com/user-attachments/assets/28916c81-7e41-4559-a8ad-e29069a0d088" />

## Methodology

1. **Baseline first.** The tool fetches the real domain (via normal DNS) to establish a baseline: HTML, headers, favicon hash.
2. **Per-candidate, per-scheme.** Each candidate IP is checked over both HTTP and HTTPS, with the target domain sent as the `Host` header (and as SNI for HTTPS).
3. **Independent signals, not one score.** Confidence is a weighted sum of signals that don't depend on each other — a host can fail the keyword/content check but still get flagged for manual review if its TLS cert matches, or vice versa.
4. **Reachability gate.** A fast TCP connect check runs before any expensive signal (TLS handshake, full page fetch, favicon fetch), so closed ports don't waste time.
5. **Negative control.** Optional, but strongly recommended — run the same checks against IPs you *know* aren't the origin to establish what "noise" looks like in that environment before trusting a match.

## Scope by design

This tool deliberately **rejects** subnets larger than `/24` (256 hosts) when using `--subnet`. There is no flag to override this.

This is intentional, not a performance limitation. The intended workflow is:

1. Narrow down candidates passively first — Certificate Transparency logs (`crt.sh`), DNS history, ASN/WHOIS lookups, Shodan/Censys — before touching anything actively.
2. Use this tool to **verify** a small, justified set of candidates (or, at most, a single `/24` you have a specific reason to check) with full multi-signal rigor.

If you find yourself wanting to point this at a `/22` or larger, that's a sign the candidate list needs to be narrowed further upstream rather than brute-forced — both for engagement scope reasons and because broad sweeps produce noisier, less defensible results than targeted verification.

## Intended use

This tool is intended for authorized security testing — i.e., you have written permission to test the target domain and its infrastructure (a signed scope of work, pentest authorization letter, or you control the infrastructure yourself). Finding a candidate IP with high confidence does **not** by itself mean it's exploitable or that bypassing a WAF/CDN in front of it is authorized — that's a separate question requiring its own justification in your scope and report.

Do not use this tool against systems you don't have explicit authorization to test.
