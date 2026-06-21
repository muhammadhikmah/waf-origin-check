#!/usr/bin/env python3
"""
Origin IP Verification Tool
============================
Purpose: verify candidate origin IPs (sourced from ASN/WHOIS lookups, DNS
history, Certificate Transparency logs, etc.) against a target domain,
using multiple independent signals so the result doesn't depend on a
single method that's prone to false positives (e.g. Host-header
reflection on shared hosting / WAF edge nodes).

READ BEFORE USE:
- This tool VERIFIES candidate IPs you ALREADY HAVE (from ASN/WHOIS, DNS
  history, etc.) -- it is not meant for blind-scanning large IP ranges.
- Make sure the target is within your engagement's written scope.
- Finding an origin IP does NOT automatically mean it's vulnerable or
  bypassable. Confirming an origin's existence and exploiting it are two
  separate things; the latter needs its own authorization and
  justification in your report.

Signals used (independent of each other):
  1. TLS certificate SAN/CN match   -> strongest signal
  2. Structural content diff ratio  -> not just a single keyword
  3. Header fingerprint similarity
  4. Favicon hash match
  5. Negative control (IPs outside the candidate set) -> baseline noise check

Final score = a breakdown per signal, NOT one opaque number that hides
the basis for the decision. A pentest report needs a basis you can
defend signal by signal.

Install:
    pip install aiohttp --break-system-packages

Usage:
    python3 verify_origin.py --domain example.com --candidates 1.2.3.4,1.2.3.5
    python3 verify_origin.py --domain example.com --candidates-file ips.txt
    python3 verify_origin.py --domain example.com --subnet 1.2.3.0/24

--subnet limit (intentional, cannot be overridden by any flag):
    Only accepts /24 or smaller (i.e. >= /24, max 256 hosts). Larger
    subnets are REJECTED -- split them into multiple /24 runs if you
    genuinely need broader coverage.
    This is not a technical limitation, it's a deliberately enforced
    boundary so this tool stays a targeted verification tool, not a
    mass scanner.
"""

import argparse
import asyncio
import hashlib
import ipaddress
import json
import re
import socket
import ssl
import sys
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from typing import Optional

import aiohttp

TIMEOUT = aiohttp.ClientTimeout(total=10, connect=6)
UA = "Mozilla/5.0 (compatible; OriginVerify/1.0; pentest-tool)"
MAX_SUBNET_HOSTS = 256  # hard cap -- equivalent to /24, see docstring note


# ---------------------------------------------------------------------------
# Terminal colors (auto-disabled when not a TTY, e.g. when piped to a file)
# ---------------------------------------------------------------------------

class C:
    ENABLED = sys.stdout.isatty()

    @staticmethod
    def _wrap(code: str, text: str) -> str:
        if not C.ENABLED:
            return text
        return f"\033[{code}m{text}\033[0m"

    @staticmethod
    def bold(t):    return C._wrap("1", t)
    @staticmethod
    def dim(t):     return C._wrap("2", t)
    @staticmethod
    def green(t):   return C._wrap("32", t)
    @staticmethod
    def yellow(t):  return C._wrap("33", t)
    @staticmethod
    def red(t):     return C._wrap("31", t)
    @staticmethod
    def cyan(t):    return C._wrap("36", t)
    @staticmethod
    def magenta(t): return C._wrap("35", t)
    @staticmethod
    def gray(t):    return C._wrap("90", t)
    @staticmethod
    def bold_green(t):  return C._wrap("1;32", t)
    @staticmethod
    def bold_yellow(t): return C._wrap("1;33", t)
    @staticmethod
    def bold_red(t):    return C._wrap("1;31", t)
    @staticmethod
    def bold_cyan(t):   return C._wrap("1;36", t)


BANNER = r"""
  ___       _       _        __     __        _  __
 / _ \ _ __(_) __ _(_)_ __   \ \   / /__ _ __(_)/ _|_   _
| | | | '__| |/ _` | | '_ \   \ \ / / _ \ '__| | |_| | | |
| |_| | |  | | (_| | | | | |   \ V /  __/ |  | |  _| |_| |
 \___/|_|  |_|\__, |_|_| |_|    \_/ \___|_|  |_|_|  \__, |
              |___/                                 |___/
            Origin IP Verification Tool
"""


# ---------------------------------------------------------------------------
# Subnet input (intentionally capped at /24 / 256 hosts)
# ---------------------------------------------------------------------------

def parse_subnet(cidr: str) -> list:
    """
    Parse a CIDR into a list of host IPs. Hard-rejects subnets larger
    than 256 hosts (bigger than /24). This isn't about performance --
    it's a deliberate boundary so the tool doesn't turn into a generic
    mass scanner.
    """
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError as e:
        print(f"Error: invalid subnet -- {e}", file=sys.stderr)
        sys.exit(1)

    hosts = list(net.hosts())
    if len(hosts) == 0:
        # /31 or /32 -- .hosts() can be empty for these
        hosts = [net.network_address] if net.num_addresses == 1 else list(net)

    if len(hosts) > MAX_SUBNET_HOSTS:
        print(
            f"Error: subnet {cidr} contains {len(hosts)} hosts, exceeding the "
            f"{MAX_SUBNET_HOSTS}-host limit (equivalent to /24).\n"
            f"This tool is deliberately capped at /24 or smaller so it stays "
            f"targeted verification rather than a mass scan.\n"
            f"Split larger ranges into multiple /24 runs instead.",
            file=sys.stderr,
        )
        sys.exit(1)

    return [str(ip) for ip in hosts]


async def quick_tcp_check(ip: str, port: int, timeout: float = 2.5) -> bool:
    """Fast check for whether a port is open, run before any expensive
    signal (TLS handshake, HTML fetch, favicon fetch). This significantly
    speeds up /24 runs since many hosts simply aren't listening at all."""
    try:
        fut = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(fut, timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class FetchResult:
    ok: bool = False
    status: Optional[int] = None
    html: str = ""
    headers: dict = field(default_factory=dict)
    error: Optional[str] = None


@dataclass
class TLSResult:
    ok: bool = False
    san_names: list = field(default_factory=list)
    cn: Optional[str] = None
    issuer: Optional[str] = None
    error: Optional[str] = None


@dataclass
class SignalScore:
    name: str
    matched: bool
    detail: str
    weight: float


VERDICT_LIKELY = "LIKELY_ORIGIN"
VERDICT_POSSIBLE = "POSSIBLE"
VERDICT_UNLIKELY = "UNLIKELY"

VERDICT_LABELS = {
    VERDICT_LIKELY: "LIKELY ORIGIN",
    VERDICT_POSSIBLE: "POSSIBLE (needs manual review)",
    VERDICT_UNLIKELY: "LIKELY NOT ORIGIN (shared host / CDN edge / false positive)",
}


@dataclass
class CandidateReport:
    ip: str
    scheme: str
    signals: list = field(default_factory=list)
    fetch: Optional[FetchResult] = None
    tls: Optional[TLSResult] = None
    favicon_hash: Optional[str] = None

    @property
    def total_weight(self) -> float:
        return sum(s.weight for s in self.signals if s.matched)

    @property
    def max_weight(self) -> float:
        return sum(s.weight for s in self.signals)

    @property
    def confidence(self) -> float:
        if self.max_weight == 0:
            return 0.0
        return round(self.total_weight / self.max_weight, 3)

    @property
    def reachable(self) -> bool:
        return bool(self.fetch and self.fetch.ok and (self.fetch.status or 0) < 400)

    @property
    def verdict_key(self) -> str:
        if not self.reachable:
            return VERDICT_UNLIKELY
        if self.confidence >= 0.75:
            return VERDICT_LIKELY
        if self.confidence >= 0.4:
            return VERDICT_POSSIBLE
        return VERDICT_UNLIKELY

    @property
    def verdict(self) -> str:
        return VERDICT_LABELS[self.verdict_key]


# ---------------------------------------------------------------------------
# HTTP fetch
# ---------------------------------------------------------------------------

async def fetch_html(session: aiohttp.ClientSession, ip: str, scheme: str,
                      host: str, path: str = "/") -> FetchResult:
    url = f"{scheme}://{ip}{path}"
    headers = {"Host": host, "User-Agent": UA, "Accept": "text/html,*/*"}
    ssl_ctx = False
    if scheme == "https":
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ssl_ctx = ctx
    try:
        async with session.get(url, headers=headers, timeout=TIMEOUT,
                                ssl=ssl_ctx, allow_redirects=False) as r:
            text = await r.text(errors="ignore")
            return FetchResult(ok=True, status=r.status, html=text,
                                headers=dict(r.headers))
    except Exception as e:
        return FetchResult(ok=False, error=str(e))


# ---------------------------------------------------------------------------
# TLS certificate inspection (the strongest signal)
# ---------------------------------------------------------------------------

def get_tls_cert_names(ip: str, sni_host: str, port: int = 443,
                        timeout: float = 6.0) -> TLSResult:
    """
    Fetch the TLS certificate directly from the IP, using the target
    domain as SNI. If this IP is genuinely the origin (or at least
    covered by the same cert), the domain name will show up in the
    SAN/CN -- this is hard to fake without the matching private key.
    """
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=sni_host) as ssock:
                cert = ssock.getpeercert()

        if not cert:
            return TLSResult(ok=False, error="no cert returned")

        sans = []
        for typ, val in cert.get("subjectAltName", []):
            if typ == "DNS":
                sans.append(val)

        cn = None
        for field_set in cert.get("subject", []):
            for k, v in field_set:
                if k == "commonName":
                    cn = v

        issuer = None
        for field_set in cert.get("issuer", []):
            for k, v in field_set:
                if k == "organizationName":
                    issuer = v

        return TLSResult(ok=True, san_names=sans, cn=cn, issuer=issuer)

    except Exception as e:
        return TLSResult(ok=False, error=str(e))


def domain_in_cert(domain: str, tls: TLSResult) -> bool:
    if not tls.ok:
        return False
    names = list(tls.san_names)
    if tls.cn:
        names.append(tls.cn)
    domain = domain.lower()
    for n in names:
        n = n.lower()
        if n == domain:
            return True
        # wildcard match: *.example.com matches sub.example.com
        if n.startswith("*."):
            base = n[2:]
            if domain == base or domain.endswith("." + base):
                return True
    return False


# ---------------------------------------------------------------------------
# Content structural comparison
# ---------------------------------------------------------------------------

def strip_volatile(html: str) -> str:
    """Strip parts that commonly change between requests (csrf token,
    timestamp, nonce, etc.) so the diff isn't biased by that noise."""
    html = re.sub(r'(?i)(csrf[-_]?token|nonce|timestamp)["\']?\s*[:=]\s*["\']?[\w\-]+',
                   "", html)
    html = re.sub(r"\s+", " ", html)
    return html.strip()


def structural_similarity(base_html: str, candidate_html: str) -> float:
    a = strip_volatile(base_html)
    b = strip_volatile(candidate_html)
    if not a or not b:
        return 0.0
    # quick_ratio is sufficient for large HTML, faster than the full ratio
    return SequenceMatcher(None, a, b).quick_ratio()


# ---------------------------------------------------------------------------
# Header fingerprint comparison
# ---------------------------------------------------------------------------

FINGERPRINT_HEADERS = ["server", "x-powered-by", "etag", "set-cookie",
                        "x-aspnet-version", "x-generator"]


def header_fingerprint(headers: dict) -> dict:
    out = {}
    lower = {k.lower(): v for k, v in headers.items()}
    for h in FINGERPRINT_HEADERS:
        if h in lower:
            # for set-cookie / etag, only keep cookie names / presence,
            # not the value, since that's expected to change per request
            if h == "set-cookie":
                names = re.findall(r"([\w\-]+)=", lower[h])
                out[h] = sorted(set(names))
            elif h == "etag":
                out[h] = "present"
            else:
                out[h] = lower[h]
    return out


def header_similarity(base: dict, cand: dict) -> float:
    if not base and not cand:
        return 0.0
    keys = set(base.keys()) | set(cand.keys())
    if not keys:
        return 0.0
    matches = sum(1 for k in keys if base.get(k) == cand.get(k))
    return matches / len(keys)


# ---------------------------------------------------------------------------
# Favicon hash
# ---------------------------------------------------------------------------

async def fetch_favicon_hash(session: aiohttp.ClientSession, ip: str,
                              scheme: str, host: str) -> Optional[str]:
    url = f"{scheme}://{ip}/favicon.ico"
    headers = {"Host": host, "User-Agent": UA}
    ssl_ctx = False
    if scheme == "https":
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ssl_ctx = ctx
    try:
        async with session.get(url, headers=headers, timeout=TIMEOUT,
                                ssl=ssl_ctx) as r:
            if r.status != 200:
                return None
            data = await r.read()
            if not data:
                return None
            return hashlib.md5(data).hexdigest()
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Core verification per candidate
# ---------------------------------------------------------------------------

async def verify_candidate(session: aiohttp.ClientSession, ip: str, domain: str,
                            base: dict, scheme: str,
                            skip_tcp_check: bool = False) -> CandidateReport:
    report = CandidateReport(ip=ip, scheme=scheme)

    port = 443 if scheme == "https" else 80
    if not skip_tcp_check:
        port_open = await quick_tcp_check(ip, port)
        if not port_open:
            report.signals.append(SignalScore(
                "http_reachable", False, f"port {port} closed/filtered", weight=0))
            return report

    fetch = await fetch_html(session, ip, scheme, domain)
    report.fetch = fetch

    if not fetch.ok or fetch.status is None or fetch.status >= 400:
        report.signals.append(SignalScore(
            "http_reachable", False,
            f"status={fetch.status} error={fetch.error}", weight=0))
        return report  # no point checking other signals if unreachable

    # Signal: domain reference sanity check (a gate, not a primary score)
    has_domain_ref = domain.lower() in fetch.html.lower()

    # Signal 1: TLS cert (only relevant for https)
    if scheme == "https":
        tls = get_tls_cert_names(ip, domain)
        report.tls = tls
        matched = domain_in_cert(domain, tls)
        detail = f"SAN={tls.san_names} CN={tls.cn}" if tls.ok else f"error={tls.error}"
        report.signals.append(SignalScore("tls_cert_match", matched, detail, weight=40))

    # Signal 2: structural content similarity
    sim = structural_similarity(base["html"], fetch.html)
    report.signals.append(SignalScore(
        "content_structural_similarity", sim >= 0.85,
        f"ratio={sim:.3f}", weight=30))

    # Signal 3: header fingerprint
    cand_fp = header_fingerprint(fetch.headers)
    hsim = header_similarity(base["headers_fp"], cand_fp)
    report.signals.append(SignalScore(
        "header_fingerprint", hsim >= 0.6,
        f"sim={hsim:.2f} headers={cand_fp}", weight=15))

    # Signal 4: favicon hash
    fav = await fetch_favicon_hash(session, ip, scheme, domain)
    report.favicon_hash = fav
    fav_match = fav is not None and fav == base.get("favicon_hash")
    report.signals.append(SignalScore(
        "favicon_hash", fav_match, f"hash={fav}", weight=15))

    # Gate: if the domain isn't referenced anywhere AND content similarity
    # is also weak, this is likely a default vhost / shared host response
    if not has_domain_ref and sim < 0.5:
        report.signals.append(SignalScore(
            "domain_reference_sanity", False,
            "domain not referenced & content not similar -> likely default vhost",
            weight=0))

    return report


async def get_baseline(session: aiohttp.ClientSession, domain: str) -> dict:
    """Fetch the real domain (via normal DNS) to use as a comparison baseline."""
    fetch = await fetch_html(session, domain, "https", domain)
    if not fetch.ok:
        fetch = await fetch_html(session, domain, "http", domain)
    fav = await fetch_favicon_hash(session, domain, "https", domain)
    return {
        "html": fetch.html,
        "headers_fp": header_fingerprint(fetch.headers),
        "favicon_hash": fav,
        "status": fetch.status,
    }


# ---------------------------------------------------------------------------
# Negative control — checks baseline noise in the same environment
# ---------------------------------------------------------------------------

async def negative_control(session: aiohttp.ClientSession, domain: str,
                            base: dict, control_ips: list) -> list:
    """
    Fetch IPs that are NOT candidates (e.g. neighboring IPs in the same
    subnet, or random public IPs) using the same Host header. If these
    ALSO score high, the environment is noisy (shared hosting / a WAF
    that reflects any Host header) and the main candidate's match should
    be treated with suspicion too, not trusted outright.
    """
    results = []
    for ip in control_ips:
        r = await verify_candidate(session, ip, domain, base, "https")
        results.append(r)
    return results


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def verdict_style(key: str, text: str) -> str:
    if key == VERDICT_LIKELY:
        return C.bold_green(text)
    if key == VERDICT_POSSIBLE:
        return C.bold_yellow(text)
    return C.bold_red(text)


def confidence_bar(confidence: float, width: int = 20) -> str:
    filled = round(confidence * width)
    bar = "█" * filled + "░" * (width - filled)
    pct = f"{confidence:.0%}"
    if confidence >= 0.75:
        return C.green(bar) + f" {pct}"
    if confidence >= 0.4:
        return C.yellow(bar) + f" {pct}"
    return C.red(bar) + f" {pct}"


def _pad(text: str, width: int) -> str:
    """Pad a plain (uncolored) string to width, return the padding only.
    Use this instead of Python's :<N on already-colored strings, since
    ANSI escape codes inflate the apparent string length and break
    alignment."""
    pad_len = max(0, width - len(text))
    return " " * pad_len


BOX_WIDTH = 68


def print_report(report: CandidateReport):
    key = report.verdict_key
    label = VERDICT_LABELS[key]

    ip_scheme_plain = f"{report.ip}  {report.scheme.upper()}"
    label_plain = label

    print()
    print(C.dim("┌" + "─" * BOX_WIDTH + "┐"))
    print(f"{C.dim('│')} {C.bold(report.ip)}  {C.cyan(report.scheme.upper())}"
          f"{_pad(ip_scheme_plain, BOX_WIDTH - 1)}{C.dim('│')}")
    print(f"{C.dim('│')} {verdict_style(key, label)}"
          f"{_pad(label_plain, BOX_WIDTH - 1)}{C.dim('│')}")

    if not report.reachable:
        err = report.fetch.error if report.fetch else "n/a"
        status = report.fetch.status if report.fetch else None
        detail_plain = f"unreachable -- status={status} error={err}"
        print(C.dim("├" + "─" * BOX_WIDTH + "┤"))
        print(f"{C.dim('│')} {C.gray(detail_plain)}"
              f"{_pad(detail_plain, BOX_WIDTH - 1)}{C.dim('│')}")
        print(C.dim("└" + "─" * BOX_WIDTH + "┘"))
        return

    print(C.dim("├" + "─" * BOX_WIDTH + "┤"))
    conf_plain = f"confidence  {'█' * round(report.confidence * 20)}{'░' * (20 - round(report.confidence * 20))} {report.confidence:.0%}"
    print(f"{C.dim('│')} confidence  {confidence_bar(report.confidence)}"
          f"{_pad(conf_plain, BOX_WIDTH - 1)}{C.dim('│')}")
    print(C.dim("├" + "─" * BOX_WIDTH + "┤"))
    for s in report.signals:
        mark_plain = "✓" if s.matched else "✗"
        mark = C.green(mark_plain) if s.matched else C.gray(mark_plain)
        name = f"{s.name:<28}"
        detail_short = s.detail[:26]
        line_plain = f"{mark_plain} {name} w={s.weight:>2}  {detail_short}"
        print(f"{C.dim('│')} {mark} {name} {C.dim(f'w={s.weight:>2}')}  "
              f"{C.dim(detail_short)}{_pad(line_plain, BOX_WIDTH - 1)}{C.dim('│')}")
    print(C.dim("└" + "─" * BOX_WIDTH + "┘"))


def to_json(reports: list) -> str:
    out = []
    for r in reports:
        out.append({
            "ip": r.ip,
            "scheme": r.scheme,
            "verdict": r.verdict_key,
            "verdict_label": r.verdict,
            "confidence": r.confidence,
            "http_status": r.fetch.status if r.fetch else None,
            "signals": [
                {"name": s.name, "matched": s.matched, "detail": s.detail,
                 "weight": s.weight}
                for s in r.signals
            ],
        })
    return json.dumps(out, indent=2, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

async def main():
    ap = argparse.ArgumentParser(
        description="Verify candidate origin IPs against a target domain "
                     "using multiple independent signals.")
    ap.add_argument("--domain", required=True, help="Target domain, no scheme")
    ap.add_argument("--candidates", help="Comma-separated candidate IPs")
    ap.add_argument("--candidates-file", help="File with one IP per line")
    ap.add_argument("--subnet", help="CIDR, /24 or smaller only (max 256 hosts). "
                                      "Example: 103.65.96.0/24")
    ap.add_argument("--control", help="Comma-separated negative-control IPs. "
                                       "Optional but recommended.")
    ap.add_argument("--concurrency", type=int, default=20,
                     help="Number of IPs processed in parallel (default 20). "
                          "Kept low so the target isn't flooded.")
    ap.add_argument("--show-all", action="store_true",
                     help="Include unreachable hosts in the output.")
    ap.add_argument("--verdict", choices=["likely", "possible", "unlikely", "all"],
                     default="all",
                     help="Only show results matching this verdict "
                          "(default: all reachable results).")
    ap.add_argument("--json", action="store_true", help="JSON output")
    ap.add_argument("--no-banner", action="store_true", help="Skip the ASCII banner")
    args = ap.parse_args()

    candidates = []
    if args.candidates:
        candidates += [c.strip() for c in args.candidates.split(",") if c.strip()]
    if args.candidates_file:
        with open(args.candidates_file) as f:
            candidates += [line.strip() for line in f if line.strip()]
    if args.subnet:
        subnet_ips = parse_subnet(args.subnet)
        candidates += subnet_ips

    if not candidates:
        print("Error: provide --candidates, --candidates-file, or --subnet",
              file=sys.stderr)
        sys.exit(1)

    control_ips = []
    if args.control:
        control_ips = [c.strip() for c in args.control.split(",") if c.strip()]

    if not args.json and not args.no_banner:
        print(C.cyan(BANNER))

    sem = asyncio.Semaphore(max(1, args.concurrency))

    async def bounded_verify(session, ip, domain, base, scheme):
        async with sem:
            return await verify_candidate(session, ip, domain, base, scheme)

    connector = aiohttp.TCPConnector(limit=args.concurrency, ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        if not args.json:
            print(C.bold(f"[*] Fetching baseline from https://{args.domain} ..."))
        base = await get_baseline(session, args.domain)
        if not base["html"]:
            print("[!] Failed to fetch baseline from the real domain. "
                  "Check connectivity / domain validity.", file=sys.stderr)
            sys.exit(1)
        if not args.json:
            print(C.dim(f"    status={base['status']}  html_len={len(base['html'])}  "
                        f"favicon={base['favicon_hash']}"))
            if args.subnet:
                print(C.bold(f"[*] Subnet {args.subnet} -> {len(candidates)} hosts "
                              f"(within the {MAX_SUBNET_HOSTS}-host cap)"))
            print(C.bold(f"[*] Verifying {len(candidates)} candidate IP(s) "
                          f"(concurrency={args.concurrency})...\n"))

        tasks = []
        for ip in candidates:
            for scheme in ("https", "http"):
                tasks.append(bounded_verify(session, ip, args.domain, base, scheme))

        reports = []
        done = 0
        for coro in asyncio.as_completed(tasks):
            r = await coro
            reports.append(r)
            done += 1
            if not args.json and done % 50 == 0:
                print(C.gray(f"    ... {done}/{len(tasks)} fetches done"))

        if control_ips:
            if not args.json:
                print(C.bold(f"\n[*] Running negative control against "
                              f"{len(control_ips)} comparison IP(s)..."))
            control_reports = await negative_control(session, args.domain, base,
                                                       control_ips)
        else:
            control_reports = []

    # ---- filtering for display ----
    verdict_filter_map = {
        "likely": VERDICT_LIKELY,
        "possible": VERDICT_POSSIBLE,
        "unlikely": VERDICT_UNLIKELY,
    }

    display_reports = reports
    if not args.show_all:
        display_reports = [r for r in display_reports if r.reachable]

    if args.verdict != "all":
        wanted = verdict_filter_map[args.verdict]
        display_reports = [r for r in display_reports if r.verdict_key == wanted]

    hidden = len(reports) - len(display_reports)

    if args.json:
        print(to_json(display_reports))
    else:
        display_reports.sort(key=lambda r: r.confidence, reverse=True)
        for r in display_reports:
            print_report(r)

        if not display_reports:
            print(C.gray(f"\n[*] No results match the current filter "
                          f"(--verdict {args.verdict})."))

        if hidden:
            print(C.gray(f"\n[*] {hidden} fetch attempt(s) hidden by current "
                          f"filters. Use --show-all and/or --verdict all to see "
                          f"everything."))

        if control_reports:
            print(C.bold_cyan("\n\n" + "═" * 70))
            print(C.bold_cyan("  NEGATIVE CONTROL (non-candidate IPs)"))
            print(C.bold_cyan("═" * 70))
            print(C.gray("  If these ALSO score high, the environment is noisy --"))
            print(C.gray("  treat the main candidate's match with suspicion too.\n"))
            for r in control_reports:
                print_report(r)

    high_confidence = [r for r in reports if r.verdict_key == VERDICT_LIKELY]
    possible = [r for r in reports if r.verdict_key == VERDICT_POSSIBLE]

    if not args.json:
        print(C.bold("\n\n" + "─" * 70))
        print(C.bold(f" SUMMARY"))
        print(C.bold("─" * 70))
        print(f" {C.bold_green(str(len(high_confidence)))} likely origin   "
              f"{C.bold_yellow(str(len(possible)))} possible   "
              f"out of {len(reports)} fetch attempts")
        for r in sorted(high_confidence, key=lambda r: r.confidence, reverse=True):
            print(f"   {C.bold_green('●')} {r.ip:<16} ({r.scheme})  "
                  f"confidence={r.confidence:.0%}")
        for r in sorted(possible, key=lambda r: r.confidence, reverse=True):
            print(f"   {C.bold_yellow('●')} {r.ip:<16} ({r.scheme})  "
                  f"confidence={r.confidence:.0%}")
        if not high_confidence and not possible:
            print(C.gray(" No high-confidence or possible candidates. The origin "
                          "may not be directly reachable from the checked IPs, "
                          "or these genuinely aren't the origin."))


if __name__ == "__main__":
    asyncio.run(main())
