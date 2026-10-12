"""Unit tests for the Markdown and HTML report generators. Offline."""
from __future__ import annotations

from conftest import apivolt

META = {"tool": "APIvolt", "version": "0.1.0", "scan_date": "2026-01-01T00:00:00",
        "target": "http://127.0.0.1:8000", "spec": "spec.json", "total": 2}
FINDINGS = [
    {"severity": "CRITICAL", "category": "BFLA", "endpoint": "GET /admin",
     "title": "Low-priv user reaches admin", "detail": "detail one"},
    {"severity": "LOW", "category": "SECURITY_HEADERS", "endpoint": "Global",
     "title": "Missing: ['X-Frame-Options']", "detail": "has a | pipe and <tag>"},
]


def test_markdown_has_header_counts_and_rows():
    md = apivolt.render_markdown(FINDINGS, META)
    assert md.startswith("# APIvolt report")
    assert "Total findings: 2" in md
    assert "CRITICAL=1" in md and "LOW=1" in md
    assert "| CRITICAL | BFLA | GET /admin |" in md


def test_markdown_escapes_pipe():
    md = apivolt.render_markdown(FINDINGS, META)
    # the literal pipe in the detail must be escaped so it cannot split a cell
    assert "has a \\| pipe" in md


def test_markdown_empty():
    md = apivolt.render_markdown([], {**META, "total": 0})
    assert "no findings" in md


def test_html_is_self_contained_and_escaped():
    html = apivolt.render_html(FINDINGS, META)
    assert html.lstrip().startswith("<!doctype html>")
    assert "APIvolt report" in html
    assert "http" not in html.split("<style>")[1].split("</style>")[0]  # no external url in css
    # hostile angle brackets from a finding are escaped, not raw
    assert "<tag>" not in html
    assert "&lt;tag&gt;" in html


def test_html_severity_classes_and_chips():
    html = apivolt.render_html(FINDINGS, META)
    assert 'class="sev-critical"' in html
    assert 'class="chip chip-critical"' in html
    assert 'class="chip chip-info chip-zero"' in html  # no INFO findings -> dimmed chip
