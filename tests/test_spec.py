"""Spec resolution and endpoint parsing. Offline: no server needed."""
from __future__ import annotations

import json

from conftest import apivolt


def test_resolve_local_file(spec_file):
    spec, base_url, source = apivolt.resolve_target(spec_file)
    assert spec["openapi"].startswith("3.")
    assert base_url == "http://127.0.0.1:8000"  # from the spec's servers block
    assert source == spec_file


def _engine(spec_file):
    # base_url is a placeholder; construction loads the local spec, no network.
    return apivolt.APIvolt(spec_path=spec_file, base_url="http://127.0.0.1:1", timeout=5)


def test_parse_endpoints_counts_and_methods(spec_file):
    eng = _engine(spec_file)
    seen = {(e["method"], e["path"]) for e in eng.endpoints}
    assert ("GET", "/users/{id}") in seen
    assert ("POST", "/users") in seen
    assert ("GET", "/admin/users") in seen
    assert ("GET", "/search") in seen


def test_endpoints_carry_security(spec_file):
    eng = _engine(spec_file)
    by_key = {(e["method"], e["path"]): e for e in eng.endpoints}
    assert by_key[("GET", "/users/{id}")]["security"]  # non-empty: auth required


def test_id_parameter_detected(spec_file):
    eng = _engine(spec_file)
    ep = next(e for e in eng.endpoints if e["path"] == "/users/{id}")
    assert any(eng._is_id_param(p) for p in ep["parameters"])


def test_export_findings_json(spec_file, tmp_path):
    eng = _engine(spec_file)
    eng._add_finding("HIGH", "BROKEN_AUTH", "GET /x", "title", "detail")
    out = tmp_path / "findings.json"
    eng.export_findings_json(str(out))
    data = json.loads(out.read_text())
    blob = json.dumps(data)
    assert "BROKEN_AUTH" in blob
