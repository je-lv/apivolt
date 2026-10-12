"""Integration tests: each module run against the vulnerable demo server
produces the finding it is supposed to catch. Loopback only."""
from __future__ import annotations


def _cats(engine):
    return {f["category"] for f in engine.findings}


def test_unauth_flags_broken_auth(engine):
    engine.test_unauth()
    assert "BROKEN_AUTH" in _cats(engine)


def test_bola_flags_idor(engine):
    engine.test_bola()
    assert "BOLA/IDOR" in _cats(engine)


def test_bfla_flags_admin_access(engine):
    engine.test_bfla()
    assert "BFLA" in _cats(engine)


def test_mass_assignment_flags_injected_fields(engine):
    engine.test_mass_assignment()
    assert "MASS_ASSIGNMENT" in _cats(engine)


def test_method_tampering(engine):
    engine.test_method_tampering()
    assert "METHOD_TAMPERING" in _cats(engine)


def test_security_headers_missing(engine):
    engine.test_security_headers()
    assert "SECURITY_HEADERS" in _cats(engine)


def test_rate_limit_absent(engine):
    engine.test_rate_limit(burst=12)
    assert "RATE_LIMITING" in _cats(engine)


def test_jwt_accepts_forged_tokens_but_not_garbage(engine):
    engine.test_jwt()
    cats = _cats(engine)
    # No signature verification: alg:none and signature stripping are accepted.
    assert "JWT_ALG_NONE" in cats
    assert "JWT_SIG_STRIP" in cats
    # Structurally invalid tokens are still rejected, so this must NOT fire.
    assert "JWT_MALFORMED" not in cats


def test_fuzz_finds_reflection_ssti_and_sqli(engine):
    engine.fuzz_endpoints(categories=["xss", "ssti", "sqli"])
    cats = _cats(engine)
    assert "INJECTION_XSS" in cats
    assert "INJECTION_SSTI" in cats
    assert "INJECTION_SQLI" in cats
