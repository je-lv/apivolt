"""Unit tests for the pure-Python JWT utilities. Offline, no network."""
from __future__ import annotations

import base64
import json

from conftest import apivolt

JWTUtils = apivolt.JWTUtils


def _make(header, payload):
    return JWTUtils.encode_unsigned(header, payload)


def _decode_segment(segment: str) -> dict:
    pad = "=" * (-len(segment) % 4)
    return json.loads(base64.urlsafe_b64decode(segment + pad))


def test_roundtrip_decode():
    token = _make({"alg": "HS256", "typ": "JWT"}, {"sub": "7", "role": "user"})
    header, payload, sig = JWTUtils.decode(token)
    assert header["alg"] == "HS256"
    assert payload["sub"] == "7"
    assert sig == ""  # unsigned


def test_decode_rejects_malformed():
    for bad in ["", "a.b", "...", "one-part"]:
        try:
            JWTUtils.decode(bad)
        except ValueError:
            continue
        except Exception:
            continue
        raise AssertionError(f"expected decode to reject {bad!r}")


def test_forge_none_sets_alg_and_strips_signature():
    original = _make({"alg": "HS256", "typ": "JWT"}, {"sub": "1"})
    forged = JWTUtils.forge_none(original)
    header, _, sig = JWTUtils.decode(forged)
    assert header["alg"] == "none"
    assert forged.endswith(".")
    assert sig == ""


def test_forge_none_variants_cover_casings():
    original = _make({"alg": "RS256"}, {"sub": "1"})
    variants = dict(JWTUtils.forge_none_variants(original))
    assert {"none", "None", "NONE", "nOnE"} <= set(variants)
    assert "none_no_dot" in variants


def test_forge_role_escalation_injects_admin_claims():
    original = _make({"alg": "RS256"}, {"sub": "1", "role": "user"})
    labels = dict(JWTUtils.forge_role_escalation(original))
    assert any(lbl.startswith("role=") for lbl in labels)
    _, payload, _ = JWTUtils.decode(labels["role=admin"])
    assert payload["role"] == "admin"


def test_forge_expired_bypass_sets_future_exp():
    import time

    original = _make({"alg": "HS256"}, {"sub": "1", "exp": 1})
    forged = JWTUtils.forge_expired_bypass(original)
    _, payload, _ = JWTUtils.decode(forged)
    assert payload["exp"] > time.time() + 86_400 * 300  # ~300+ days ahead


def test_forge_sub_claim_changes_identity():
    original = _make({"alg": "HS256"}, {"sub": "1"})
    forged = JWTUtils.forge_sub_claim(original, "victim")
    _, payload, _ = JWTUtils.decode(forged)
    assert payload["sub"] == "victim"


def test_encode_with_hmac_is_verifiable():
    import hashlib
    import hmac as _hmac

    header, payload, key = {"alg": "HS256"}, {"sub": "1"}, b"secret"
    token = JWTUtils.encode_with_hmac(header, payload, key)
    h, p, sig = token.split(".")
    expected = base64.urlsafe_b64encode(
        _hmac.new(key, f"{h}.{p}".encode(), hashlib.sha256).digest()
    ).rstrip(b"=").decode()
    assert sig == expected


def test_analyze_flags_no_expiry():
    token = _make({"alg": "HS256"}, {"sub": "1"})  # no exp
    info = JWTUtils.analyze(token)
    assert info["valid"] is True
    assert info["algorithm"] == "HS256"
    assert info.get("no_expiry") is True


def test_analyze_detects_expired():
    token = _make({"alg": "HS256"}, {"sub": "1", "exp": 1})  # 1970
    info = JWTUtils.analyze(token)
    assert info["expired"] is True


def test_analyze_invalid_token():
    info = JWTUtils.analyze("not-a-jwt")
    assert info["valid"] is False
