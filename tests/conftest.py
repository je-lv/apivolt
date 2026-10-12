"""Shared fixtures: the in-process vulnerable demo server, tokens, and an engine.

No test touches the network beyond loopback; the demo server binds to an
ephemeral port on 127.0.0.1 and is torn down after the session.
"""
from __future__ import annotations

import importlib.util
import json
import sys
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


apivolt = _load("apivolt", ROOT / "apivolt.py")
demo_server = _load("demo_server", ROOT / "demo" / "vulnerable-api" / "server.py")


@pytest.fixture(scope="session")
def vuln_server():
    """Start the deliberately vulnerable demo API on a loopback ephemeral port."""
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), demo_server.Handler)
    port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        httpd.shutdown()
        httpd.server_close()


@pytest.fixture(scope="session")
def spec_file(tmp_path_factory):
    """The demo API's OpenAPI spec written to a temp file, for offline parsing."""
    path = tmp_path_factory.mktemp("spec") / "openapi.json"
    path.write_text(json.dumps(demo_server._openapi_spec()))
    return str(path)


@pytest.fixture(scope="session")
def primary_token():
    # A structurally valid, unsigned JWT (the demo accepts any decodable token).
    return apivolt.JWTUtils.encode_unsigned(
        {"alg": "HS256", "typ": "JWT"},
        {"sub": "1", "role": "user", "exp": 9999999999},
    )


@pytest.fixture(scope="session")
def secondary_token():
    return apivolt.JWTUtils.encode_unsigned(
        {"alg": "HS256", "typ": "JWT"},
        {"sub": "2", "role": "user", "exp": 9999999999},
    )


@pytest.fixture
def engine(spec_file, vuln_server, primary_token, secondary_token):
    """An APIvolt engine pointed at the demo spec and the running demo server."""
    return apivolt.APIvolt(
        spec_path=spec_file,
        base_url=vuln_server,
        jwt=primary_token,
        jwt_secondary=secondary_token,
        timeout=10,
    )
