#!/usr/bin/env python3
"""A deliberately vulnerable REST API, for testing APIvolt itself.

Everything this server does is fake. It holds no real data and runs no real
database or shell. It exists only so a scan against it produces a predictable
set of findings, to confirm APIvolt works end to end on your machine.

Run it, then scan it:

    python3 demo/vulnerable-api/server.py              # prints the port it binds
    apivolt http://127.0.0.1:8000 --endpoints          # auto-discovers /openapi.json
    apivolt http://127.0.0.1:8000 --jwt <t> --jwt-secondary <t2> --test-all

It serves its own OpenAPI 3 spec at /openapi.json and binds to 127.0.0.1 only.
The vulnerabilities are intentional; never expose this server off localhost.

The deliberate flaws, and the APIvolt module that catches each one:

  - Endpoints declare `security` in the spec but serve 2xx with no token
    (test_unauth, BROKEN_AUTH).
  - A Bearer token is "accepted" whenever it merely decodes as a JWT: the
    signature and `alg` are never verified, so alg:none, signature stripping,
    claim/role tampering and a forged future `exp` all pass
    (test_jwt: JWT_ALG_NONE, JWT_SIG_STRIP, JWT_ROLE_ESCALATION, ...).
    Structurally invalid tokens (empty, "a.b", "...") are still rejected, so
    the flaw is "no signature verification", not "accepts anything".
  - GET /users/{id} returns any user to any caller (test_bola, BOLA/IDOR) and
    answers every HTTP method (test_method_tampering, METHOD_TAMPERING).
  - GET /admin/users is reachable by any token (test_bfla, BFLA).
  - POST /users echoes back whatever fields it is sent, including injected
    role/is_admin fields (test_mass_assignment, MASS_ASSIGNMENT).
  - GET /search reflects its `q` parameter (fuzz XSS), returns a hardcoded
    "49" for a `{{7*7}}`-style value (fuzz SSTI) and a hardcoded fake SQL
    error string when `q` contains a quote (fuzz SQLi). No input is ever
    evaluated or run; these are fixed strings.
  - No security headers are ever sent (test_security_headers) and there is no
    rate limiting (test_rate_limit).
"""
from __future__ import annotations

import argparse
import base64
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DEFAULT_PORT = 8000

_USERS = {
    "1": {"id": 1, "name": "Alice Example", "email": "alice@example.com", "role": "user"},
    "2": {"id": 2, "name": "Bob Example", "email": "bob@example.com", "role": "user"},
    "99": {"id": 99, "name": "Admin Example", "email": "admin@example.com", "role": "admin"},
}


def _looks_like_jwt(authorization: str | None) -> bool:
    """Accept a token whenever it structurally decodes as a JWT.

    This is the intentional flaw: the signature and `alg` header are never
    checked, so any decodable token (including alg:none and signature-stripped
    ones) is treated as valid. A non-JWT string is still rejected.
    """
    if not authorization or not authorization.lower().startswith("bearer "):
        return False
    token = authorization[7:].strip()
    parts = token.split(".")
    if len(parts) != 3:
        return False
    try:
        for segment in parts[:2]:
            pad = "=" * (-len(segment) % 4)
            json.loads(base64.urlsafe_b64decode(segment + pad))
        return True
    except Exception:
        return False


def _openapi_spec() -> dict:
    secured = [{"bearerAuth": []}]
    return {
        "openapi": "3.0.3",
        "info": {"title": "APIvolt Vulnerable Demo API", "version": "0.1.0",
                 "description": "Intentionally vulnerable. For testing APIvolt only."},
        "servers": [{"url": "http://127.0.0.1:%d" % DEFAULT_PORT}],
        "components": {"securitySchemes": {"bearerAuth": {
            "type": "http", "scheme": "bearer", "bearerFormat": "JWT"}}},
        "security": secured,
        "paths": {
            "/users/{id}": {"get": {
                "tags": ["users"], "summary": "Get a user by id", "security": secured,
                "parameters": [{"name": "id", "in": "path", "required": True,
                                "schema": {"type": "integer"}}],
                "responses": {"200": {"description": "A user"}}}},
            "/users": {"post": {
                "tags": ["users"], "summary": "Create a user", "security": secured,
                "requestBody": {"required": True, "content": {"application/json": {"schema": {
                    "type": "object",
                    "properties": {"name": {"type": "string"}, "email": {"type": "string"}},
                    "required": ["name", "email"]}}}},
                "responses": {"201": {"description": "Created"}}}},
            "/admin/users": {"get": {
                "tags": ["admin"], "summary": "List all users (admin only)", "security": secured,
                "responses": {"200": {"description": "All users"}}}},
            "/search": {"get": {
                "tags": ["search"], "summary": "Search", "security": secured,
                "parameters": [{"name": "q", "in": "query", "required": False,
                                "schema": {"type": "string"}}],
                "responses": {"200": {"description": "Results"}}}},
        },
    }


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):  # quiet by default
        pass

    def _send(self, code: int, payload):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        # Intentionally no security headers and no rate limiting.
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _read_body(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if not length:
            return {}
        try:
            return json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            return {}

    def _path_and_query(self):
        if "?" not in self.path:
            return self.path, {}
        path, _, raw = self.path.partition("?")
        query = {}
        for pair in raw.split("&"):
            if "=" in pair:
                k, _, v = pair.partition("=")
                query[k] = _url_unquote(v)
        return path, query

    def _route(self):
        path, query = self._path_and_query()

        if path == "/openapi.json" and self.command == "GET":
            return self._send(200, _openapi_spec())

        # Intentional auth flaw: a request with NO token is served (broken
        # access control), but a token that IS present is checked only for JWT
        # structure, never its signature or alg. So alg:none and signature
        # stripping pass, while a non-JWT string is rejected with 401.
        authorization = self.headers.get("Authorization")
        if authorization is not None and not _looks_like_jwt(authorization):
            return self._send(401, {"error": "invalid token"})

        # /search: reflects input; fakes SSTI and SQLi with fixed strings only.
        if path == "/search":
            q = query.get("q", "")
            if "'" in q or '"' in q:
                return self._send(200, {"error": "You have an error in your SQL syntax near '%s'" % q})
            if any(tpl in q for tpl in ("{{7*7}}", "${7*7}", "#{7*7}")):
                return self._send(200, {"results": [], "echo": "49"})
            return self._send(200, {"results": [], "echo": q})  # reflects q verbatim (XSS)

        # /admin/users: no privilege check (BFLA) and no real auth gate.
        if path == "/admin/users":
            return self._send(200, {"users": list(_USERS.values())})

        # /users/{id}: returns any user to anyone (BOLA), any method (tampering).
        if path.startswith("/users/"):
            uid = path.split("/users/", 1)[1].strip("/")
            user = _USERS.get(uid, {"id": uid, "name": "User %s" % uid,
                                    "email": "user%s@example.com" % uid, "role": "user"})
            return self._send(200, user)

        # POST /users: echoes the posted body back, injected fields and all.
        if path == "/users" and self.command in ("POST", "PUT", "PATCH"):
            body = self._read_body()
            created = {"id": 1000, "created": True}
            created.update(body)  # mass assignment: no allow-list
            return self._send(201, created)

        return self._send(404, {"error": "not found", "path": path})

    # Every method routes the same way (enables method-tampering findings).
    def do_GET(self):
        self._route()

    do_POST = do_GET
    do_PUT = do_GET
    do_PATCH = do_GET
    do_DELETE = do_GET
    do_HEAD = do_GET
    do_OPTIONS = do_GET


def _url_unquote(value: str) -> str:
    from urllib.parse import unquote_plus
    return unquote_plus(value)


def main() -> int:
    parser = argparse.ArgumentParser(description="APIvolt deliberately vulnerable demo API")
    parser.add_argument("-p", "--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--host", default="127.0.0.1",
                        help="bind address (default 127.0.0.1; do not change for a real network)")
    args = parser.parse_args()

    httpd = ThreadingHTTPServer((args.host, args.port), Handler)
    bound_port = httpd.server_address[1]
    print("APIvolt vulnerable demo API on http://%s:%d" % (args.host, bound_port))
    print("Spec at http://%s:%d/openapi.json  (Ctrl+C to stop)" % (args.host, bound_port))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopping")
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
