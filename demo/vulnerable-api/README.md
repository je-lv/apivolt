# Vulnerable demo API

A deliberately vulnerable REST API, for testing APIvolt itself. It holds no
real data and runs no real database or shell: every "vulnerability" is a fixed
response, so a scan against it produces a predictable set of findings. Use it
to confirm APIvolt works end to end on your machine.

## Run it

```sh
python3 demo/vulnerable-api/server.py        # default 127.0.0.1:8000
python3 demo/vulnerable-api/server.py -p 9000
```

It serves its own OpenAPI 3 spec at `/openapi.json` and binds to `127.0.0.1`
only. The flaws are intentional; never expose it off localhost.

## Scan it

```sh
apivolt http://127.0.0.1:8000 --endpoints
T=$(python3 -c "import apivolt;print(apivolt.JWTUtils.encode_unsigned({'alg':'HS256','typ':'JWT'},{'sub':'1','role':'user'}))")
T2=$(python3 -c "import apivolt;print(apivolt.JWTUtils.encode_unsigned({'alg':'HS256','typ':'JWT'},{'sub':'2','role':'user'}))")
apivolt http://127.0.0.1:8000 --jwt "$T" --jwt-secondary "$T2" --test-all
```

## The planted flaws, and the module that catches each

| Endpoint / behavior | Flaw | Module |
|---|---|---|
| All secured endpoints answer with no token | Broken authentication | `--test-unauth` (BROKEN_AUTH) |
| A present Bearer token is checked only for JWT structure, never its signature or alg | alg:none, signature stripping, claim/role tampering, forged exp, kid injection accepted | `--test-jwt` |
| `GET /users/{id}` returns any user to any caller | BOLA / IDOR | `--test-bola` |
| `GET /users/{id}` answers every HTTP method | Method tampering | `--test-method` |
| `GET /admin/users` reachable by any token | BFLA | `--test-bfla` |
| `POST /users` echoes back any fields it is sent | Mass assignment | `--test-mass` |
| `POST /users` accepts alternate or missing Content-Type headers | Content-Type confusion | `--test-ctype` |
| `GET /search?q=` reflects `q` | Reflected XSS | `--fuzz` |
| `GET /search?q={{7*7}}` returns a fixed `49` | SSTI signal (simulated) | `--fuzz` |
| `GET /search?q=...'` returns a fixed fake SQL error string | SQLi signal (simulated) | `--fuzz` |
| No security headers on any response | Missing headers | `--test-headers` |
| The default `Server` response header identifies the implementation | Information leakage | `--test-headers` |
| No throttling under a burst | No rate limiting | `--test-rate` |

A structurally invalid token (empty, `a.b`, `...`) is still rejected with 401,
so the JWT flaw is specifically "no signature verification", not "accepts
anything". No input is ever evaluated or executed: the SSTI and SQLi responses
are hardcoded strings.
