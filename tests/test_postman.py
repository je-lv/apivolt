"""Unit tests for the Postman -> OpenAPI converter. Offline, no network."""
from __future__ import annotations

import json

from conftest import apivolt

PostmanToOpenAPI = apivolt.PostmanToOpenAPI


COLLECTION = {
    "info": {"name": "Demo Collection", "schema":
             "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
    "variable": [
        {"key": "baseUrl", "value": "https://api.example.com"},
        {"key": "jwt", "value": "x.y.z"},
    ],
    "item": [
        {"name": "Users", "item": [
            {"name": "Get user", "request": {
                "method": "GET",
                "url": {"raw": "{{baseUrl}}/users/:id", "path": ["users", ":id"]}}},
            {"name": "Create user", "request": {
                "method": "POST",
                "url": {"raw": "{{baseUrl}}/users", "path": ["users"]},
                "body": {"mode": "raw", "raw": json.dumps({"name": "a", "email": "b"})}}},
        ]},
    ],
}


def _write(tmp_path, data):
    path = tmp_path / "collection.json"
    path.write_text(json.dumps(data))
    return str(path)


def test_convert_produces_openapi(tmp_path):
    spec = PostmanToOpenAPI(_write(tmp_path, COLLECTION)).convert()
    assert spec["openapi"].startswith("3.")
    assert spec["info"]["title"] == "Demo Collection"


def test_paths_and_methods_extracted(tmp_path):
    spec = PostmanToOpenAPI(_write(tmp_path, COLLECTION)).convert()
    paths = spec["paths"]
    # :id is converted to the OpenAPI {id} style
    assert "/users/{id}" in paths
    assert "get" in paths["/users/{id}"]
    assert "/users" in paths
    assert "post" in paths["/users"]


def test_base_url_becomes_server(tmp_path):
    spec = PostmanToOpenAPI(_write(tmp_path, COLLECTION)).convert()
    assert spec.get("servers")
    assert spec["servers"][0]["url"] == "https://api.example.com"


def test_jwt_variable_adds_bearer_security(tmp_path):
    spec = PostmanToOpenAPI(_write(tmp_path, COLLECTION)).convert()
    schemes = spec["components"]["securitySchemes"]
    assert "bearerAuth" in schemes
    assert schemes["bearerAuth"]["scheme"] == "bearer"


def test_folder_name_becomes_tag(tmp_path):
    spec = PostmanToOpenAPI(_write(tmp_path, COLLECTION)).convert()
    op = spec["paths"]["/users/{id}"]["get"]
    assert "Users" in op.get("tags", [])
