import json

import pytest

from app.core import openapi_parser


def _write_spec(path):
    path.write_text(
        json.dumps(
            {
                "openapi": "3.0.3",
                "servers": [{"url": "https://api.example.test"}],
                "paths": {
                    "/users/{id}": {
                        "get": {"tags": ["users"]},
                    },
                    "/admin/users": {
                        "post": {
                            "tags": ["administration"],
                            "requestBody": {
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "type": "object",
                                            "properties": {
                                                "email": {
                                                    "type": "string",
                                                    "format": "email",
                                                },
                                                "enabled": {"type": "boolean"},
                                            },
                                        }
                                    }
                                }
                            },
                        }
                    },
                },
            }
        ),
        encoding="utf-8",
    )


def test_parser_discovers_endpoints_and_admin_context(tmp_path, monkeypatch):
    monkeypatch.setattr(openapi_parser, "ALLOWED_BASE_DIR", str(tmp_path))
    spec_path = tmp_path / "openapi.json"
    _write_spec(spec_path)

    endpoints = openapi_parser.OpenAPIParser(str(spec_path)).parse()

    assert endpoints[0]["path"] == "https://api.example.test/users/{id}"
    assert endpoints[0]["is_admin"] is False
    assert endpoints[1]["is_admin"] is True
    assert endpoints[1]["body"] == {
        "email": "test@example.com",
        "enabled": True,
    }


def test_parser_blocks_file_outside_allowed_directory(tmp_path, monkeypatch):
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    outside = tmp_path / "allowed-escape.json"
    _write_spec(outside)
    monkeypatch.setattr(openapi_parser, "ALLOWED_BASE_DIR", str(allowed))

    with pytest.raises(ValueError, match="outside the allowed base directory"):
        openapi_parser.OpenAPIParser(str(outside))


def test_remote_specs_verify_tls_by_default(monkeypatch):
    response = type(
        "Response",
        (),
        {
            "is_redirect": False,
            "is_permanent_redirect": False,
            "text": json.dumps({"openapi": "3.0.3", "paths": {}}),
            "raise_for_status": lambda self: None,
        },
    )()
    captured = {}

    monkeypatch.setattr(
        openapi_parser.socket, "gethostbyname", lambda _: "93.184.216.34"
    )

    def fake_get(*args, **kwargs):
        captured.update(kwargs)
        return response

    monkeypatch.setattr(openapi_parser.requests, "get", fake_get)
    monkeypatch.delenv("BOLA_ALLOW_INSECURE_TLS", raising=False)

    openapi_parser.OpenAPIParser("https://example.com/openapi.json")

    assert captured["verify"] is True
    assert captured["allow_redirects"] is False
