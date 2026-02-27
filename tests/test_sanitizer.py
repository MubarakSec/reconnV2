from __future__ import annotations

from recon_cli.utils.sanitizer import redact, redact_json_value


def test_redact_masks_authorization_header() -> None:
    text = "Authorization: Bearer super-secret-token"
    masked = redact(text)
    assert masked is not None
    assert "super-secret-token" not in masked
    assert "***" in masked


def test_redact_json_value_masks_nested_sensitive_values() -> None:
    payload = {
        "request": {
            "headers": {"Authorization": "Bearer abc123", "X-API-Key": "top-secret"},
            "url": "https://example.com/?token=abc123&foo=ok",
        },
        "response": [{"set-cookie": "sessionid=abcdef"}, "plain text"],
        "metadata": {"safe": "value"},
    }
    masked = redact_json_value(payload)
    assert masked["request"]["headers"]["Authorization"] == "***"
    assert masked["request"]["headers"]["X-API-Key"] == "***"
    assert "abc123" not in masked["request"]["url"]
    assert masked["response"][0]["set-cookie"] == "***"
    assert masked["metadata"]["safe"] == "value"


def test_redact_json_value_handles_non_string_scalars() -> None:
    payload = {"count": 5, "ok": True, "none": None}
    assert redact_json_value(payload) == payload
