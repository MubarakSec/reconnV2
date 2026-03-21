import pytest
from recon_cli.db.schemas import validate_result


def test_validate_finding():
    finding = {
        "type": "finding",
        "finding_type": "xss",
        "severity": "high",
        "hostname": "example.com",
        "url": "https://example.com/xss",
    }
    validated = validate_result(finding)
    assert validated["type"] == "finding"
    assert validated["finding_type"] == "xss"
    assert validated["severity"] == "high"
    assert "timestamp" in validated


def test_validate_signal():
    signal = {
        "type": "signal",
        "signal_id": "sig_123",
        "signal_type": "new_host",
        "target_type": "host",
        "target": "example.com",
    }
    validated = validate_result(signal)
    assert validated["type"] == "signal"
    assert validated["signal_id"] == "sig_123"
    assert validated["signal_type"] == "new_host"


def test_validate_host():
    host = {
        "type": "hostname",
        "hostname": "example.com",
        "resolved": True,
    }
    validated = validate_result(host)
    assert validated["type"] == "hostname"
    assert validated["hostname"] == "example.com"
    assert validated["resolved"] is True


def test_validate_extra_fields_preserved():
    finding = {
        "type": "finding",
        "finding_type": "xss",
        "extra_field": "preserved",
    }
    validated = validate_result(finding)
    assert validated["extra_field"] == "preserved"


def test_invalid_type_fails():
    with pytest.raises(Exception):
        validate_result({"type": "invalid_type"})


def test_missing_required_fields_fails():
    with pytest.raises(Exception):
        # Missing finding_type
        validate_result({"type": "finding"})


def test_validate_parameter():
    param = {
        "type": "parameter",
        "name": "user_id",
        "source": "spider",
    }
    validated = validate_result(param)
    assert validated["type"] == "parameter"
    assert validated["name"] == "user_id"


def test_validate_cms():
    cms = {
        "type": "cms",
        "hostname": "example.com",
        "cms": "wordpress",
    }
    validated = validate_result(cms)
    assert validated["type"] == "cms"
    assert validated["cms"] == "wordpress"


def test_validate_screenshot():
    shot = {
        "type": "screenshot",
        "screenshot_path": "/tmp/shot.png",
        "url": "https://example.com",
    }
    validated = validate_result(shot)
    assert validated["type"] == "screenshot"
    assert validated["screenshot_path"] == "/tmp/shot.png"


def test_validate_idor_suspect():
    suspect = {
        "type": "idor_suspect",
        "url": "https://example.com/api/user/1",
        "auth": "session_id=123",
    }
    validated = validate_result(suspect)
    assert validated["type"] == "idor_suspect"
    assert validated["url"] == "https://example.com/api/user/1"


def test_validate_invalid_severity_fails():
    with pytest.raises(Exception):
        validate_result(
            {
                "type": "finding",
                "finding_type": "xss",
                "severity": "super_critical",  # Invalid literal
            }
        )
