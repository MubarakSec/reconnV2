import pytest

from recon_cli.utils import validation


def test_validate_target_url_strips_scheme_and_path():
    assert (
        validation.validate_target("https://www.example.com/login") == "www.example.com"
    )


def test_validate_target_host_with_port():
    assert validation.validate_target("example.com:8443") == "example.com"


def test_validate_target_ip_requires_flag():
    with pytest.raises(ValueError):
        validation.validate_target("http://127.0.0.1")


def test_validate_target_ip_allowed():
    assert validation.validate_target("http://127.0.0.1", allow_ip=True) == "127.0.0.1"


def test_validate_target_strips_wildcard_prefix():
    assert validation.validate_target("*.example.com") == "example.com"
