import pytest

from recon_cli.utils import validation


def test_validate_target_url_strips_scheme_and_path():
    assert (
        validation.validate_target("https://www.example.com/login") == "www.example.com"
    )


def test_validate_target_host_with_port():
    assert validation.validate_target("example.com:8443") == "example.com:8443"


def test_validate_target_ip_requires_flag():
    with pytest.raises(ValueError):
        validation.validate_target("http://127.0.0.1")


def test_validate_target_ip_allowed():
    assert validation.validate_target("http://127.0.0.1", allow_ip=True) == "127.0.0.1"


def test_validate_target_strips_wildcard_prefix():
    assert validation.validate_target("*.example.com") == "example.com"


def test_is_sensible_file():
    # Legitimate SQL
    sql_content = b"CREATE TABLE users (id INT, name VARCHAR(255)); INSERT INTO users VALUES (1, 'admin');"
    assert validation.is_sensible_file(sql_content, "https://example.com/db.sql") is True
    
    # HTML masquerading as SQL
    html_sql = b"<!doctype html><html><body><h1>404 Not Found</h1></body></html>"
    assert validation.is_sensible_file(html_sql, "https://example.com/db.sql") is False
    
    # Legitimate ZIP
    zip_content = b"PK\x03\x04\x14\x00\x00\x00\x08\x00"
    assert validation.is_sensible_file(zip_content, "https://example.com/backup.zip") is True
    
    # HTML masquerading as ZIP
    html_zip = b"<html><body>Access Forbidden</body></html>"
    assert validation.is_sensible_file(html_zip, "https://example.com/backup.zip") is False
    
    # Environment file
    env_content = b"DB_PASSWORD=secret\nAPI_KEY=12345"
    assert validation.is_sensible_file(env_content, "https://example.com/.env") is True
    
    # Very short content
    assert validation.is_sensible_file(b"too short", "https://example.com/test.txt") is False
