from recon_cli.utils import reporting


def test_resolve_severity_priority_and_score():
    assert reporting.resolve_severity({"severity": "high"}) == "high"
    assert reporting.resolve_severity({"priority": "critical"}) == "critical"
    assert reporting.resolve_severity({"score": 80}) == "high"
    assert reporting.resolve_severity({"score": 10}) == "info"


def test_resolve_finding_type_rules():
    assert reporting.resolve_finding_type({"finding_type": "sql_injection"}) == "sql_injection"
    assert reporting.resolve_finding_type({"type": "auth_matrix_issue"}) == "auth_matrix_issue"
    assert reporting.resolve_finding_type({"type": "finding", "tags": ["xss"]}) == "xss"
    assert reporting.resolve_finding_type({"type": "finding", "source": "sqlmap"}) == "sql_injection"


def test_is_finding_and_secret():
    assert reporting.is_finding({"finding_type": "exposed_secret"}) is True
    assert reporting.is_finding({"type": "idor_suspect"}) is True
    assert reporting.is_secret({"finding_type": "exposed_secret"}) is True
    assert reporting.is_secret({"type": "secret"}) is True
    assert reporting.is_secret({"source": "secrets-static"}) is True
