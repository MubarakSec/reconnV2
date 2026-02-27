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


def test_resolve_confidence_label_and_verified():
    assert reporting.resolve_confidence_label({"tags": ["confirmed"]}) == "verified"
    assert reporting.resolve_confidence_label({"tags": ["ssrf:confirmed"]}) == "verified"
    assert reporting.resolve_confidence_label({"source": "extended-validation"}) == "verified"
    assert reporting.resolve_confidence_label({"confidence": 0.9}) == "high"
    assert reporting.resolve_confidence_label({"confidence": 0.7}) == "medium"
    assert reporting.resolve_confidence_label({"confidence": 0.2}) == "low"
    assert reporting.resolve_confidence_label({"severity": "high"}) == "high"
    assert reporting.resolve_confidence_label({"severity": "medium"}) == "medium"
    assert reporting.is_verified_finding({"tags": ["verified:live"]}) is True
    assert reporting.is_verified_finding({"severity": "high"}) is False


def test_infer_replay_stage_and_rerun_command():
    assert reporting.infer_replay_stage({"source": "dalfox"}) == "vuln_scan"
    assert reporting.infer_replay_stage({"finding_type": "open_redirect"}) == "extended_validation"
    assert reporting.build_finding_rerun_command("job123", {"source": "dalfox"}) == (
        "recon-cli rerun job123 --stages vuln_scan --keep-results"
    )
    assert reporting.build_finding_rerun_command("job123", {"source": "unknown"}) == "recon-cli rerun job123 --restart"


def test_build_submission_summary_contains_key_fields():
    summary = reporting.build_submission_summary(
        {
            "title": "SQLi in search",
            "source": "sqlmap",
            "finding_type": "sql_injection",
            "url": "https://example.com/search?q=1",
            "severity": "critical",
            "tags": ["confirmed"],
        }
    )
    assert "SQLi in search" in summary
    assert "CRITICAL" in summary
    assert "https://example.com/search?q=1" in summary
    assert "confidence=verified" in summary


def test_build_triage_entry_fields():
    entry = reporting.build_triage_entry(
        {
            "type": "finding",
            "finding_type": "sql_injection",
            "source": "sqlmap",
            "title": "SQLi in search",
            "url": "https://example.com/search?q=1",
            "hostname": "example.com",
            "severity": "critical",
            "tags": ["sqli:confirmed"],
        },
        job_id="job123",
    )
    assert entry["finding_id"].startswith("fnd_")
    assert entry["job_id"] == "job123"
    assert entry["severity"] == "critical"
    assert entry["finding_type"] == "sql_injection"
    assert entry["proof"] == "verified"
    assert entry["repro_cmd"].startswith("recon-cli rerun job123 --stages vuln_scan")
    assert entry["poc_steps"][0]["command"] == entry["repro_cmd"]
    assert "injectable parameter" in entry["poc_steps"][0]["expected_success"].lower()
    assert entry["asset_context"]["host"] == "example.com"
    assert entry["asset_context"]["endpoint"] == "https://example.com/search?q=1"
    assert entry["asset_context"]["auth_requirement"] in {"unknown", "likely_required", "public"}
    assert entry["impact_hypothesis"]


def test_compute_risk_score_prioritizes_verified_public_auth():
    high_value = {
        "type": "finding",
        "finding_type": "sql_injection",
        "source": "sqlmap",
        "title": "SQLi in admin account API",
        "url": "https://example.com/api/admin/account?id=1",
        "severity": "high",
        "tags": ["sqli:confirmed"],
    }
    low_value = {
        "type": "finding",
        "finding_type": "sql_injection",
        "source": "sqlmap",
        "title": "SQLi internal test",
        "url": "https://10.0.0.5/internal",
        "severity": "medium",
        "tags": [],
    }
    assert reporting.compute_risk_score(high_value) > reporting.compute_risk_score(low_value)


def test_rank_findings_is_deterministic():
    items = [
        {
            "type": "finding",
            "title": "a",
            "finding_type": "sql_injection",
            "source": "sqlmap",
            "url": "https://example.com/a",
            "severity": "high",
            "tags": ["sqli:confirmed"],
        },
        {
            "type": "finding",
            "title": "b",
            "finding_type": "xss",
            "source": "dalfox",
            "url": "https://example.com/b",
            "severity": "medium",
        },
    ]
    first = [entry["title"] for entry in reporting.rank_findings(items)]
    second = [entry["title"] for entry in reporting.rank_findings(items)]
    assert first == second


def test_rank_findings_prioritizes_higher_risk():
    items = [
        {
            "type": "finding",
            "title": "low-risk",
            "finding_type": "xss",
            "source": "dalfox",
            "url": "https://10.0.0.5/internal",
            "severity": "low",
        },
        {
            "type": "finding",
            "title": "high-risk",
            "finding_type": "sql_injection",
            "source": "sqlmap",
            "url": "https://example.com/api/admin/account?id=1",
            "severity": "high",
            "tags": ["sqli:confirmed"],
        },
    ]
    ranked = reporting.rank_findings(items)
    assert ranked[0]["title"] == "high-risk"
