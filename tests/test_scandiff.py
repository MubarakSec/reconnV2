from __future__ import annotations

import pytest
from recon_cli.utils.diff import ResultNormalizer, ScanDiff, ChangeType, Severity

@pytest.fixture
def normalizer():
    return ResultNormalizer()

@pytest.fixture
def differ():
    return ScanDiff()

class TestResultNormalizer:
    def test_category_detection(self, normalizer):
        assert normalizer._detect_category({"cve": "CVE-2021-1234"}) == "vulnerability"
        assert normalizer._detect_category({"port": 80, "service": "http"}) == "port"
        assert normalizer._detect_category({"subdomain": "test.example.com"}) == "subdomain"
        assert normalizer._detect_category({"url": "https://example.com/path"}) == "endpoint"
        assert normalizer._detect_category({"secret": "ABCDEFG"}) == "secret"
        assert normalizer._detect_category({"some_other_field": "value"}) == "other"

    def test_key_generation(self, normalizer):
        # Vulnerability key
        rec1 = {"id": "vuln-123", "name": "XSS"}
        assert normalizer._generate_key(rec1, "vulnerability") == "id=vuln-123|name=XSS"
        
        # Endpoint key
        rec2 = {"url": "https://a.com/login"}
        assert normalizer._generate_key(rec2, "endpoint") == "url=https://a.com/login"

        # Fallback key
        rec3 = {"info": "some data"}
        assert normalizer._generate_key(rec3, "other") == "1077c23c4d10"

    def test_record_cleaning(self, normalizer):
        rec = {"host": "example.com", "port": 443, "scan_time": 123.45}
        cleaned = normalizer._clean_record(rec)
        assert "scan_time" not in cleaned
        assert "host" in cleaned

    def test_full_normalization(self, normalizer):
        results = [
            {"host": "a.com", "port": 80, "scan_id": "scan-1"},
            {"host": "b.com", "port": 443, "timestamp": "2023-01-01"},
        ]
        normalized = normalizer.normalize(results)
        
        assert "port" in normalized
        assert len(normalized["port"]) == 2
        
        key1 = "host=a.com|port=80"
        key2 = "host=b.com|port=443"

        assert key1 in normalized["port"]
        assert key2 in normalized["port"]
        
        # Check that ignored fields are gone
        assert "scan_id" not in normalized["port"][key1]
        assert "timestamp" not in normalized["port"][key2]

class TestScanDiff:
    def test_compare_no_changes(self, differ):
        results = [{"host": "a.com", "port": 80}]
        changes = differ.compare(results, results)
        assert len(changes) == 0

    def test_compare_added(self, differ):
        old = []
        new = [{"host": "a.com", "port": 80, "service": "http"}]
        changes = differ.compare(old, new)
        
        assert len(changes) == 1
        change = changes[0]
        assert change.change_type == ChangeType.ADDED
        assert change.category == "port"
        assert change.key == "host=a.com|port=80"
        assert change.severity == Severity.HIGH

    def test_compare_removed(self, differ):
        old = [{"host": "a.com", "port": 80, "service": "http"}]
        new = []
        changes = differ.compare(old, new)

        assert len(changes) == 1
        change = changes[0]
        assert change.change_type == ChangeType.REMOVED
        assert change.category == "port"
        assert change.key == "host=a.com|port=80"
        assert change.severity == Severity.INFO # Default for removed ports

    def test_compare_modified(self, differ):
        old = [{"host": "a.com", "port": 80, "service": "http"}]
        new = [{"host": "a.com", "port": 80, "service": "http-alt"}]
        changes = differ.compare(old, new)

        assert len(changes) == 1
        change = changes[0]
        assert change.change_type == ChangeType.MODIFIED
        assert change.category == "port"
        assert "field_changes" in change.details
        assert "service" in change.details["field_changes"]
        assert change.details["field_changes"]["service"] == ("http", "http-alt")

    def test_compare_mixed(self, differ):
        old = [
            {"host": "a.com", "port": 80, "service": "http"}, # modified
            {"host": "b.com", "port": 22, "service": "ssh"},  # removed
        ]
        new = [
            {"host": "a.com", "port": 80, "service": "http-proxy"}, # modified
            {"host": "c.com", "port": 443, "service": "https"},   # added
        ]
        
        changes = differ.compare(old, new)
        assert len(changes) == 3

        change_types = sorted([c.change_type.value for c in changes])
        assert change_types == ["added", "modified", "removed"]

    def test_vulnerability_added_severity(self, differ):
        old = []
        new = [{"cve": "CVE-2023-1337", "severity": "critical"}]
        changes = differ.compare(old, new)
        
        assert len(changes) == 1
        assert changes[0].change_type == ChangeType.ADDED
        assert changes[0].category == "vulnerability"
        assert changes[0].severity == Severity.CRITICAL

    def test_summarize(self, differ):
        old = [{"host": "a.com"}]
        new = [
            {"host": "b.com"}, # added
            {"cve": "CVE-2023-1337"}, # added
        ]
        changes = differ.compare(old, new)
        summary = differ.summarize(changes)

        assert summary.total_changes == 3
        assert summary.added == 2
        assert summary.removed == 1
        assert summary.modified == 0
        
        assert summary.by_category == {"subdomain": 2, "vulnerability": 1}
        assert summary.by_severity == {"critical": 1, "medium": 1, "info": 1}
        assert len(summary.critical_changes) == 1 # Only Critical severity
