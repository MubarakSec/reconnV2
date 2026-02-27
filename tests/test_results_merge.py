from pathlib import Path

from recon_cli.jobs.results import ResultsTracker
from recon_cli.utils.jsonl import read_jsonl


def test_results_tracker_merges_duplicates(tmp_path: Path):
    path = tmp_path / "results.jsonl"
    tracker = ResultsTracker(path)
    tracker.append({"type": "url", "url": "https://example.com", "tags": ["a"], "source": "probe", "score": 10})
    tracker.append({"type": "url", "url": "https://example.com", "tags": ["b"], "source": "ffuf", "score": 30})
    entries = [e for e in read_jsonl(path) if e.get("type") != "meta"]
    assert len(entries) == 1
    entry = entries[0]
    assert set(entry.get("tags", [])) == {"a", "b"}
    assert entry.get("score") == 30
    assert "ffuf" in entry.get("sources", [])
    assert tracker.stats.get("records_seen") == 2
    assert tracker.stats.get("records_unique") == 1
    assert tracker.stats.get("records_duplicate") == 1


def test_results_tracker_keeps_distinct_idor_suspects(tmp_path: Path):
    path = tmp_path / "results.jsonl"
    tracker = ResultsTracker(path)
    tracker.append(
        {
            "type": "idor_suspect",
            "source": "idor-stage",
            "url": "https://api.example.com/users/1",
            "auth": "token-a",
            "score": 80,
            "priority": "high",
        }
    )
    tracker.append(
        {
            "type": "idor_suspect",
            "source": "idor-stage",
            "url": "https://api.example.com/users/2",
            "auth": "token-a",
            "score": 80,
            "priority": "high",
        }
    )
    tracker.append(
        {
            "type": "idor_suspect",
            "source": "idor-stage",
            "url": "https://api.example.com/users/1",
            "auth": "token-b",
            "score": 80,
            "priority": "high",
        }
    )
    entries = [e for e in read_jsonl(path) if e.get("type") == "idor_suspect"]
    assert len(entries) == 3


def test_results_tracker_distinguishes_findings_by_url(tmp_path: Path):
    path = tmp_path / "results.jsonl"
    tracker = ResultsTracker(path)
    tracker.append(
        {
            "type": "finding",
            "finding_type": "xss",
            "description": "Reflected XSS",
            "hostname": "example.com",
            "url": "https://example.com/a",
            "severity": "high",
        }
    )
    tracker.append(
        {
            "type": "finding",
            "finding_type": "xss",
            "description": "Reflected XSS",
            "hostname": "example.com",
            "url": "https://example.com/b",
            "severity": "high",
        }
    )
    entries = [e for e in read_jsonl(path) if e.get("type") == "finding"]
    assert len(entries) == 2


def test_results_tracker_sets_confidence_label(tmp_path: Path):
    path = tmp_path / "results.jsonl"
    tracker = ResultsTracker(path)
    tracker.append(
        {
            "type": "finding",
            "finding_type": "open_redirect",
            "description": "Open redirect",
            "hostname": "example.com",
            "url": "https://example.com/redirect",
            "tags": ["redirect", "confirmed"],
        }
    )
    entries = [e for e in read_jsonl(path) if e.get("type") == "finding"]
    assert entries[0].get("confidence_label") == "verified"
    assert entries[0].get("confidence_score") == 1.0
    assert str(entries[0].get("finding_fingerprint", "")).startswith("fp_")


def test_results_tracker_keeps_findings_with_different_parameters(tmp_path: Path):
    path = tmp_path / "results.jsonl"
    tracker = ResultsTracker(path)
    base = {
        "type": "finding",
        "finding_type": "sql_injection",
        "description": "SQLi",
        "hostname": "example.com",
        "url": "https://example.com/search?q=1",
        "source": "sqlmap",
        "severity": "high",
    }
    tracker.append({**base, "parameter": "q"})
    tracker.append({**base, "parameter": "id", "url": "https://example.com/search?id=1"})
    entries = [e for e in read_jsonl(path) if e.get("type") == "finding"]
    assert len(entries) == 2


def test_results_tracker_dedupes_by_fingerprint_across_sources(tmp_path: Path):
    path = tmp_path / "results.jsonl"
    tracker = ResultsTracker(path)
    first = {
        "type": "finding",
        "finding_type": "xss",
        "description": "Reflected XSS",
        "url": "https://example.com/search?q=1",
        "source": "dalfox",
        "severity": "high",
    }
    second = {
        "type": "finding",
        "finding_type": "xss",
        "description": "Reflected XSS",
        "url": "https://example.com/search?q=999",
        "source": "manual-check",
        "severity": "high",
    }
    tracker.append(first)
    tracker.append(second)
    entries = [e for e in read_jsonl(path) if e.get("type") == "finding"]
    assert len(entries) == 1
    assert set(entries[0].get("sources", [])) >= {"dalfox", "manual-check"}
