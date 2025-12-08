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
