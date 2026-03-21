
import json
from pathlib import Path
from recon_cli.jobs.results import ResultsTracker

def test_strict_validation():
    results_file = Path("test_results.jsonl")
    if results_file.exists():
        results_file.unlink()
    
    tracker = ResultsTracker(results_file)
    
    # Valid finding
    valid_finding = {
        "type": "finding",
        "finding_type": "xss",
        "severity": "high",
        "hostname": "example.com",
    }
    tracker.append(valid_finding)
    
    # Invalid finding (missing finding_type)
    invalid_finding = {
        "type": "finding",
        "severity": "medium",
        "hostname": "example.com",
    }
    tracker.append(invalid_finding)
    
    # Check results
    with open(results_file, "r") as f:
        lines = f.readlines()
        for line in lines:
            print(f"Result: {line.strip()}")

if __name__ == "__main__":
    test_strict_validation()
