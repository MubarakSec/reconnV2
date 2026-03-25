#!/usr/bin/env python3
import asyncio
import sys
from pathlib import Path

# Add the project root to the Python path
sys.path.insert(0, str(Path(__file__).parent.parent))

from recon_cli.utils.benchmark_harness import BenchmarkHarness, BenchmarkTarget, ExpectedFinding

async def main():
    output_dir = Path("artifacts/benchmarks")
    harness = BenchmarkHarness(output_dir)

    # Overrides to speed up tests by skipping heavy signature scanners
    # and focusing on the autonomous logic engine
    fast_overrides = {
        "enable_scanner": False,
        "enable_nuclei": False,
        "enable_fuzz": False,
        "enable_screenshots": False
    }

    targets = [
        BenchmarkTarget(
            name="Juice Shop",
            url="http://localhost:3000",
            profile="full",
            runtime_overrides=fast_overrides,
            expected_findings=[
                ExpectedFinding(type="api_schema", pattern="swagger|api-docs"),
                ExpectedFinding(type="sqli", pattern="login|search"),
                ExpectedFinding(type="xss", pattern="search|feedback"),
            ]
        ),
        BenchmarkTarget(
            name="DVWA",
            url="http://localhost:8001",
            profile="full",
            runtime_overrides=fast_overrides,
            expected_findings=[
                ExpectedFinding(type="sqli", pattern="vulnerabilities/sqli"),
                ExpectedFinding(type="xss", pattern="vulnerabilities/xss_r"),
            ]
        ),
        BenchmarkTarget(
            name="WebGoat",
            url="http://localhost:8081/WebGoat",
            profile="full",
            runtime_overrides=fast_overrides,
            expected_findings=[
                ExpectedFinding(type="auth_bypass", pattern="login"),
            ]
        )
    ]

    results = []
    for target in targets:
        result = await harness.run_benchmark(target)
        results.append(result)
        
        # Determine color based on success
        status_color = "\033[92m" if result.success else "\033[91m"
        reset_color = "\033[0m"
        
        print(f"[{status_color}{'SUCCESS' if result.success else 'FAILED'}{reset_color}] {target.name}")
        print(f"  Findings: {result.findings_count}")
        print(f"  Expected Matched: {result.matched_expected}/{result.total_expected}")
        print(f"  Time: {result.elapsed_seconds:.1f}s\n")

    harness.generate_report(results)
    
    # Exit with code 1 if any benchmark failed
    if not all(r.success for r in results):
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())
