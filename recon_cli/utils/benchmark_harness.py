from __future__ import annotations

import json
import time
import asyncio
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from recon_cli.jobs.manager import JobManager, JobRecord
from recon_cli.pipeline.runner import run_pipeline
from recon_cli.utils.jsonl import iter_jsonl

@dataclass
class ExpectedFinding:
    type: str
    pattern: str  # Regex or substring to match in URL or description
    min_severity: str = "info"
    met: bool = False

@dataclass
class BenchmarkTarget:
    name: str
    url: str
    expected_findings: List[ExpectedFinding] = field(default_factory=list)
    profile: str = "full"

@dataclass
class BenchmarkResult:
    target_name: str
    success: bool
    findings_count: int
    matched_expected: int
    total_expected: int
    false_positives: int = 0 # Difficult to calculate automatically without a full ground truth
    elapsed_seconds: float = 0.0

class BenchmarkHarness:
    """
    Harness to run ReconnV2 against known vulnerable targets and verify results.
    Part of Phase 5: Real Evaluation Gates.
    """
    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.manager = JobManager()

    async def run_benchmark(self, target: BenchmarkTarget) -> BenchmarkResult:
        print(f"[*] Starting benchmark for {target.name} at {target.url}...")
        start_time = time.monotonic()
        
        # 1. Create Job
        record = self.manager.create_job(target=target.url, profile=target.profile)
        job_id = record.spec.job_id
        
        # 2. Run Pipeline
        try:
            # Note: run_pipeline is sync in some versions, but we should use the async version if available
            # or wrap it. Based on recent work, run_pipeline calls PipelineRunner which is async.
            # In recon_cli/pipeline/runner.py, run_pipeline is sync but calls asyncio.run(runner.run(context))
            # However, we are in an async context here.
            
            from recon_cli.pipeline.context import PipelineContext
            from recon_cli.pipeline.runner import PipelineRunner
            
            context = PipelineContext(record=record, manager=self.manager)
            runner = PipelineRunner()
            await runner.run(context)
            
        except Exception as e:
            print(f"[!] Pipeline raised exception for {target.name}: {e}")
            # Continue to analysis because partial results might be present

        elapsed = time.monotonic() - start_time
        
        # 3. Analyze Results
        actual_findings = list(iter_jsonl(record.paths.results_jsonl))
        matched_count = 0
        
        for expected in target.expected_findings:
            for actual in actual_findings:
                if actual.get("type") != "finding":
                    continue
                
                # Check if type matches
                if actual.get("finding_type") == expected.type:
                    # Check if pattern matches URL or description
                    haystack = f"{actual.get('url', '')} {actual.get('description', '')}"
                    import re
                    if re.search(expected.pattern, haystack, re.IGNORECASE):
                        expected.met = True
                        matched_count += 1
                        break
        
        return BenchmarkResult(
            target_name=target.name,
            success=matched_count == len(target.expected_findings),
            findings_count=len([f for f in actual_findings if f.get("type") == "finding"]),
            matched_expected=matched_count,
            total_expected=len(target.expected_findings),
            elapsed_seconds=elapsed
        )

    def generate_report(self, results: List[BenchmarkResult]):
        report_path = self.output_dir / f"benchmark_report_{int(time.time())}.json"
        data = [
            {
                "target": r.target_name,
                "success": r.success,
                "matched": f"{r.matched_expected}/{r.total_expected}",
                "findings": r.findings_count,
                "time": f"{r.elapsed_seconds:.1f}s"
            }
            for r in results
        ]
        report_path.write_text(json.dumps(data, indent=2))
        print(f"[+] Benchmark report saved to {report_path}")
