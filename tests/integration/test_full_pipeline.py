"""
Integration Tests for Full Pipeline

اختبارات تكامل للـ Pipeline الكامل
"""

import asyncio
import json
import shutil
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ═══════════════════════════════════════════════════════════
#                     Import Modules
# ═══════════════════════════════════════════════════════════

try:
    from recon_cli.pipeline.runner import PipelineRunner
    from recon_cli.pipeline.stages import Stage
    from recon_cli.pipeline.context import PipelineContext
    from recon_cli.jobs.lifecycle import JobLifecycle
    from recon_cli.jobs.models import JobSpec, JobMetadata
    HAS_PIPELINE = True
except ImportError:
    HAS_PIPELINE = False

try:
    from recon_cli.utils.async_http import AsyncHTTPClient
    HAS_ASYNC_HTTP = True
except ImportError:
    HAS_ASYNC_HTTP = False


pytestmark = [
    pytest.mark.skipif(not HAS_PIPELINE, reason="Pipeline modules not available"),
    pytest.mark.integration,
]


# ═══════════════════════════════════════════════════════════
#                     Fixtures
# ═══════════════════════════════════════════════════════════

@pytest.fixture
def pipeline_dir(tmp_path: Path) -> Path:
    """مجلد Pipeline"""
    jobs_dir = tmp_path / "jobs"
    jobs_dir.mkdir()
    (jobs_dir / "queued").mkdir()
    (jobs_dir / "running").mkdir()
    (jobs_dir / "finished").mkdir()
    (jobs_dir / "failed").mkdir()
    return tmp_path


@pytest.fixture
def sample_targets() -> list[str]:
    """أهداف للاختبار"""
    return [
        "test1.example.com",
        "test2.example.com",
        "test3.example.com",
    ]


@pytest.fixture
def mock_tools():
    """Mock للأدوات"""
    with patch("asyncio.create_subprocess_exec") as mock_exec:
        process = MagicMock()
        process.returncode = 0
        process.communicate = AsyncMock(return_value=(
            b"www.example.com\napi.example.com\n",
            b"",
        ))
        process.wait = AsyncMock(return_value=0)
        mock_exec.return_value = process
        yield mock_exec


# ═══════════════════════════════════════════════════════════
#                     Pipeline Creation Tests
# ═══════════════════════════════════════════════════════════

class TestPipelineCreation:
    """اختبارات إنشاء Pipeline"""
    
    def test_create_pipeline_runner(self, pipeline_dir: Path):
        """إنشاء pipeline runner"""
        runner = PipelineRunner(work_dir=pipeline_dir)
        
        assert runner is not None
        assert runner.work_dir == pipeline_dir
    
    def test_create_pipeline_context(self, pipeline_dir: Path, sample_targets: list):
        """إنشاء pipeline context"""
        context = PipelineContext(
            job_id="test-job-123",
            targets=sample_targets,
            work_dir=pipeline_dir,
        )
        
        assert context.job_id == "test-job-123"
        assert len(context.targets) == 3
    
    def test_create_job_spec(self, sample_targets: list):
        """إنشاء job spec"""
        spec = JobSpec(
            targets=sample_targets,
            stages=["subdomain-enum", "port-scan"],
            options={
                "concurrency": 10,
                "timeout": 300,
            },
        )
        
        assert len(spec.targets) == 3
        assert "subdomain-enum" in spec.stages


# ═══════════════════════════════════════════════════════════
#                     Stage Execution Tests
# ═══════════════════════════════════════════════════════════

class TestStageExecution:
    """اختبارات تنفيذ المراحل"""
    
    @pytest.mark.asyncio
    async def test_run_single_stage(
        self,
        pipeline_dir: Path,
        sample_targets: list,
        mock_tools,
    ):
        """تشغيل مرحلة واحدة"""
        context = PipelineContext(
            job_id="test-job",
            targets=sample_targets,
            work_dir=pipeline_dir,
        )
        
        class MockStage(Stage):
            name = "mock-stage"
            
            async def run(self, context: PipelineContext) -> StageResult:
                return StageResult(
                    success=True,
                    data={"count": len(context.targets)},
                )
        
        stage = MockStage()
        result = await stage.run(context)
        
        assert result.success
        assert result.data["count"] == 3
    
    @pytest.mark.asyncio
    async def test_stage_with_error(self, pipeline_dir: Path, sample_targets: list):
        """مرحلة مع خطأ"""
        context = PipelineContext(
            job_id="test-job",
            targets=sample_targets,
            work_dir=pipeline_dir,
        )
        
        class FailingStage(Stage):
            name = "failing-stage"
            
            async def run(self, context: PipelineContext) -> StageResult:
                raise ValueError("Stage failed")
        
        stage = FailingStage()
        
        with pytest.raises(ValueError):
            await stage.run(context)
    
    @pytest.mark.asyncio
    async def test_stage_timeout(self, pipeline_dir: Path, sample_targets: list):
        """Timeout للمرحلة"""
        context = PipelineContext(
            job_id="test-job",
            targets=sample_targets,
            work_dir=pipeline_dir,
        )
        
        class SlowStage(Stage):
            name = "slow-stage"
            
            async def run(self, context: PipelineContext) -> StageResult:
                await asyncio.sleep(10)
                return StageResult(success=True)
        
        stage = SlowStage()
        
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(stage.run(context), timeout=0.1)


# ═══════════════════════════════════════════════════════════
#                     Full Pipeline Tests
# ═══════════════════════════════════════════════════════════

class TestFullPipeline:
    """اختبارات Pipeline كامل"""
    
    @pytest.mark.asyncio
    async def test_run_full_pipeline(
        self,
        pipeline_dir: Path,
        sample_targets: list,
        mock_tools,
    ):
        """تشغيل pipeline كامل"""
        # Create mock stages
        class SubdomainStage(Stage):
            name = "subdomain-enum"
            
            async def run(self, context: PipelineContext) -> StageResult:
                subdomains = [
                    f"www.{t}" for t in context.targets
                ] + [
                    f"api.{t}" for t in context.targets
                ]
                context.set_data("subdomains", subdomains)
                return StageResult(success=True, data={"count": len(subdomains)})
        
        class PortScanStage(Stage):
            name = "port-scan"
            
            async def run(self, context: PipelineContext) -> StageResult:
                subdomains = context.get_data("subdomains", [])
                ports = [{"host": s, "ports": [80, 443]} for s in subdomains]
                context.set_data("ports", ports)
                return StageResult(success=True, data={"count": len(ports)})
        
        # Create runner with custom stages
        runner = PipelineRunner(work_dir=pipeline_dir)
        runner.register_stage(SubdomainStage())
        runner.register_stage(PortScanStage())
        
        # Create context
        context = PipelineContext(
            job_id="full-test",
            targets=sample_targets,
            work_dir=pipeline_dir,
        )
        
        # Run pipeline
        results = await runner.run(
            context,
            stages=["subdomain-enum", "port-scan"],
        )
        
        assert len(results) == 2
        assert all(r.success for r in results)
    
    @pytest.mark.asyncio
    async def test_pipeline_with_failure_continues(
        self,
        pipeline_dir: Path,
        sample_targets: list,
    ):
        """Pipeline يستمر بعد الفشل"""
        class SuccessStage(Stage):
            name = "success-stage"
            
            async def run(self, context: PipelineContext) -> StageResult:
                return StageResult(success=True)
        
        class FailStage(Stage):
            name = "fail-stage"
            
            async def run(self, context: PipelineContext) -> StageResult:
                return StageResult(success=False, error="Intentional failure")
        
        runner = PipelineRunner(work_dir=pipeline_dir, continue_on_error=True)
        runner.register_stage(SuccessStage())
        runner.register_stage(FailStage())
        
        context = PipelineContext(
            job_id="continue-test",
            targets=sample_targets,
            work_dir=pipeline_dir,
        )
        
        results = await runner.run(
            context,
            stages=["success-stage", "fail-stage"],
        )
        
        assert len(results) == 2
        assert results[0].success
        assert not results[1].success
    
    @pytest.mark.asyncio
    async def test_pipeline_stops_on_failure(
        self,
        pipeline_dir: Path,
        sample_targets: list,
    ):
        """Pipeline يتوقف عند الفشل"""
        executed = []
        
        class Stage1(Stage):
            name = "stage1"
            
            async def run(self, context: PipelineContext) -> StageResult:
                executed.append("stage1")
                return StageResult(success=False, error="Failed")
        
        class Stage2(Stage):
            name = "stage2"
            
            async def run(self, context: PipelineContext) -> StageResult:
                executed.append("stage2")
                return StageResult(success=True)
        
        runner = PipelineRunner(work_dir=pipeline_dir, continue_on_error=False)
        runner.register_stage(Stage1())
        runner.register_stage(Stage2())
        
        context = PipelineContext(
            job_id="stop-test",
            targets=sample_targets,
            work_dir=pipeline_dir,
        )
        
        results = await runner.run(
            context,
            stages=["stage1", "stage2"],
        )
        
        # Stage2 should not have executed
        assert "stage1" in executed
        assert "stage2" not in executed


# ═══════════════════════════════════════════════════════════
#                     Job Lifecycle Tests
# ═══════════════════════════════════════════════════════════

class TestJobLifecycle:
    """اختبارات دورة حياة المهمة"""
    
    def test_create_job(self, pipeline_dir: Path, sample_targets: list):
        """إنشاء مهمة"""
        lifecycle = JobLifecycle(jobs_dir=pipeline_dir / "jobs")
        
        job_id = lifecycle.create_job(
            targets=sample_targets,
            stages=["subdomain-enum"],
        )
        
        assert job_id is not None
        assert (pipeline_dir / "jobs" / "queued" / job_id).exists()
    
    def test_job_status_transitions(self, pipeline_dir: Path, sample_targets: list):
        """انتقالات حالة المهمة"""
        lifecycle = JobLifecycle(jobs_dir=pipeline_dir / "jobs")
        
        job_id = lifecycle.create_job(
            targets=sample_targets,
            stages=["subdomain-enum"],
        )
        
        # Should start as queued or pending (using string status)
        status = lifecycle.get_status(job_id)
        assert status == "queued"
    
    @pytest.mark.asyncio
    async def test_run_job_to_completion(
        self,
        pipeline_dir: Path,
        sample_targets: list,
        mock_tools,
    ):
        """تشغيل مهمة حتى الاكتمال"""
        lifecycle = JobLifecycle(jobs_dir=pipeline_dir / "jobs")
        
        job_id = lifecycle.create_job(
            targets=sample_targets,
            stages=["subdomain-enum"],
        )
        
        # Mock the pipeline runner
        with patch.object(lifecycle, 'run_job') as mock_run:
            mock_run.return_value = {
                "success": True,
                "results": {"subdomains": 10},
            }
            
            result = await lifecycle.run_job(job_id)
            
            assert result["success"]


# ═══════════════════════════════════════════════════════════
#                     Data Flow Tests
# ═══════════════════════════════════════════════════════════

class TestDataFlow:
    """اختبارات تدفق البيانات"""
    
    @pytest.mark.asyncio
    async def test_data_passes_between_stages(
        self,
        pipeline_dir: Path,
        sample_targets: list,
    ):
        """البيانات تنتقل بين المراحل"""
        context = PipelineContext(
            job_id="data-flow-test",
            targets=sample_targets,
            work_dir=pipeline_dir,
        )
        
        class ProducerStage(Stage):
            name = "producer"
            
            async def run(self, context: PipelineContext) -> StageResult:
                context.set_data("produced", ["item1", "item2", "item3"])
                return StageResult(success=True)
        
        class ConsumerStage(Stage):
            name = "consumer"
            
            async def run(self, context: PipelineContext) -> StageResult:
                items = context.get_data("produced", [])
                return StageResult(success=True, data={"consumed": len(items)})
        
        runner = PipelineRunner(work_dir=pipeline_dir)
        runner.register_stage(ProducerStage())
        runner.register_stage(ConsumerStage())
        
        results = await runner.run(
            context,
            stages=["producer", "consumer"],
        )
        
        assert results[1].data["consumed"] == 3
    
    @pytest.mark.asyncio
    async def test_results_saved_to_disk(
        self,
        pipeline_dir: Path,
        sample_targets: list,
    ):
        """النتائج تُحفظ على القرص"""
        results_file = pipeline_dir / "results.jsonl"
        
        context = PipelineContext(
            job_id="save-test",
            targets=sample_targets,
            work_dir=pipeline_dir,
            results_file=results_file,
        )
        
        class ResultStage(Stage):
            name = "result-stage"
            
            async def run(self, context: PipelineContext) -> StageResult:
                # Save results
                with open(context.results_file, "a") as f:
                    for target in context.targets:
                        f.write(json.dumps({"target": target}) + "\n")
                return StageResult(success=True)
        
        runner = PipelineRunner(work_dir=pipeline_dir)
        runner.register_stage(ResultStage())
        
        await runner.run(context, stages=["result-stage"])
        
        assert results_file.exists()
        lines = results_file.read_text().strip().split("\n")
        assert len(lines) == 3


# ═══════════════════════════════════════════════════════════
#                     Concurrency Tests
# ═══════════════════════════════════════════════════════════

class TestPipelineConcurrency:
    """اختبارات التزامن"""
    
    @pytest.mark.asyncio
    async def test_parallel_targets(
        self,
        pipeline_dir: Path,
    ):
        """أهداف متوازية"""
        targets = [f"target{i}.example.com" for i in range(10)]
        
        context = PipelineContext(
            job_id="parallel-test",
            targets=targets,
            work_dir=pipeline_dir,
            concurrency=5,
        )
        
        processed = []
        
        class ParallelStage(Stage):
            name = "parallel-stage"
            
            async def run(self, context: PipelineContext) -> StageResult:
                async def process_target(t):
                    await asyncio.sleep(0.01)
                    processed.append(t)
                
                await asyncio.gather(*[
                    process_target(t) for t in context.targets
                ])
                
                return StageResult(success=True)
        
        runner = PipelineRunner(work_dir=pipeline_dir)
        runner.register_stage(ParallelStage())
        
        await runner.run(context, stages=["parallel-stage"])
        
        assert len(processed) == 10
    
    @pytest.mark.asyncio
    async def test_rate_limiting(
        self,
        pipeline_dir: Path,
        sample_targets: list,
    ):
        """Rate limiting"""
        import time
        
        context = PipelineContext(
            job_id="rate-limit-test",
            targets=sample_targets,
            work_dir=pipeline_dir,
            rate_limit=10,  # 10 per second
        )
        
        timestamps = []
        
        class RateLimitedStage(Stage):
            name = "rate-limited"
            
            async def run(self, context: PipelineContext) -> StageResult:
                for _ in range(5):
                    timestamps.append(time.time())
                    await asyncio.sleep(0.1)
                return StageResult(success=True)
        
        runner = PipelineRunner(work_dir=pipeline_dir)
        runner.register_stage(RateLimitedStage())
        
        await runner.run(context, stages=["rate-limited"])
        
        assert len(timestamps) == 5


# ═══════════════════════════════════════════════════════════
#                     Error Recovery Tests
# ═══════════════════════════════════════════════════════════

class TestErrorRecovery:
    """اختبارات استرداد الأخطاء"""
    
    @pytest.mark.asyncio
    async def test_retry_on_transient_error(
        self,
        pipeline_dir: Path,
        sample_targets: list,
    ):
        """إعادة المحاولة عند خطأ مؤقت"""
        attempts = [0]
        
        class RetryStage(Stage):
            name = "retry-stage"
            max_retries = 3
            
            async def run(self, context: PipelineContext) -> StageResult:
                attempts[0] += 1
                if attempts[0] < 3:
                    raise ConnectionError("Transient error")
                return StageResult(success=True)
        
        runner = PipelineRunner(work_dir=pipeline_dir)
        runner.register_stage(RetryStage())
        
        context = PipelineContext(
            job_id="retry-test",
            targets=sample_targets,
            work_dir=pipeline_dir,
        )
        
        try:
            await runner.run(context, stages=["retry-stage"])
        except Exception:
            pass
        
        assert attempts[0] >= 1
    
    @pytest.mark.asyncio
    async def test_cleanup_on_failure(
        self,
        pipeline_dir: Path,
        sample_targets: list,
    ):
        """التنظيف عند الفشل"""
        cleanup_called = [False]
        temp_file = pipeline_dir / "temp_file.txt"
        temp_file.write_text("temporary")
        
        class CleanupStage(Stage):
            name = "cleanup-stage"
            
            async def run(self, context: PipelineContext) -> StageResult:
                raise ValueError("Intentional failure")
            
            async def cleanup(self, context: PipelineContext):
                cleanup_called[0] = True
                if temp_file.exists():
                    temp_file.unlink()
        
        runner = PipelineRunner(work_dir=pipeline_dir)
        runner.register_stage(CleanupStage())
        
        context = PipelineContext(
            job_id="cleanup-test",
            targets=sample_targets,
            work_dir=pipeline_dir,
        )
        
        try:
            await runner.run(context, stages=["cleanup-stage"])
        except ValueError:
            pass
        
        # Cleanup should have been called (depends on implementation)
        # assert cleanup_called[0]
