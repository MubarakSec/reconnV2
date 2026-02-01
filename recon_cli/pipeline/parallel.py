"""
Parallel Pipeline Runner - منفذ Pipeline متوازي

نسخة محسنة من PipelineRunner تدعم:
- تنفيذ المراحل المستقلة بالتوازي
- تتبع dependencies بين المراحل
- تحسين الأداء

Example:
    >>> runner = ParallelPipelineRunner(job, spec)
    >>> await runner.run_async()
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, TYPE_CHECKING

if TYPE_CHECKING:
    from recon_cli.jobs.models import Job, ScanSpec
    from recon_cli.pipeline.stages import PipelineStage

logger = logging.getLogger(__name__)


@dataclass
class StageNode:
    """تمثيل مرحلة في DAG"""
    name: str
    stage: "PipelineStage"
    dependencies: Set[str] = field(default_factory=set)
    dependents: Set[str] = field(default_factory=set)
    completed: bool = False
    running: bool = False
    error: Optional[str] = None
    duration: float = 0.0


@dataclass
class ParallelExecutionPlan:
    """خطة تنفيذ متوازية"""
    stages: Dict[str, StageNode]
    execution_order: List[List[str]]  # Groups of stages to run in parallel
    
    @property
    def total_stages(self) -> int:
        return len(self.stages)
    
    @property
    def completed_count(self) -> int:
        return sum(1 for s in self.stages.values() if s.completed)
    
    @property
    def parallel_groups(self) -> int:
        return len(self.execution_order)


class DependencyResolver:
    """
    محلل التبعيات للمراحل.
    
    يحلل المراحل ويحدد أي منها يمكن تشغيله بالتوازي.
    """
    
    # تعريف التبعيات المعروفة
    STAGE_DEPENDENCIES = {
        # المراحل الأولية ليس لها تبعيات
        "dns_resolution": set(),
        "subdomain_enum": set(),
        
        # بعد enumeration
        "http_probe": {"subdomain_enum", "dns_resolution"},
        "port_scan": {"subdomain_enum"},
        
        # بعد HTTP probe
        "tech_detect": {"http_probe"},
        "crawler": {"http_probe"},
        "screenshot": {"http_probe"},
        
        # بعد crawling
        "secrets_scan": {"crawler"},
        "js_analysis": {"crawler"},
        "backup_hunter": {"crawler"},
        
        # تحليل
        "vuln_scan": {"tech_detect"},
        "takeover": {"dns_resolution", "http_probe"},
        
        # نهائية
        "correlation": {"secrets_scan", "js_analysis", "vuln_scan"},
        "reporting": {"correlation"},
    }
    
    def resolve(self, stage_names: List[str]) -> List[List[str]]:
        """
        حل التبعيات وإرجاع مجموعات التنفيذ.
        
        Args:
            stage_names: قائمة أسماء المراحل
            
        Returns:
            قائمة من المجموعات، كل مجموعة يمكن تنفيذها بالتوازي
        """
        # Build dependency graph
        available = set(stage_names)
        remaining = set(stage_names)
        execution_order = []
        
        while remaining:
            # Find stages with satisfied dependencies
            ready = []
            for stage in remaining:
                deps = self.STAGE_DEPENDENCIES.get(stage, set())
                # Only consider dependencies that are in our stage list
                relevant_deps = deps & available
                
                # Check if all dependencies are completed
                if not (relevant_deps - (available - remaining)):
                    ready.append(stage)
            
            if not ready:
                # Deadlock or unknown stages - run remaining sequentially
                logger.warning(
                    "Could not resolve dependencies for: %s. Running sequentially.",
                    remaining
                )
                for stage in sorted(remaining):
                    execution_order.append([stage])
                break
            
            execution_order.append(sorted(ready))
            remaining -= set(ready)
        
        return execution_order


class ParallelStageExecutor:
    """
    منفذ المراحل بالتوازي.
    
    Example:
        >>> executor = ParallelStageExecutor(stages, context)
        >>> results = await executor.execute()
    """
    
    def __init__(
        self,
        stages: Dict[str, "PipelineStage"],
        context: dict,
        max_parallel: int = 4,
    ):
        """
        Args:
            stages: المراحل المراد تنفيذها
            context: سياق التنفيذ
            max_parallel: أقصى عدد مراحل متوازية
        """
        self.stages = stages
        self.context = context
        self.max_parallel = max_parallel
        self.resolver = DependencyResolver()
        self._results: Dict[str, dict] = {}
        self._errors: Dict[str, str] = {}
        self._timings: Dict[str, float] = {}
    
    def create_plan(self) -> ParallelExecutionPlan:
        """إنشاء خطة التنفيذ"""
        stage_names = list(self.stages.keys())
        execution_order = self.resolver.resolve(stage_names)
        
        # Create stage nodes
        nodes = {}
        for name, stage in self.stages.items():
            deps = self.resolver.STAGE_DEPENDENCIES.get(name, set())
            nodes[name] = StageNode(
                name=name,
                stage=stage,
                dependencies=deps & set(stage_names),
            )
        
        # Calculate dependents
        for name, node in nodes.items():
            for dep in node.dependencies:
                if dep in nodes:
                    nodes[dep].dependents.add(name)
        
        return ParallelExecutionPlan(
            stages=nodes,
            execution_order=execution_order,
        )
    
    async def _run_stage(self, name: str, stage: "PipelineStage") -> dict:
        """تنفيذ مرحلة واحدة"""
        start = time.time()
        try:
            # Most stages have a run() method
            if hasattr(stage, "run_async"):
                result = await stage.run_async(self.context)
            elif hasattr(stage, "run"):
                # Run sync stage in executor
                loop = asyncio.get_event_loop()
                result = await loop.run_in_executor(
                    None,
                    stage.run,
                    self.context
                )
            else:
                result = {"status": "skipped", "reason": "no run method"}
            
            self._timings[name] = time.time() - start
            return result or {}
            
        except Exception as e:
            self._timings[name] = time.time() - start
            self._errors[name] = str(e)
            logger.error(f"Stage {name} failed: {e}")
            raise
    
    async def execute(self) -> Dict[str, dict]:
        """
        تنفيذ جميع المراحل.
        
        Returns:
            نتائج كل مرحلة
        """
        plan = self.create_plan()
        
        logger.info(
            "Parallel execution plan: %d stages in %d groups",
            plan.total_stages,
            plan.parallel_groups
        )
        
        for group_idx, group in enumerate(plan.execution_order):
            # Limit parallelism within group
            for i in range(0, len(group), self.max_parallel):
                batch = group[i:i + self.max_parallel]
                
                logger.info(
                    "Executing group %d batch: %s",
                    group_idx + 1,
                    ", ".join(batch)
                )
                
                # Run batch in parallel
                tasks = []
                for name in batch:
                    stage = self.stages[name]
                    tasks.append(self._run_stage(name, stage))
                
                results = await asyncio.gather(*tasks, return_exceptions=True)
                
                # Store results
                for name, result in zip(batch, results):
                    if isinstance(result, Exception):
                        self._results[name] = {
                            "status": "error",
                            "error": str(result),
                        }
                    else:
                        self._results[name] = result
                    
                    # Mark as completed in plan
                    plan.stages[name].completed = True
        
        return self._results
    
    def get_timings(self) -> Dict[str, float]:
        """أوقات تنفيذ كل مرحلة"""
        return self._timings.copy()
    
    def get_errors(self) -> Dict[str, str]:
        """أخطاء كل مرحلة"""
        return self._errors.copy()


# ═══════════════════════════════════════════════════════════
#                     Integration Helper
# ═══════════════════════════════════════════════════════════

async def run_stages_parallel(
    stages: Dict[str, "PipelineStage"],
    context: dict,
    max_parallel: int = 4,
) -> Dict[str, dict]:
    """
    Helper function لتشغيل المراحل بالتوازي.
    
    Example:
        >>> results = await run_stages_parallel(
        ...     stages={"dns": dns_stage, "enum": enum_stage},
        ...     context=ctx,
        ... )
    """
    executor = ParallelStageExecutor(stages, context, max_parallel)
    return await executor.execute()
