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
from recon_cli.utils.pipeline_trace import (
    current_trace_recorder,
    current_parent_span_id,
)
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, TYPE_CHECKING

if TYPE_CHECKING:
    from recon_cli.pipeline.stage_base import Stage as PipelineStage

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

    # تعريف التبعيات المعروفة (تتوافق مع أسماء المراحل الفعلية)
    STAGE_DEPENDENCIES = {
        # البداية
        "normalize_scope": set(),
        "passive_enumeration": {"normalize_scope"},
        "github_recon": {"normalize_scope"},
        "subdomain_permute": {"passive_enumeration"},
        "ct_asn_pivot": {"subdomain_permute"},
        "dedupe_canonicalize": {"ct_asn_pivot"},
        # بعد dedupe
        "dns_resolve": {"dedupe_canonicalize"},
        "http_probe": {"dedupe_canonicalize"},
        "nmap_scan": {"dedupe_canonicalize"},
        "vhost_discovery": {"http_probe"},
        "origin_discovery": {"dedupe_canonicalize"},
        # بعد DNS/HTTP
        "asset_enrichment": {"dns_resolve"},
        "cloud_asset_discovery": {"asset_enrichment"},
        "takeover_check": {"dns_resolve", "http_probe"},
        # Tagging/scoring (تحتاج نتائج المراحل السابقة كاملة)
        "scoring_tagging": {
            "http_probe",
            "asset_enrichment",
            "cloud_asset_discovery",
            "takeover_check",
            "nmap_scan",
            "vhost_discovery",
        },
        "security_headers": {"scoring_tagging"},
        "tls_hygiene": {"security_headers"},
        # مراحل تحليل/هجوم لاحقة (مرتبة لتقليل الضغط على الهدف)
        "auth_discovery": {"scoring_tagging"},
        "active_auth": {"auth_discovery"},
        "waf_probe": {"active_auth"},
        "idor_probe": {"waf_probe"},
        "auth_matrix": {"idor_probe"},
        "fuzzing": {"auth_matrix"},
        "active_intelligence": {"fuzzing"},
        "secrets_detection": {"active_intelligence"},
        "runtime_crawl": {"secrets_detection"},
        "js_intelligence": {"runtime_crawl"},
        "api_recon": {"js_intelligence"},
        "graphql_recon": {"api_recon"},
        "graphql_exploit": {"graphql_recon"},
        "api_schema_probe": {"graphql_exploit"},
        "oauth_discovery": {"api_schema_probe"},
        "ws_grpc_discovery": {"oauth_discovery"},
        "param_mining": {"ws_grpc_discovery"},
        "html_form_mining": {"param_mining"},
        "upload_probe": {"html_form_mining"},
        "vuln_scan": {"upload_probe"},
        "cms_scan": {"vuln_scan"},
        "post_scoring": {"cms_scan"},
        "trim_results": {"post_scoring"},
        "correlation": {"trim_results"},
        "learning": {"correlation"},
        "scanner": {"learning"},
        "verify_findings": {"scanner"},
        "extended_validation": {"verify_findings"},
        "idor_validator": {"extended_validation"},
        "ssrf_validator": {"extended_validation"},
        "open_redirect_validator": {"extended_validation"},
        "auth_bypass_validator": {"extended_validation"},
        "secret_exposure_validator": {"extended_validation"},
        "exploit_validation": {
            "idor_validator",
            "ssrf_validator",
            "open_redirect_validator",
            "auth_bypass_validator",
            "secret_exposure_validator",
        },
        "screenshots": {"exploit_validation"},
        "finalize": {"screenshots"},
    }

    def __init__(self, dependency_map: Optional[Dict[str, Set[str]]] = None) -> None:
        self.dependency_map = dependency_map or self.STAGE_DEPENDENCIES

    def resolve(self, stages: List["PipelineStage"]) -> List[List[str]]:
        """
        حل التبعيات وإرجاع مجموعات التنفيذ.
        تدعم التبعيات الديناميكية بناءً على نوع البيانات.
        """
        stage_names = [s.name for s in stages]
        available = set(stage_names)
        remaining = set(stage_names)
        execution_order = []

        # Build dynamic dependency map
        dynamic_deps: Dict[str, Set[str]] = {s.name: set() for s in stages}

        # Mapping of data_type -> stages that provide it
        providers = defaultdict(set)
        for s in stages:
            for p in getattr(s, "provides", []):
                providers[p].add(s.name)

        for s in stages:
            # 1. Start with hardcoded dependencies if any
            hard_deps = self.dependency_map.get(s.name, set())
            for d in hard_deps:
                if d in available:
                    dynamic_deps[s.name].add(d)

            # 2. Add dynamic dependencies based on 'requires'
            for req in getattr(s, "requires", []):
                for provider in providers[req]:
                    if provider != s.name:  # Don't depend on self
                        dynamic_deps[s.name].add(provider)

        while remaining:
            # Find stages with satisfied dependencies
            ready = []
            for name in remaining:
                deps = dynamic_deps.get(name, set())
                # Check if all dependencies are in the 'completed' set (available - remaining)
                if deps.issubset(available - remaining):
                    ready.append(name)

            if not ready:
                # Deadlock detection
                logger.warning(
                    "Dynamic resolver found deadlock or unresolved deps for: %s",
                    remaining,
                )
                for name in sorted(remaining):
                    execution_order.append([name])
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
        execution_order = self.resolver.resolve(stage_names)  # type: ignore[arg-type]

        # Create stage nodes
        nodes = {}
        for name, stage in self.stages.items():
            deps = self.resolver.dependency_map.get(name, set())
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
                result = await loop.run_in_executor(None, stage.run, self.context)  # type: ignore[arg-type]
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
            plan.parallel_groups,
        )

        for group_idx, group in enumerate(plan.execution_order):
            # Limit parallelism within group
            for i in range(0, len(group), self.max_parallel):
                batch = group[i : i + self.max_parallel]

                logger.info(
                    "Executing group %d batch: %s", group_idx + 1, ", ".join(batch)
                )

                recorder = current_trace_recorder()
                parent_span_id = current_parent_span_id()
                if recorder is not None:
                    recorder.emit(
                        "parallel.batch.started",
                        {
                            "group": group_idx + 1,
                            "stages": batch,
                            "parent_span_id": parent_span_id,
                        },
                    )

                # Run batch in parallel
                tasks = []
                for name in batch:
                    stage = self.stages[name]
                    tasks.append(self._run_stage(name, stage))

                results = await asyncio.gather(*tasks, return_exceptions=True)

                if recorder is not None:
                    recorder.emit(
                        "parallel.batch.finished",
                        {
                            "group": group_idx + 1,
                            "stages": batch,
                            "parent_span_id": parent_span_id,
                        },
                    )

                # Store results
                for name, result in zip(batch, results):
                    if isinstance(result, Exception):
                        self._results[name] = {
                            "status": "error",
                            "error": str(result),
                        }
                    else:
                        self._results[name] = result  # type: ignore[assignment]

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
