from __future__ import annotations

from typing import List

from recon_cli.pipeline.stage_base import Stage, StageError, StageResult
from recon_cli.pipeline.stage_normalize import NormalizeStage
from recon_cli.pipeline.stage_passive import PassiveEnumerationStage
from recon_cli.pipeline.stage_dedupe import DedupeStage
from recon_cli.pipeline.stage_resolve import ResolveStage
from recon_cli.pipeline.stage_enrichment import EnrichmentStage
from recon_cli.pipeline.stage_nmap import NmapStage
from recon_cli.pipeline.stage_http_probe import HttpProbeStage
from recon_cli.pipeline.stage_scoring import ScoringStage
from recon_cli.pipeline.stage_auth_discovery import AuthDiscoveryStage
from recon_cli.pipeline.stage_waf import WafProbeStage
from recon_cli.pipeline.stage_idor import IDORStage
from recon_cli.pipeline.stage_auth_matrix import AuthMatrixStage
from recon_cli.pipeline.stage_fuzz import FuzzStage
from recon_cli.pipeline.stage_active_intel import ActiveIntelligenceStage
from recon_cli.pipeline.stage_secrets import SecretsDetectionStage
from recon_cli.pipeline.stage_runtime_crawl import RuntimeCrawlStage
from recon_cli.pipeline.stage_js_intel import JSIntelligenceStage
from recon_cli.pipeline.stage_api_recon import APIReconStage
from recon_cli.pipeline.stage_param_mining import ParamMiningStage
from recon_cli.pipeline.stage_vuln_scan import VulnScanStage
from recon_cli.pipeline.stage_trim_results import TrimResultsStage
from recon_cli.pipeline.stage_correlation import CorrelationStage
from recon_cli.pipeline.stage_learning import LearningStage
from recon_cli.pipeline.stage_scanner import ScannerStage
from recon_cli.pipeline.stage_screenshots import ScreenshotStage
from recon_cli.pipeline.stage_finalize import FinalizeStage

PipelineStage = Stage

PIPELINE_STAGES: List[Stage] = [
    NormalizeStage(),
    PassiveEnumerationStage(),
    DedupeStage(),
    ResolveStage(),
    EnrichmentStage(),
    NmapStage(),
    HttpProbeStage(),
    ScoringStage(),
    AuthDiscoveryStage(),
    WafProbeStage(),
    IDORStage(),
    AuthMatrixStage(),
    FuzzStage(),
    ActiveIntelligenceStage(),
    SecretsDetectionStage(),
    RuntimeCrawlStage(),
    JSIntelligenceStage(),
    APIReconStage(),
    ParamMiningStage(),
    VulnScanStage(),
    TrimResultsStage(),
    CorrelationStage(),
    LearningStage(),
    ScannerStage(),
    ScreenshotStage(),
    FinalizeStage(),
]
