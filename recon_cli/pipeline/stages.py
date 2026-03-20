from __future__ import annotations

from typing import List

from recon_cli.pipeline.stage_base import Stage
from recon_cli.pipeline.stage_normalize import NormalizeStage
from recon_cli.pipeline.stage_passive import PassiveEnumerationStage
from recon_cli.pipeline.stage_subdomain_permute import SubdomainPermuteStage
from recon_cli.pipeline.stage_ct_asn import CTPivotStage
from recon_cli.pipeline.stage_dedupe import DedupeStage
from recon_cli.pipeline.stage_resolve import ResolveStage
from recon_cli.pipeline.stage_enrichment import EnrichmentStage
from recon_cli.pipeline.stage_cloud_assets import CloudAssetDiscoveryStage
from recon_cli.pipeline.stage_nmap import NmapStage
from recon_cli.pipeline.stage_http_probe import HttpProbeStage
from recon_cli.pipeline.stage_vhost import VHostDiscoveryStage
from recon_cli.pipeline.stage_origin_discovery import OriginDiscoveryStage
from recon_cli.pipeline.stage_github_recon import GitHubReconStage
from recon_cli.pipeline.stage_takeover import TakeoverStage
from recon_cli.pipeline.stage_scoring import ScoringStage
from recon_cli.pipeline.stage_security_headers import SecurityHeadersStage
from recon_cli.pipeline.stage_tls_hygiene import TLSHygieneStage
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
from recon_cli.pipeline.stage_graphql import GraphQLReconStage
from recon_cli.pipeline.stage_graphql_exploit import GraphQLExploitStage
from recon_cli.pipeline.stage_api_schema_probe import ApiSchemaProbeStage
from recon_cli.pipeline.stage_oauth_discovery import OAuthDiscoveryStage
from recon_cli.pipeline.stage_ws_grpc_discovery import WsGrpcDiscoveryStage
from recon_cli.pipeline.stage_param_mining import ParamMiningStage
from recon_cli.pipeline.stage_html_forms import HTMLFormMiningStage
from recon_cli.pipeline.stage_upload_probe import UploadProbeStage
from recon_cli.pipeline.stage_vuln_scan import VulnScanStage
from recon_cli.pipeline.stage_cms_scan import CMSScanStage
from recon_cli.pipeline.stage_trim_results import TrimResultsStage
from recon_cli.pipeline.stage_rescore import RescoreStage
from recon_cli.pipeline.stage_correlation import CorrelationStage
from recon_cli.pipeline.stage_learning import LearningStage
from recon_cli.pipeline.stage_scanner import ScannerStage
from recon_cli.pipeline.stage_verify_findings import VerifyFindingsStage
from recon_cli.pipeline.stage_extended_validation import ExtendedValidationStage
from recon_cli.pipeline.stage_idor_validator import IDORValidatorStage
from recon_cli.pipeline.stage_ssrf_validator import SSRFValidatorStage
from recon_cli.pipeline.stage_exploit_validation import ExploitValidationStage
from recon_cli.pipeline.stage_open_redirect_validator import OpenRedirectValidatorStage
from recon_cli.pipeline.stage_auth_bypass_validator import AuthBypassValidatorStage
from recon_cli.pipeline.stage_secret_exposure_validator import (
    SecretExposureValidatorStage,
)
from recon_cli.pipeline.stage_screenshots import ScreenshotStage
from recon_cli.pipeline.stage_finalize import FinalizeStage

PipelineStage = Stage

PIPELINE_STAGES: List[Stage] = [
    NormalizeStage(),
    PassiveEnumerationStage(),
    SubdomainPermuteStage(),
    CTPivotStage(),
    DedupeStage(),
    ResolveStage(),
    EnrichmentStage(),
    CloudAssetDiscoveryStage(),
    NmapStage(),
    HttpProbeStage(),
    VHostDiscoveryStage(),
    OriginDiscoveryStage(),
    GitHubReconStage(),
    TakeoverStage(),
    ScoringStage(),
    SecurityHeadersStage(),
    TLSHygieneStage(),
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
    GraphQLReconStage(),
    GraphQLExploitStage(),
    ApiSchemaProbeStage(),
    OAuthDiscoveryStage(),
    WsGrpcDiscoveryStage(),
    ParamMiningStage(),
    HTMLFormMiningStage(),
    UploadProbeStage(),
    VulnScanStage(),
    CMSScanStage(),
    RescoreStage(),
    TrimResultsStage(),
    CorrelationStage(),
    LearningStage(),
    ScannerStage(),
    VerifyFindingsStage(),
    ExtendedValidationStage(),
    IDORValidatorStage(),
    SSRFValidatorStage(),
    OpenRedirectValidatorStage(),
    AuthBypassValidatorStage(),
    SecretExposureValidatorStage(),
    ExploitValidationStage(),
    ScreenshotStage(),
    FinalizeStage(),
]
