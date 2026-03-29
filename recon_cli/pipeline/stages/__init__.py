from __future__ import annotations

from typing import List

from recon_cli.pipeline.stages.core.stage_base import Stage
from recon_cli.pipeline.stages.core.stage_normalize import NormalizeStage
from recon_cli.pipeline.stages.discovery.stage_passive import PassiveEnumerationStage
from recon_cli.pipeline.stages.discovery.stage_subdomain_permute import SubdomainPermuteStage
from recon_cli.pipeline.stages.discovery.stage_ct_asn import CTPivotStage
from recon_cli.pipeline.stages.core.stage_dedupe import DedupeStage
from recon_cli.pipeline.stages.discovery.stage_resolve import ResolveStage
from recon_cli.pipeline.stages.core.stage_enrichment import EnrichmentStage
from recon_cli.pipeline.stages.discovery.stage_cloud_assets import CloudAssetDiscoveryStage
from recon_cli.pipeline.stages.discovery.stage_cloud_looter import CloudBucketLooterStage
from recon_cli.pipeline.stages.discovery.stage_nmap import NmapStage
from recon_cli.pipeline.stages.discovery.stage_http_probe import HttpProbeStage
from recon_cli.pipeline.stages.discovery.stage_vhost import VHostDiscoveryStage
from recon_cli.pipeline.stages.discovery.stage_origin_discovery import OriginDiscoveryStage
from recon_cli.pipeline.stages.discovery.stage_github_recon import GitHubReconStage
from recon_cli.pipeline.stages.vuln.stage_takeover import TakeoverStage
from recon_cli.pipeline.stages.core.stage_scoring import ScoringStage
from recon_cli.pipeline.stages.vuln.stage_security_headers import SecurityHeadersStage
from recon_cli.pipeline.stages.vuln.stage_tls_hygiene import TLSHygieneStage
from recon_cli.pipeline.stages.auth.stage_auth_discovery import AuthDiscoveryStage
from recon_cli.pipeline.stages.auth.stage_active_auth import ActiveAuthStage
from recon_cli.pipeline.stages.vuln.stage_waf import WafProbeStage
from recon_cli.pipeline.stages.vuln.stage_waf_bypass import WafBypassStage
from recon_cli.pipeline.stages.vuln.stage_http_smuggling import HttpSmugglingStage
from recon_cli.pipeline.stages.vuln.stage_host_injection import HostInjectionStage
from recon_cli.pipeline.stages.vuln.stage_race_condition import RaceConditionStage
from recon_cli.pipeline.stages.vuln.stage_cache_vuln import WebCacheVulnStage
from recon_cli.pipeline.stages.vuln.stage_idor import IDORStage
from recon_cli.pipeline.stages.auth.stage_auth_matrix import AuthMatrixStage
from recon_cli.pipeline.stages.discovery.stage_wordlist_miner import WordlistMinerStage
from recon_cli.pipeline.stages.vuln.stage_fuzz import FuzzStage
from recon_cli.pipeline.stages.discovery.stage_active_intel import ActiveIntelligenceStage
from recon_cli.pipeline.stages.vuln.stage_secrets import SecretsDetectionStage
from recon_cli.pipeline.stages.discovery.stage_runtime_crawl import RuntimeCrawlStage
from recon_cli.pipeline.stages.discovery.stage_js_intel import JSIntelligenceStage
from recon_cli.pipeline.stages.discovery.stage_headless_crawl import HeadlessCrawlStage
from recon_cli.pipeline.stages.discovery.stage_api_recon import APIReconStage
from recon_cli.pipeline.stages.discovery.stage_graphql import GraphQLReconStage
from recon_cli.pipeline.stages.vuln.stage_graphql_exploit import GraphQLExploitStage
from recon_cli.pipeline.stages.discovery.stage_api_schema_probe import ApiSchemaProbeStage
from recon_cli.pipeline.stages.discovery.stage_api_reconstructor import ApiSchemaReconstructorStage
from recon_cli.pipeline.stages.vuln.stage_api_logic_fuzzer import ApiLogicFuzzerStage
from recon_cli.pipeline.stages.vuln.stage_mass_assignment import MassAssignmentStage
from recon_cli.pipeline.stages.vuln.stage_second_order_injection import SecondOrderInjectionStage
from recon_cli.pipeline.stages.vuln.stage_advanced_idor import AdvancedIDORStage
from recon_cli.pipeline.stages.vuln.stage_timing_attacks import TimingAttackStage
from recon_cli.pipeline.stages.auth.stage_oauth_discovery import OAuthDiscoveryStage
from recon_cli.pipeline.stages.auth.stage_oauth_vuln import OAuthVulnerabilityStage
from recon_cli.pipeline.stages.auth.stage_jwt_vuln import JWTVulnerabilityStage
from recon_cli.pipeline.stages.discovery.stage_ws_grpc_discovery import WsGrpcDiscoveryStage
from recon_cli.pipeline.stages.discovery.stage_param_mining import ParamMiningStage
from recon_cli.pipeline.stages.discovery.stage_html_forms import HTMLFormMiningStage
from recon_cli.pipeline.stages.auth.stage_auth_bypass_tech import AuthBypassTechniqueStage
from recon_cli.pipeline.stages.vuln.stage_upload_probe import UploadProbeStage
from recon_cli.pipeline.stages.vuln.stage_vuln_scan import VulnScanStage
from recon_cli.pipeline.stages.discovery.stage_cms_scan import CMSScanStage
from recon_cli.pipeline.stages.vuln.stage_proto_pollution import ProtoPollutionStage
from recon_cli.pipeline.stages.discovery.stage_favicon_recon import FaviconReconStage
from recon_cli.pipeline.stages.discovery.stage_quic_discovery import QuicDiscoveryStage
from recon_cli.pipeline.stages.core.stage_trim_results import TrimResultsStage
from recon_cli.pipeline.stages.core.stage_rescore import RescoreStage
from recon_cli.pipeline.stages.core.stage_correlation import CorrelationStage
from recon_cli.pipeline.stages.vuln.stage_scanner import ScannerStage
from recon_cli.pipeline.stages.vuln.stage_nuclei import NucleiStage
from recon_cli.pipeline.stages.core.stage_verify_findings import VerifyFindingsStage
from recon_cli.pipeline.stages.validation.stage_exploit_validation import ExploitValidationStage
from recon_cli.pipeline.stages.validation.stage_extended_validation import ExtendedValidationStage
from recon_cli.pipeline.stages.validation.stage_idor_validator import IDORValidatorStage
from recon_cli.pipeline.stages.validation.stage_ssrf_validator import SSRFValidatorStage
from recon_cli.pipeline.stages.vuln.stage_ssrf_pivot import SSRFPivotStage
from recon_cli.pipeline.stages.validation.stage_open_redirect_validator import OpenRedirectValidatorStage
from recon_cli.pipeline.stages.validation.stage_input_validator import InputValidatorStage
from recon_cli.pipeline.stages.validation.stage_auth_bypass_validator import AuthBypassValidatorStage
from recon_cli.pipeline.stages.validation.stage_secret_exposure_validator import (
    SecretExposureValidatorStage,
)
from recon_cli.pipeline.stages.core.stage_decision_engine import DecisionEngineStage
from recon_cli.pipeline.stages.core.stage_screenshots import ScreenshotStage
from recon_cli.pipeline.stages.core.stage_finalize import FinalizeStage
from recon_cli.pipeline.stages.core.stage_poc_generator import POCGeneratorStage

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
    CloudBucketLooterStage(),
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
    AuthBypassTechniqueStage(),
    ActiveAuthStage(),
    WafProbeStage(),
    WafBypassStage(),
    HttpSmugglingStage(),
    HostInjectionStage(),
    RaceConditionStage(),
    WebCacheVulnStage(),
    IDORStage(),
    AuthMatrixStage(),
    WordlistMinerStage(),
    FuzzStage(),
    ActiveIntelligenceStage(),
    SecretsDetectionStage(),
    RuntimeCrawlStage(),
    JSIntelligenceStage(),
    HeadlessCrawlStage(),
    APIReconStage(),
    GraphQLReconStage(),
    GraphQLExploitStage(),
    ApiSchemaProbeStage(),
    ApiSchemaReconstructorStage(),
    ApiLogicFuzzerStage(),
    MassAssignmentStage(),
    SecondOrderInjectionStage(),
    AdvancedIDORStage(),
    TimingAttackStage(),
    OAuthDiscoveryStage(),
    OAuthVulnerabilityStage(),
    JWTVulnerabilityStage(),
    WsGrpcDiscoveryStage(),
    ParamMiningStage(),
    HTMLFormMiningStage(),
    UploadProbeStage(),
    VulnScanStage(),
    CMSScanStage(),
    ProtoPollutionStage(),
    FaviconReconStage(),
    QuicDiscoveryStage(),
    RescoreStage(),
    TrimResultsStage(),
    CorrelationStage(),
    ScannerStage(),
    NucleiStage(),
    VerifyFindingsStage(),
    ExtendedValidationStage(),
    IDORValidatorStage(),
    SSRFValidatorStage(),
    SSRFPivotStage(),
    OpenRedirectValidatorStage(),
    InputValidatorStage(),
    AuthBypassValidatorStage(),
    SecretExposureValidatorStage(),
    ExploitValidationStage(),
    DecisionEngineStage(),
    ScreenshotStage(),
    FinalizeStage(),
    POCGeneratorStage(),
]
