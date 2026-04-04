from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional, Union
from pydantic import BaseModel, ConfigDict, Field, TypeAdapter
from recon_cli.utils import time as time_utils


class BaseResult(BaseModel):
    """Base model for all results in results.jsonl."""

    model_config = ConfigDict(extra="allow")

    type: str
    timestamp: str = Field(default_factory=time_utils.iso_now)
    source: Optional[str] = None
    tags: List[str] = Field(default_factory=list)


class MetaResult(BaseResult):
    """Schema version and metadata."""

    type: Literal["meta"] = "meta"
    schema_version: str = "1.0.0"


class HostResult(BaseResult):
    """Host discovery result."""

    type: Literal["hostname", "host", "asset"] = "hostname"
    hostname: str
    ip: Optional[str] = None
    resolved: bool = False
    live: bool = False


class URLResult(BaseResult):
    """URL discovery result."""

    type: Literal["url"] = "url"
    url: str
    hostname: Optional[str] = None
    status_code: Optional[int] = None
    title: Optional[str] = None
    server: Optional[str] = None
    content_type: Optional[str] = None
    tls: bool = False


class FindingResult(BaseResult):
    """Security finding or vulnerability."""

    type: Literal["finding"] = "finding"
    finding_type: str
    severity: Literal[
        "info", "low", "medium", "high", "critical", "unknown", "noise"
    ] = "info"
    confidence: Union[float, str] = 0.5
    confidence_label: Optional[str] = None
    confidence_score: Optional[float] = None
    finding_fingerprint: Optional[str] = None
    hostname: Optional[str] = None
    url: Optional[str] = None
    matched_at: Optional[str] = None
    description: Optional[str] = None
    title: Optional[str] = None
    template_id: Optional[str] = None
    reference: Optional[str] = None
    extracted: Optional[str] = None
    evidence: Optional[Any] = None
    proof: Optional[str] = None
    repro_cmd: Optional[str] = None


class SignalResult(BaseResult):
    """Pipeline internal signal."""

    type: Literal["signal"] = "signal"
    signal_id: str
    signal_type: str
    target_type: str
    target: str
    confidence: float = 0.5
    evidence: Optional[Dict[str, Any]] = None
    metadata: Optional[Dict[str, Any]] = None


class SecretResult(BaseResult):
    """Exposed secret or credential."""

    type: Literal["secret", "credential"] = "secret"
    secret_type: Optional[str] = None
    file_path: Optional[str] = None
    url: Optional[str] = None
    line_number: Optional[int] = None
    match: Optional[str] = None
    entropy: Optional[float] = None


class APIResult(BaseResult):
    """API discovery result."""

    type: Literal["api", "api_spec"] = "api"
    url: str
    hostname: Optional[str] = None
    method: Optional[str] = None
    auth_required: bool = False


class FormResult(BaseResult):
    """HTML form discovery result."""

    type: Literal["form", "auth_form"] = "form"
    url: str
    action: Optional[str] = None
    method: str = "GET"
    fields: List[str] = Field(default_factory=list)


class ParameterResult(BaseResult):
    """Discovered HTTP parameter."""

    type: Literal["parameter"] = "parameter"
    name: str
    source: Optional[str] = None


class ParamMutationResult(BaseResult):
    """Parameter mutation discovery."""

    type: Literal["param_mutation"] = "param_mutation"
    name: str
    category: Optional[str] = None
    source: Optional[str] = None


class CMSResult(BaseResult):
    """CMS discovery result."""

    type: Literal["cms"] = "cms"
    hostname: str
    cms: str
    source: Optional[str] = None


class ScreenshotResult(BaseResult):
    """URL screenshot metadata."""

    type: Literal["screenshot"] = "screenshot"
    screenshot_path: str
    url: Optional[str] = None
    hostname: Optional[str] = None


class RuntimeCrawlResult(BaseResult):
    """Runtime crawl discovery."""

    type: Literal["runtime_crawl", "runtime_crawl_profile"] = "runtime_crawl"
    url: str
    auth_profile: Optional[str] = None


class IDORSuspectResult(BaseResult):
    """Suspected IDOR vulnerability."""

    type: Literal["idor_suspect"] = "idor_suspect"
    url: str
    auth: Optional[str] = None
    source: Optional[str] = None


class AssetEnrichmentResult(BaseResult):
    """Enriched asset data."""

    type: Literal["asset_enrichment"] = "asset_enrichment"
    hostname: str
    ip: Optional[str] = None


class LearningPredictionResult(BaseResult):
    """ML-based discovery prediction."""

    type: Literal["learning_prediction"] = "learning_prediction"
    hostname: str


class IPPrefixResult(BaseResult):
    """IP prefix discovery."""

    type: Literal["ip_prefix"] = "ip_prefix"
    prefix: str
    asn: Optional[str] = None
    source: Optional[str] = None


class AttackPathResult(BaseResult):
    """Vulnerability attack path discovery."""

    type: Literal["attack_path"] = "attack_path"
    entry_url: str
    sink_url: str
    finding_type: str
    hostname: Optional[str] = None


# Union type for all possible results in the JSONL file
AnyResult = Union[
    MetaResult,
    HostResult,
    URLResult,
    FindingResult,
    SignalResult,
    SecretResult,
    APIResult,
    FormResult,
    ParameterResult,
    ParamMutationResult,
    CMSResult,
    ScreenshotResult,
    RuntimeCrawlResult,
    IDORSuspectResult,
    AssetEnrichmentResult,
    LearningPredictionResult,
    IPPrefixResult,
    AttackPathResult,
]

# Type adapter for validation
result_adapter: TypeAdapter = TypeAdapter(AnyResult)


def validate_result(data: Dict[str, Any]) -> Dict[str, Any]:
    """Validate a result dictionary against Pydantic models."""
    return result_adapter.validate_python(data).model_dump(exclude_none=False)
