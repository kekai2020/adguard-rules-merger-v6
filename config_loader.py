"""V5 configuration loader — pydantic v2 validated YAML config.

V5 changes vs V4:
  - Removed dead knobs ``normalize_case`` / ``normalize_trailing_dot``
    (lowercasing and trailing-dot stripping are always on in V5).
  - Added ``wildcard_child_aggregation``, ``wildcard_promotion_threshold``,
    ``fail_threshold``, ``diff`` settings.
  - ``cascade_subdomains`` is now genuinely honored by the engine.
"""

from __future__ import annotations

from pathlib import Path
from typing import List, Literal
import os

import yaml
from pydantic import BaseModel, Field, model_validator

from merger.version import user_agent


class SourceConfig(BaseModel):
    name: str
    url: str
    enabled: bool = True
    category: str = "other"
    reputation: float = Field(default=0.5, ge=0.0, le=1.0)
    timeout: int | None = None
    id: int | None = None


class CacheConfig(BaseModel):
    enabled: bool = True
    directory: str = "cache"
    ttl_seconds: int = Field(default=0, ge=0)
    max_size_mb: int = Field(default=500, ge=0)
    # V5.3 — negative cache: dead sources are skipped for this many seconds
    # before retrying (0 = disabled, always retry).
    negative_ttl_seconds: int = Field(default=300, ge=0, le=86400)


class QualityFilterConfig(BaseModel):
    enabled: bool = True
    min_domain_length: int = Field(default=4, ge=1, le=100)
    max_domain_length: int = Field(default=253, ge=10, le=500)
    filter_localhost: bool = True
    filter_ip_rules: bool = False


class DedupConfig(BaseModel):
    # Only www-stripping is optional in V5. Lowercase / trailing-dot are always on.
    strip_www: bool = False


class AggregationConfig(BaseModel):
    enabled: bool = True
    min_aggregator_labels: int = Field(default=2, ge=1, le=5)
    # V5: fold ||*.sub.x.com^ under ||*.x.com^ / ||x.com^
    wildcard_child_aggregation: bool = True
    # V5: when >= N exact sibling subdomains exist, promote to ||*.parent^.
    # 0 disables promotion (default — conservative, avoids widening blocks).
    wildcard_promotion_threshold: int = Field(default=0, ge=0, le=10000)
    # V5.3 — PSL guard: skip wildcard promotion when the parent is a public
    # suffix itself (e.g. co.uk, com). Pure defense, zero impact on normal lists.
    psl_guard: bool = True
    # V5.3 — promotion mode: "count" (legacy, N siblings) or "pattern"
    # (N siblings + variant-label consistency >= min_ratio).
    promotion_mode: Literal["count", "pattern"] = "count"
    promotion_pattern_min_ratio: float = Field(default=0.8, ge=0.0, le=1.0)


class ConflictResolutionConfig(BaseModel):
    enabled: bool = True
    # V5: this flag now actually controls subdomain cascade.
    cascade_subdomains: bool = True


class AIAuditConfig(BaseModel):
    """V5: optional LLM-assisted domain classification (4th layer).

    Only called for domains where the offline classifier has low confidence
    (< min_confidence).  Requires an OpenAI-compatible API key.
    """
    enabled: bool = False
    api_key: str = ""
    base_url: str = "https://api.openai.com/v1"
    model: str = "gpt-4o-mini"
    # Only call AI when offline confidence is below this threshold
    min_confidence: float = Field(default=0.6, ge=0.0, le=1.0)
    # Safety cap: max domains to classify per run (cost control)
    max_domains: int = Field(default=100, ge=1, le=1000)


class WhitelistAuditConfig(BaseModel):
    """V5: multi-layer defense-in-depth audit of whitelist rules.

    Layers (all network layers run in parallel via asyncio.gather):
      1. DNS resolution          (free, keyless)
      2. URLhaus + ThreatFox     (free, keyless threat intel)
      3. RDAP domain age         (free, keyless, new-domain detection)
      4. MarketNow scam check    (free, keyless, typosquatting/social-engineering)
      5. DNSBL blocklists (V5.2) (free, keyless: Spamhaus DBL + SURBL)
      6. VirusTotal              (optional, needs API key)
      7. Offline tldextract      (free, PSL-based classification)
      8. AI / LLM                (optional, needs API key, low-confidence only)

    Disabled by default because it adds network requests and latency.
    """
    enabled: bool = False
    concurrency: int = Field(default=10, ge=1, le=50)
    use_dns: bool = True
    use_urlhaus: bool = True
    use_threatfox: bool = True
    use_rdap: bool = True
    # MarketNow scam/phishing check (free, keyless, social-engineering detection)
    use_scam_check: bool = True
    # V5.2 — DNSBL lookups (Spamhaus DBL + SURBL, free DNS queries)
    use_dnsbl: bool = True
    # V5.2 — persist audit results (skip re-querying unchanged domains, 24h TTL)
    cache_results: bool = True
    # URLhaus / ThreatFox are rate-limited; delay between requests in seconds.
    urlhaus_delay: float = Field(default=1.0, ge=0.0, le=10.0)
    # VirusTotal (optional, needs API key)
    use_virustotal: bool = False
    virustotal_api_key: str = ""
    # AI classification (optional, needs API key)
    ai: AIAuditConfig = Field(default_factory=AIAuditConfig)
    # Domains younger than this (days) are flagged as "new" (higher risk)
    new_domain_threshold_days: int = Field(default=30, ge=1, le=3650)
    # V5.3 — threat-intel mode: "api" (per-domain HTTP) or "auto" (feed
    # dataset with API fallback). Default "api" preserves existing behavior.
    ti_mode: Literal["api", "auto"] = "api"
    feed_ttl_seconds: int = Field(default=3600, ge=60, le=86400)


class WhitelistOutputConfig(BaseModel):
    """V5: control graded whitelist output files.

    When whitelist_audit is enabled, the auditor assigns each whitelist rule a
    rating (safe/suspicious/malicious/unknown) and a category (advertising,
    analytics, cdn, ...).  This config controls which sub-files are written.
    """
    enabled: bool = True
    # Write whitelist_safe.txt / whitelist_suspicious.txt / whitelist_malicious.txt
    by_rating: bool = True
    # Write whitelist_by_category/<rating>_<category>.txt (safe categories only
    # by default; set include_all_ratings=true to also split suspicious/malicious)
    by_category: bool = True
    include_all_ratings: bool = False
    # Which categories to split out (empty = all 9 categories)
    categories: List[str] = Field(default_factory=list)


class DownloadConfig(BaseModel):
    user_agent: str = Field(default_factory=user_agent)
    retry_count: int = Field(default=2, ge=0, le=5)
    retry_delay: float = Field(default=1.5, ge=0.1, le=10.0)
    # V5.2: hard per-source time budget covering ALL retry attempts
    # (0 = unlimited). Exceeded → fall back to the stale cache.
    source_deadline: float = Field(default=120.0, ge=0.0, le=3600.0)
    # V5.3 — retry backoff strategy: "linear" (legacy) or "exponential".
    backoff: str = "linear"


class OutputConfig(BaseModel):
    directory: str = "output"
    formats: List[str] = Field(
        default_factory=lambda: [
            "adguard", "whitelist", "hosts", "domains",
            "clash", "surge", "smartdns",
        ]
    )
    tiered: bool = True
    report: bool = True
    write_diff: bool = False

    @model_validator(mode="after")
    def _check_formats(self) -> "OutputConfig":
        valid = {
            "adguard", "whitelist", "hosts", "domains",
            "clash", "surge", "smartdns",
        }
        invalid = set(self.formats) - valid
        if invalid:
            raise ValueError(f"Invalid output formats: {invalid}. Valid: {valid}")
        return self


class MergeConfig(BaseModel):
    sources: List[SourceConfig] = Field(default_factory=list)
    cache: CacheConfig = Field(default_factory=CacheConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)
    dedup: DedupConfig = Field(default_factory=DedupConfig)
    quality_filter: QualityFilterConfig = Field(default_factory=QualityFilterConfig)
    aggregation: AggregationConfig = Field(default_factory=AggregationConfig)
    conflict_resolution: ConflictResolutionConfig = Field(default_factory=ConflictResolutionConfig)
    whitelist_audit: WhitelistAuditConfig = Field(default_factory=WhitelistAuditConfig)
    whitelist_output: WhitelistOutputConfig = Field(default_factory=WhitelistOutputConfig)
    download: DownloadConfig = Field(default_factory=DownloadConfig)
    timeout: int = Field(default=60, ge=1)
    max_concurrency: int = Field(default=50, ge=1, le=200)
    # V5: abort if more than this fraction of sources fails (0.0-1.0).
    fail_threshold: float = Field(default=0.5, ge=0.0, le=1.0)
    # V5: path to a previous domains.txt for added/removed diff (optional).
    diff_against: str | None = None

    @model_validator(mode="after")
    def _check(self) -> "MergeConfig":
        enabled = [s for s in self.sources if s.enabled]
        if not enabled:
            raise ValueError("At least one enabled source is required")
        urls = [s.url for s in enabled]
        if len(urls) != len(set(urls)):
            raise ValueError("Duplicate source URLs detected")
        ids = [s.id for s in enabled if s.id is not None]
        if len(ids) != len(set(ids)):
            raise ValueError("Duplicate source ids detected")
        valid_cats = {"ads", "malware", "tracking", "phishing", "mining", "other"}
        invalid_cats = {s.category for s in enabled if s.category not in valid_cats}
        if invalid_cats:
            raise ValueError(f"Invalid categories: {invalid_cats}. Valid: {valid_cats}")
        # Secrets from environment when YAML left them blank (never commit keys).
        if not self.whitelist_audit.virustotal_api_key:
            self.whitelist_audit.virustotal_api_key = os.environ.get("VIRUSTOTAL_API_KEY", "")
        if not self.whitelist_audit.ai.api_key:
            self.whitelist_audit.ai.api_key = (
                os.environ.get("OPENAI_API_KEY", "")
                or os.environ.get("LLM_API_KEY", "")
            )
        return self


def load_config(path: str) -> MergeConfig:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Config not found: {path}")
    raw = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    try:
        return MergeConfig(**raw)
    except Exception as e:  # noqa: BLE001
        raise ValueError(f"Config validation failed: {e}") from e


def validate_config(path: str) -> List[str]:
    """Validate a config file, returning a list of problems (empty = valid).

    V5.3 C12: aggregates multiple issues instead of stopping at the first.
    """
    problems: List[str] = []
    try:
        cfg = load_config(path)
    except (FileNotFoundError, ValueError) as e:
        return [str(e)]

    for dir_path, label in [(cfg.cache.directory, "cache"),
                            (cfg.output.directory, "output")]:
        if os.path.isdir(dir_path) and not os.access(dir_path, os.W_OK):
            problems.append(f"{label} directory '{dir_path}' is not writable")

    enabled = [s for s in cfg.sources if s.enabled]
    if not enabled:
        problems.append("No enabled sources")

    return problems
