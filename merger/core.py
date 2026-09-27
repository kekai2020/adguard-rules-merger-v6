"""V5.1 async rule engine — fetch, parse, dedup, aggregate, resolve conflicts.

Pipeline:
  1. Concurrent fetch + parse off the event loop (aiohttp, ETag/SHA256 cache,
     parsed-rule sidecar so unchanged sources skip the regex parser).
  2. Dedup by key (normalized_domain, wildcard, modifiers); three counters.
  3. Upward aggregation (exact child, wildcard child, optional promotion).
  4. Whitelist split + conflict resolution.
  5. Category merge with security-first priority.
  6. Stable sort via tuple key, per-source contribution stats, optional diff.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import re
import time
from itertools import chain
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import aiohttp

from .cache import SourceCache
from .models import Rule, SourceMeta, iter_source_keys
from .parser import RuleParser
from .version import user_agent as default_user_agent

logger = logging.getLogger(__name__)

_MIN_AGGREGATOR_LABELS = 2


def _iter_parents(norm: str, min_labels: int = 2):
    """Yield strict parent domains, most-specific first.

    Stops as soon as a parent would have fewer than ``min_labels`` labels,
    so callers don't build (and then filter) the full parent list.
    """
    parts = norm.split(".")
    n = len(parts)
    for i in range(1, n):
        if n - i < min_labels:
            break
        yield ".".join(parts[i:])


@dataclass
class SourceFailure:
    url: str
    name: str
    error: str
    error_type: str = "unknown"


def classify_source_error(err: BaseException) -> str:
    """Map a fetch exception to a coarse error_type for CI triage."""
    msg = str(err).lower()
    if isinstance(err, asyncio.TimeoutError) or "timeout" in msg or "deadline" in msg:
        return "timeout"
    if "404" in msg:
        return "not_found"
    if "403" in msg or "401" in msg:
        return "auth"
    if "name or service not known" in msg or "nodename nor servname" in msg \
            or "getaddrinfo failed" in msg or "name resolution" in msg:
        return "dns"
    if "connect" in msg or "connection" in msg:
        return "network"
    return "unknown"


@dataclass
class SourceContribution:
    name: str
    url: str
    category: str
    raw_rules: int = 0
    unique_rules: int = 0
    shared_rules: int = 0


@dataclass
class MergeOutcome:
    """Result of a merge run — all counts and rule lists produced by the engine.

    ``blocks``/``allows`` are the final deduplicated, aggregated, sorted rule
    lists ready for export.  ``regex_*`` hold regex rules (kept separate because
    they are not subject to domain aggregation).  The ``*_merged``/``*_dropped``
    counters feed the stats report.  ``added``/``removed`` (and ``added_allows``/
    ``removed_allows``, V5.3 C10) are diff lines against the previous output
    directory, used by the CLI summary table.  ``content_version`` is the
    short version stamp written into ``stats.json``.
    """
    blocks: List[Rule] = field(default_factory=list)
    allows: List[Rule] = field(default_factory=list)
    regex_blocks: List[Rule] = field(default_factory=list)
    regex_allows: List[Rule] = field(default_factory=list)
    raw_count: int = 0
    sources_ok: int = 0
    sources_total: int = 0
    sources_cached: int = 0
    exact_merged: int = 0
    normalized_merged: int = 0
    regex_merged: int = 0
    aggregated: int = 0
    wildcard_aggregated: int = 0
    wildcard_promoted: int = 0
    conflict_resolved: int = 0
    whitelist_blocked: int = 0
    pattern_dropped: int = 0
    quality_dropped: int = 0
    css_dropped: int = 0
    comment_dropped: int = 0
    modifier_stripped: int = 0
    badfilter_removed: int = 0
    conflicts: List[Dict[str, Any]] = field(default_factory=list)
    failed_sources: List[Dict[str, str]] = field(default_factory=list)
    contributions: List[Dict[str, Any]] = field(default_factory=list)
    source_overlap: Dict[str, Any] = field(default_factory=dict)
    modifier_stats: Dict[str, int] = field(default_factory=dict)
    whitelist_audit: Dict[str, Any] = field(default_factory=dict)
    added: List[str] = field(default_factory=list)
    removed: List[str] = field(default_factory=list)
    added_allows: List[str] = field(default_factory=list)
    removed_allows: List[str] = field(default_factory=list)
    elapsed: float = 0.0
    content_version: str = ""


class AsyncRuleEngine:
    """Fetch + merge AdGuard DNS rules (async)."""

    def __init__(
        self,
        timeout: int = 60,
        max_concurrency: int = 50,
        cache_dir: Optional[str] = None,
        cache_ttl: int = 0,
        cache_max_size_mb: int = 0,
        strip_www: bool = False,
        quality_filter_enabled: bool = True,
        min_domain_length: int = 4,
        max_domain_length: int = 253,
        filter_localhost: bool = True,
        filter_ip_rules: bool = False,
        aggregation_enabled: bool = True,
        min_aggregator_labels: int = 2,
        wildcard_child_aggregation: bool = True,
        wildcard_promotion_threshold: int = 0,
        psl_guard: bool = True,
        promotion_mode: str = "count",
        promotion_pattern_min_ratio: float = 0.8,
        conflict_resolution_enabled: bool = True,
        cascade_subdomains: bool = True,
        whitelist_audit_enabled: bool = False,
        whitelist_audit_concurrency: int = 10,
        whitelist_audit_use_dns: bool = True,
        whitelist_audit_use_urlhaus: bool = True,
        whitelist_audit_use_threatfox: bool = True,
        whitelist_audit_use_rdap: bool = True,
        whitelist_audit_use_scam_check: bool = True,
        whitelist_audit_use_dnsbl: bool = False,
        whitelist_audit_cache_results: bool = False,
        whitelist_audit_cache_dir: str = "cache",
        whitelist_audit_use_virustotal: bool = False,
        whitelist_audit_vt_api_key: str = "",
        whitelist_audit_use_ai: bool = False,
        whitelist_audit_ai_api_key: str = "",
        whitelist_audit_ai_base_url: str = "https://api.openai.com/v1",
        whitelist_audit_ai_model: str = "gpt-4o-mini",
        whitelist_audit_ai_min_confidence: float = 0.6,
        whitelist_audit_ai_max_domains: int = 100,
        whitelist_audit_new_domain_days: int = 30,
        whitelist_audit_urlhaus_delay: float = 1.0,
        whitelist_audit_ti_mode: str = "api",
        whitelist_audit_feed_ttl: int = 3600,
        fail_threshold: float = 0.5,
        diff_against: Optional[str] = None,
        user_agent: str = default_user_agent(),
        retry_count: int = 2,
        retry_delay: float = 1.5,
        source_deadline: float = 120.0,
        backoff: str = "linear",
        negative_ttl_seconds: int = 300,
    ) -> None:
        self.timeout = timeout
        self.max_concurrency = max_concurrency
        self.strip_www = strip_www
        self.aggregation_enabled = aggregation_enabled
        self.conflict_resolution_enabled = conflict_resolution_enabled
        self.cascade_subdomains = cascade_subdomains
        self.whitelist_audit_enabled = whitelist_audit_enabled
        self.whitelist_audit_concurrency = whitelist_audit_concurrency
        self.whitelist_audit_use_dns = whitelist_audit_use_dns
        self.whitelist_audit_use_urlhaus = whitelist_audit_use_urlhaus
        self.whitelist_audit_use_threatfox = whitelist_audit_use_threatfox
        self.whitelist_audit_use_rdap = whitelist_audit_use_rdap
        self.whitelist_audit_use_scam_check = whitelist_audit_use_scam_check
        self.whitelist_audit_use_dnsbl = whitelist_audit_use_dnsbl
        self.whitelist_audit_cache_results = whitelist_audit_cache_results
        self.whitelist_audit_cache_dir = whitelist_audit_cache_dir
        self.whitelist_audit_use_virustotal = whitelist_audit_use_virustotal
        self.whitelist_audit_vt_api_key = whitelist_audit_vt_api_key
        self.whitelist_audit_use_ai = whitelist_audit_use_ai
        self.whitelist_audit_ai_api_key = whitelist_audit_ai_api_key
        self.whitelist_audit_ai_base_url = whitelist_audit_ai_base_url
        self.whitelist_audit_ai_model = whitelist_audit_ai_model
        self.whitelist_audit_ai_min_confidence = whitelist_audit_ai_min_confidence
        self.whitelist_audit_ai_max_domains = whitelist_audit_ai_max_domains
        self.whitelist_audit_new_domain_days = whitelist_audit_new_domain_days
        self.whitelist_audit_urlhaus_delay = whitelist_audit_urlhaus_delay
        self.whitelist_audit_ti_mode = whitelist_audit_ti_mode
        self.whitelist_audit_feed_ttl = whitelist_audit_feed_ttl
        self.min_aggregator_labels = min_aggregator_labels
        self.wildcard_child_aggregation = wildcard_child_aggregation
        self.wildcard_promotion_threshold = wildcard_promotion_threshold
        self.psl_guard = psl_guard
        self.promotion_mode = promotion_mode
        self.promotion_pattern_min_ratio = promotion_pattern_min_ratio
        self.fail_threshold = fail_threshold
        self.diff_against = diff_against
        self.user_agent = user_agent
        self.retry_count = retry_count
        self.retry_delay = retry_delay
        # V5.2: hard per-source time budget. A dead source used to burn
        # (retry_count+1) x timeout ≈ 380s of wall time; the deadline caps
        # the whole retry chain and falls back to the stale cache instead.
        self.source_deadline = source_deadline
        self.backoff = backoff
        self.negative_ttl_seconds = negative_ttl_seconds
        self._negative_cache: Dict[str, float] = {}
        self._badfilter_cancelled: Set[Tuple[str, bool]] = set()
        self._parser_kwargs = dict(
            strip_www=strip_www,
            quality_filter=quality_filter_enabled,
            min_domain_length=min_domain_length,
            max_domain_length=max_domain_length,
            filter_localhost=filter_localhost,
            filter_ip_rules=filter_ip_rules,
        )
        self.parser = RuleParser(**self._parser_kwargs)
        self.cache: Optional[SourceCache] = None
        if cache_dir is not None:
            self.cache = SourceCache(cache_dir=cache_dir, ttl_seconds=cache_ttl,
                                     max_size_mb=cache_max_size_mb)
            self.cache.load()
        self._session: Optional[aiohttp.ClientSession] = None
        self._cache_lock: Optional[asyncio.Lock] = None
        self.pattern_dropped = 0
        self.quality_dropped = 0
        self.css_dropped = 0
        self.comment_dropped = 0
        self.modifier_stripped = 0

    @classmethod
    def from_config(cls, cfg: Any) -> "AsyncRuleEngine":
        """Build an engine from a ``MergeConfig`` (avoids 40-kwarg plumbing)."""
        cache_dir = cfg.cache.directory if cfg.cache.enabled else None
        ai = cfg.whitelist_audit.ai
        wa = cfg.whitelist_audit
        return cls(
            timeout=cfg.timeout,
            max_concurrency=cfg.max_concurrency,
            cache_dir=cache_dir,
            cache_ttl=cfg.cache.ttl_seconds,
            cache_max_size_mb=cfg.cache.max_size_mb,
            strip_www=cfg.dedup.strip_www,
            quality_filter_enabled=cfg.quality_filter.enabled,
            min_domain_length=cfg.quality_filter.min_domain_length,
            max_domain_length=cfg.quality_filter.max_domain_length,
            filter_localhost=cfg.quality_filter.filter_localhost,
            filter_ip_rules=cfg.quality_filter.filter_ip_rules,
            aggregation_enabled=cfg.aggregation.enabled,
            min_aggregator_labels=cfg.aggregation.min_aggregator_labels,
            wildcard_child_aggregation=cfg.aggregation.wildcard_child_aggregation,
            wildcard_promotion_threshold=cfg.aggregation.wildcard_promotion_threshold,
            psl_guard=cfg.aggregation.psl_guard,
            promotion_mode=cfg.aggregation.promotion_mode,
            promotion_pattern_min_ratio=cfg.aggregation.promotion_pattern_min_ratio,
            conflict_resolution_enabled=cfg.conflict_resolution.enabled,
            cascade_subdomains=cfg.conflict_resolution.cascade_subdomains,
            whitelist_audit_enabled=wa.enabled,
            whitelist_audit_concurrency=wa.concurrency,
            whitelist_audit_use_dns=wa.use_dns,
            whitelist_audit_use_urlhaus=wa.use_urlhaus,
            whitelist_audit_use_threatfox=wa.use_threatfox,
            whitelist_audit_use_rdap=wa.use_rdap,
            whitelist_audit_use_scam_check=wa.use_scam_check,
            whitelist_audit_use_dnsbl=wa.use_dnsbl,
            whitelist_audit_cache_results=wa.cache_results,
            whitelist_audit_cache_dir=cfg.cache.directory or "cache",
            whitelist_audit_use_virustotal=wa.use_virustotal,
            whitelist_audit_vt_api_key=wa.virustotal_api_key,
            whitelist_audit_use_ai=ai.enabled,
            whitelist_audit_ai_api_key=ai.api_key,
            whitelist_audit_ai_base_url=ai.base_url,
            whitelist_audit_ai_model=ai.model,
            whitelist_audit_ai_min_confidence=ai.min_confidence,
            whitelist_audit_ai_max_domains=ai.max_domains,
            whitelist_audit_new_domain_days=wa.new_domain_threshold_days,
            whitelist_audit_urlhaus_delay=wa.urlhaus_delay,
            whitelist_audit_ti_mode=wa.ti_mode,
            whitelist_audit_feed_ttl=wa.feed_ttl_seconds,
            fail_threshold=cfg.fail_threshold,
            diff_against=cfg.diff_against,
            user_agent=cfg.download.user_agent,
            retry_count=cfg.download.retry_count,
            retry_delay=cfg.download.retry_delay,
            source_deadline=getattr(cfg.download, "source_deadline", 120.0),
            backoff=getattr(cfg.download, "backoff", "linear"),
            negative_ttl_seconds=getattr(cfg.cache, "negative_ttl_seconds", 300),
        )

    # ── async context ───────────────────────────────────────────

    async def __aenter__(self) -> "AsyncRuleEngine":
        await self._ensure_session()
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.close()

    async def _ensure_session(self) -> None:
        if self._session is None or self._session.closed:
            timeout = aiohttp.ClientTimeout(
                total=self.timeout, sock_connect=30, sock_read=self.timeout)
            connector = aiohttp.TCPConnector(limit=self.max_concurrency,
                                             ttl_dns_cache=300,
                                             force_close=False)
            self._session = aiohttp.ClientSession(
                timeout=timeout, connector=connector,
                headers={"User-Agent": self.user_agent},
            )
        if self._cache_lock is None:
            self._cache_lock = asyncio.Lock()

    async def close(self) -> None:
        if self._session and not self._session.closed:
            await self._session.close()
        if self.cache:
            self.cache.save_if_dirty()

    # ── fetch ────────────────────────────────────────────────────

    async def _fetch_text(
        self, source: str, retries: int = 2, timeout: Optional[int] = None,
    ) -> Tuple[str, bool, Optional[str], Optional[str]]:
        """Return (text, from_cache, error, content_hash)."""
        p = Path(source)
        if p.exists() and p.is_file():
            text = p.read_text(encoding="utf-8", errors="replace")
            h = SourceCache.hash_text(text)
            return text, False, None, h

        cond_headers: Dict[str, str] = {}
        if self.cache:
            cond_headers = self.cache.conditional_headers(source)

        # V5.3 — negative cache: skip sources that failed recently
        if self.negative_ttl_seconds > 0:

            neg_ts = self._negative_cache.get(source)
            if neg_ts is not None and (time.monotonic() - neg_ts) < self.negative_ttl_seconds:
                if self.cache:
                    cached = self.cache.get_content(source)
                    if cached is not None:
                        logger.warning("negative cache hit for %s; using stale", source)
                        return cached, True, "negative cache hit", self.cache.content_hash_of(source)
                return "", False, "negative cache hit (no stale content)", None

        await self._ensure_session()
        assert self._session is not None
        last_exc: Optional[Exception] = None
        start = time.monotonic()
        deadline = (start + self.source_deadline) if self.source_deadline else None

        async def _get(headers: Dict[str, str], req_timeout):
            return self._session.get(source, headers=headers, timeout=req_timeout)

        for attempt in range(retries + 1):
            base = timeout or self.timeout
            if deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0.5:
                    last_exc = TimeoutError(
                        f"per-source deadline {self.source_deadline:g}s exhausted")
                    break
                base = min(base, max(1.0, remaining))
            req_timeout = aiohttp.ClientTimeout(
                total=base, sock_connect=min(30.0, base), sock_read=base)
            try:
                async with await _get(cond_headers, req_timeout) as resp:
                    if resp.status == 404:
                        return "", False, f"HTTP 404 Not Found: {source}", None
                    if resp.status == 304:
                        if self.cache:
                            cached = self.cache.get_content(source)
                            if cached is not None:
                                async with self._cache_lock:  # type: ignore[union-attr]
                                    self.cache.store_not_modified(source)
                                    self.cache.save_if_dirty()
                                return cached, True, None, self.cache.content_hash_of(source)
                        # 304 but body/cache missing: retry once without validators.
                        logger.warning("304 with missing cache for %s; retrying unconditional", source)
                        cond_headers = {}
                        async with await _get({}, req_timeout) as resp2:
                            resp2.raise_for_status()
                            text = await resp2.text(encoding="utf-8", errors="replace")
                            h = None
                            if self.cache:
                                h = SourceCache.hash_text(text)
                                async with self._cache_lock:  # type: ignore[union-attr]
                                    self.cache.store(
                                        url=source, content=text,
                                        etag=resp2.headers.get("ETag"),
                                        last_modified=resp2.headers.get("Last-Modified"),
                                        content_hash=h,
                                    )
                                    self.cache.save_if_dirty()
                            return text, False, None, h
                    resp.raise_for_status()
                    text = await resp.text(encoding="utf-8", errors="replace")
                    h = None
                    from_cache = False
                    if self.cache:
                        changed, h = self.cache.content_changed(source, text)
                        async with self._cache_lock:  # type: ignore[union-attr]
                            self.cache.store(
                                url=source, content=text,
                                etag=resp.headers.get("ETag"),
                                last_modified=resp.headers.get("Last-Modified"),
                                content_hash=h,
                            )
                            self.cache.save_if_dirty()
                        if not changed:
                            from_cache = True
                    return text, from_cache, None, h
            except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as e:
                last_exc = e
                if attempt < retries:
                    if self.backoff == "exponential":
                        delay = self.retry_delay * (2 ** attempt)
                    else:
                        delay = self.retry_delay * (attempt + 1)
                    await asyncio.sleep(delay)
                    continue
        # V5.3 — record negative cache for this source
        if self.negative_ttl_seconds > 0:
            self._negative_cache[source] = time.monotonic()
        if self.cache:
            cached = self.cache.get_content(source)
            if cached is not None:
                logger.warning("fetch %s failed (%s); using stale cache", source, last_exc)
                return cached, True, None, self.cache.content_hash_of(source)
        return "", False, f"{type(last_exc).__name__}: {last_exc}" if last_exc else "unknown error", None

    def _parse_text(self, text: str, url: str, category: str
                    ) -> Tuple[List[Rule], int, int, int, int, int]:
        """CPU-bound parse; safe to run in a worker thread (own parser)."""
        parser = RuleParser(**self._parser_kwargs)
        rules = parser.parse_text(text, source=url, category=category)
        return (rules, parser.pattern_dropped, parser.quality_dropped,
                parser.css_dropped, parser.comment_dropped, parser.modifier_stripped)

    async def _fetch_one(self, meta: SourceMeta
                         ) -> Tuple[List[Rule], bool, bool, int, Optional[str]]:
        """Return (rules, success, from_cache, raw_line_count, error)."""
        t0 = time.time()
        text, from_cache, err, content_hash = await self._fetch_text(
            meta.url, retries=self.retry_count, timeout=meta.timeout)
        if err:
            logger.warning("source failed %s: %s", meta.url, err)
            return [], False, False, 0, err

        rules: Optional[List[Rule]] = None
        if self.cache and content_hash:
            loaded = self.cache.load_parsed(content_hash)
            if loaded is not None:
                recs, counters = loaded
                rules = RuleParser.rules_from_records(
                    recs, source=meta.url, strip_www=self.strip_www)
                if counters:  # V5.2: drop counters survive the parsed cache
                    self.pattern_dropped += counters.get("pattern", 0)
                    self.quality_dropped += counters.get("quality", 0)
                    self.css_dropped += counters.get("css", 0)
                    self.comment_dropped += counters.get("comment", 0)
                    self.modifier_stripped += counters.get("modifier_stripped", 0)
                logger.info("parsed %6d rules from %-40s (parsed-cache, %.2fs)",
                            len(rules), meta.url.split("/")[-1], time.time() - t0)
                return rules, True, True, len(rules), None

        loop = asyncio.get_running_loop()
        (rules, pat, qual, css, comments, modstrip) = await loop.run_in_executor(
            None, self._parse_text, text, meta.url, meta.category)
        self.pattern_dropped += pat
        self.quality_dropped += qual
        self.css_dropped += css
        self.comment_dropped += comments
        self.modifier_stripped += modstrip
        if self.cache and content_hash:
            try:
                recs = RuleParser.compact_records(rules)
                self.cache.store_parsed(content_hash, recs, counters={
                    "pattern": pat, "quality": qual, "css": css,
                    "comment": comments, "modifier_stripped": modstrip,
                })
            except OSError as e:
                logger.debug("parsed sidecar write failed: %s", e)
        logger.info("parsed %6d rules from %-40s (%s, %.2fs)",
                    len(rules), meta.url.split("/")[-1],
                    "cache" if from_cache else "net", time.time() - t0)
        return rules, True, from_cache, len(rules), None

    async def fetch_all(self, sources: List[SourceMeta]):
        sem = asyncio.Semaphore(self.max_concurrency)
        block_map: Dict[Tuple[str, bool, str], Rule] = {}
        allow_map: Dict[Tuple[str, bool, str], Rule] = {}
        regex_blocks: Dict[str, Rule] = {}
        regex_allows: Dict[str, Rule] = {}
        raw_count = ok = cached = 0
        exact_merged = normalized_merged = regex_merged = 0
        failures: List[SourceFailure] = []
        source_raw_counts: Dict[str, int] = {}
        source_names: Dict[str, str] = {}

        async def bounded(meta: SourceMeta):
            async with sem:
                return meta, await self._fetch_one(meta)

        for fut in asyncio.as_completed([bounded(s) for s in sources]):
            meta, (rules, success, from_cache, n, err) = await fut
            source_names[meta.url] = meta.name
            if not success:
                failures.append(SourceFailure(
                    url=meta.url, name=meta.name, error=err or "unknown",
                    error_type=classify_source_error(err or "")))
                continue
            ok += 1
            raw_count += n
            source_raw_counts[meta.url] = n
            if from_cache:
                cached += 1

            for r in rules:
                if r.rule_type == "comment":
                    continue
                if r.normalized_domain == "":
                    m = regex_blocks if r.rule_type == "block" else regex_allows
                    key = r.raw
                    existing = m.get(key)
                    if existing is None:
                        m[key] = r
                    else:
                        existing.merge_from(r)
                        regex_merged += 1
                    continue
                m = block_map if r.rule_type == "block" else allow_map
                key = (r.normalized_domain, r.wildcard, r.modifiers)
                existing = m.get(key)
                if existing is None:
                    m[key] = r
                else:
                    if existing.raw and r.raw and existing.raw != r.raw:
                        normalized_merged += 1
                    else:
                        exact_merged += 1
                    existing.merge_from(r)
            del rules

        return (block_map, allow_map,
                list(regex_blocks.values()), list(regex_allows.values()),
                raw_count, ok, cached,
                exact_merged, normalized_merged, regex_merged,
                failures, source_raw_counts, source_names)

    # ── badfilter cancellation ───────────────────────────────────

    def _apply_badfilter(self, block_map: Dict, allow_map: Dict) -> int:
        """Cancel $badfilter rules and their targets.

        Records cancelled (domain, wildcard) pairs on ``_badfilter_cancelled``
        so wildcard promotion cannot recreate a parent that was just voided.
        """
        def _modset(mods: str) -> set:
            return {m.strip() for m in mods.split(",") if m.strip()}

        cancelled: Set[Tuple[str, bool]] = set()
        removed = 0
        for m in (block_map, allow_map):
            bad_keys = [k for k, r in m.items()
                        if r.modifiers and "badfilter" in _modset(r.modifiers)]
            for bk in bad_keys:
                bf = m.pop(bk)
                removed += 1
                cancelled.add((bf.normalized_domain, bf.wildcard))
                remaining = sorted(_modset(bf.modifiers) - {"badfilter"})
                tgt_mods = ",".join(remaining)
                tgt_key = (bf.normalized_domain, bf.wildcard, tgt_mods)
                if tgt_key in m:
                    m.pop(tgt_key)
                    removed += 1
        self._badfilter_cancelled = cancelled
        return removed

    # ── upward aggregation ──────────────────────────────────────

    # V5.3 — pattern-aware wildcard promotion helpers
    _PROMO_PATTERNS = (
        re.compile(r"^cdn\d+$"),
        re.compile(r"^ads?\d*$"),
        re.compile(r"^img\d+$"),
        re.compile(r"^static\d+$"),
        re.compile(r"^s\d+$"),
        re.compile(r"^ns\d+$"),
        re.compile(r"^\d+$"),
        re.compile(r"^server\d+$"),
    )

    @classmethod
    def _variant_label(cls, child: str, parent: str,
                       counters: Optional[Dict[str, int]] = None) -> Optional[str]:
        """First label of *child* relative to *parent* if it matches a promo pattern.

        Returns None when the child differs from the parent in more than the
        first label (multi-level change); in that case, if *counters* is
        provided, ``promotion_multi_level_skipped`` is incremented.
        """
        child_parts = child.split(".")
        parent_parts = parent.split(".")
        if len(child_parts) != len(parent_parts) + 1:
            if counters is not None:
                counters["promotion_multi_level_skipped"] = \
                    counters.get("promotion_multi_level_skipped", 0) + 1
            return None
        if child_parts[1:] != parent_parts:
            if counters is not None:
                counters["promotion_multi_level_skipped"] = \
                    counters.get("promotion_multi_level_skipped", 0) + 1
            return None
        label = child_parts[0]
        for pat in cls._PROMO_PATTERNS:
            if pat.match(label):
                return label
        return None

    @classmethod
    def _pattern_consistency(cls, children: List[str], parent: str,
                             counters: Optional[Dict[str, int]] = None) -> float:
        """Fraction of children whose first label matches a promo pattern."""
        if not children:
            return 0.0
        matched = sum(1 for c in children
                      if cls._variant_label(c, parent, counters) is not None)
        return matched / len(children)

    def _aggregate(self, block_map: Dict[Tuple[str, bool], Rule],
                   allow_domains: Optional[Set[str]] = None,
                   counters: Optional[Dict[str, int]] = None,
                   ) -> Tuple[List[Rule], int, int, int]:
        """Aggregate child rules under surviving parents.

        V5.3 C10: when *allow_domains* is provided, exact/wildcard children
        that are themselves whitelist exceptions are NOT folded into a parent
        — folding would let the parent's block widen the allow's scope.
        """
        wild_map: Dict[str, Rule] = {}
        exact_map: Dict[str, Rule] = {}
        for r in block_map.values():
            if r.modifiers:
                continue
            if r.wildcard:
                wild_map[r.normalized_domain] = r
            else:
                exact_map[r.normalized_domain] = r

        min_labels = self.min_aggregator_labels
        removed: Set[int] = set()
        exact_agg = 0
        wild_agg = 0
        promoted = 0

        if self.wildcard_promotion_threshold > 0:
            _tld = None
            if self.psl_guard:
                try:
                    import tldextract
                    _tld = tldextract.extract
                except ImportError:
                    pass
            sibling_groups: Dict[str, List[str]] = {}
            for norm in exact_map:
                parts = norm.split(".")
                if len(parts) >= min_labels + 1:
                    parent = ".".join(parts[1:])
                    sibling_groups.setdefault(parent, []).append(norm)
            for parent, children in sibling_groups.items():
                if parent.count(".") + 1 < min_labels:
                    continue
                if parent in wild_map or parent in exact_map:
                    continue
                # Never recreate a wildcard parent that $badfilter just voided.
                if (parent, True) in self._badfilter_cancelled:
                    continue
                # V5.3 C6: PSL guard — skip if parent is a public suffix itself.
                if _tld is not None and _tld(parent).domain == "":
                    continue
                # V5.3 C7: pattern mode requires variant-label consistency.
                if self.promotion_mode == "pattern":
                    if (self._pattern_consistency(children, parent, counters)
                            < self.promotion_pattern_min_ratio):
                        continue
                if len(children) >= self.wildcard_promotion_threshold:
                    template = exact_map[children[0]]
                    wc = Rule(raw=f"||*.{parent}^", domain=parent, rule_type="block",
                              wildcard=True, sources=template.source_mask,
                              category=template.category)
                    wild_map[parent] = wc
                    block_map[(parent, True, "")] = wc
                    keeper = wc
                    for child_norm in children:
                        child = exact_map.get(child_norm)
                        if child is not None and id(child) not in removed:
                            keeper.merge_from(child)
                            removed.add(id(child))
                            promoted += 1

        exact_children = sorted(
            (r for r in block_map.values()
             if not r.wildcard and not r.modifiers and id(r) not in removed),
            key=lambda r: (-r.normalized_domain.count("."), r.normalized_domain),
        )
        for child in exact_children:
            if allow_domains and child.normalized_domain in allow_domains:
                continue
            for parent in _iter_parents(child.normalized_domain, min_labels):
                keeper = wild_map.get(parent) or exact_map.get(parent)
                if keeper is not None and id(keeper) != id(child):
                    keeper.merge_from(child)
                    removed.add(id(child))
                    exact_agg += 1
                    break

        if self.wildcard_child_aggregation:
            wild_children = sorted(
                (r for r in block_map.values()
                 if r.wildcard and not r.modifiers and id(r) not in removed),
                key=lambda r: (-r.normalized_domain.count("."), r.normalized_domain),
            )
            for child in wild_children:
                child_norm = child.normalized_domain
                if allow_domains and child_norm in allow_domains:
                    continue
                same_exact = exact_map.get(child_norm)
                if same_exact is not None and id(same_exact) not in removed:
                    same_exact.merge_from(child)
                    removed.add(id(child))
                    wild_agg += 1
                    continue
                for parent in _iter_parents(child_norm, min_labels):
                    keeper = wild_map.get(parent) or exact_map.get(parent)
                    if keeper is not None and id(keeper) != id(child):
                        keeper.merge_from(child)
                        removed.add(id(child))
                        wild_agg += 1
                        break

        survivors = [r for r in block_map.values() if id(r) not in removed]
        return survivors, exact_agg, wild_agg, promoted

    # ── conflict resolution ─────────────────────────────────────

    def _resolve_conflicts(
        self,
        blocks: List[Rule],
        allows: List[Rule],
        source_names: Optional[Dict[str, str]] = None,
    ) -> Tuple[List[Rule], int, List[Dict[str, Any]]]:
        source_names = source_names or {}

        def _src_names(rule: Rule) -> List[str]:
            return [source_names.get(s, s) for s in rule.source_ids]

        exact_allow: Dict[str, Rule] = {}
        wild_allow: Dict[str, Rule] = {}
        suffix_allow: Dict[str, Rule] = {}
        for a in allows:
            n = a.normalized_domain
            if not n:
                continue
            if a.wildcard:
                wild_allow[n] = a
            else:
                exact_allow[n] = a
            if self.cascade_subdomains:
                suffix_allow[n] = a

        removed: Set[int] = set()
        conflicts: List[Dict[str, Any]] = []

        for b in blocks:
            n = b.normalized_domain
            if not n:
                continue
            if b.modifiers and "important" in b.modifiers.split(","):
                continue  # $important rules outrank whitelists at AGH runtime
            by = None
            conflict_type = "exact"
            if n in exact_allow:
                by = exact_allow[n]
            else:
                parts = n.split(".")
                for i in range(1, len(parts)):
                    parent = ".".join(parts[i:])
                    if parent in wild_allow:
                        by = wild_allow[parent]
                        conflict_type = "wildcard"
                        break
                    if self.cascade_subdomains and parent in suffix_allow:
                        by = suffix_allow[parent]
                        conflict_type = "cascade"
                        break
            if by is not None:
                removed.add(id(b))
                conflicts.append({
                    "domain": n,
                    "blocked_rule": b.output_raw,
                    "blocked_category": b.category,
                    "blocked_sources": _src_names(b),
                    "whitelist_rule": by.output_raw,
                    "whitelist_sources": _src_names(by),
                    "conflict_type": conflict_type,
                })

        survivors = [b for b in blocks if id(b) not in removed]
        return survivors, len(removed), conflicts

    # ── per-source contribution stats ───────────────────────────

    @staticmethod
    def _rule_key(r: Rule) -> str:
        """Identity key for coverage stats: domain rules by normalized domain,
        regex rules by raw body (V5.2: regex rules used to be invisible here,
        which made e.g. DNS Rebind Protection show 3/16 rules and a bogus
        100% unique ratio)."""
        return r.normalized_domain or r.raw

    @classmethod
    def _compute_stats(
        cls,
        blocks: List[Rule], allows: List[Rule],
        source_names: Dict[str, str], source_raw_counts: Dict[str, int],
    ) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """Fused single-pass contributions + source_overlap (V5.3 C9).

        Two traversals over chain(blocks, allows): the first accumulates
        per-key coverage, per-source effective counts and pairwise overlap;
        the second attributes unique/shared/category counts. Provenance bits
        are walked lazily via ``iter_source_keys`` — rows hold the integer
        mask, not a per-rule tuple, so memory stays flat on millions of rules.
        """
        from itertools import chain
        from collections import Counter

        coverage: Dict[str, int] = {}
        effective: Counter = Counter()
        pair_overlap: Counter = Counter()
        rows: List[Tuple[Optional[str], int, str]] = []

        for r in chain(blocks, allows):
            key = cls._rule_key(r)
            if key:
                coverage[key] = r.source_mask.bit_count()
            mask = r.source_mask
            if not mask or not key:
                continue
            rows.append((key, mask, r.category))
            srcs = list(iter_source_keys(mask))
            for s in srcs:
                effective[s] += 1
            n = len(srcs)
            for i in range(n):
                for j in range(i + 1, n):
                    pair_overlap[frozenset({srcs[i], srcs[j]})] += 1

        unique_count: Dict[str, int] = {}
        shared_count: Dict[str, int] = {}
        cat_by_src: Dict[str, Counter] = {}
        for key, mask, category in rows:
            unique = coverage.get(key, 1) == 1
            for src in iter_source_keys(mask):
                if unique:
                    unique_count[src] = unique_count.get(src, 0) + 1
                else:
                    shared_count[src] = shared_count.get(src, 0) + 1
                cat_by_src.setdefault(src, Counter())[category] += 1

        contributions = []
        for url, name in source_names.items():
            uniq = unique_count.get(url, 0)
            shrd = shared_count.get(url, 0)
            raw = source_raw_counts.get(url, 0)
            eff = uniq + shrd
            contributions.append({
                "name": name, "url": url,
                "raw_rules": raw, "unique_rules": uniq,
                "shared_rules": shrd, "effective_rules": eff,
                "coverage_rate": round(eff / raw * 100, 1) if raw else 0.0,
                "unique_rate": round(uniq / eff * 100, 1) if eff else 0.0,
                "rule_categories": dict(cat_by_src.get(url, {})),
            })
        contributions.sort(key=lambda c: (-c["unique_rules"], -c["effective_rules"], c["name"]))

        pairs = []
        for pair, count in pair_overlap.most_common():
            src_list = sorted(pair)
            a, b = src_list[0], src_list[1]
            ea, eb = effective[a], effective[b]
            union = ea + eb - count
            pairs.append({
                "source_a": source_names.get(a, a),
                "source_b": source_names.get(b, b),
                "overlap": count,
                "rate_a": round(count / ea * 100, 1) if ea else 0.0,
                "rate_b": round(count / eb * 100, 1) if eb else 0.0,
                "jaccard": round(count / union * 100, 1) if union else 0.0,
            })
        source_effective = {
            source_names.get(k, k): v for k, v in effective.most_common()
        }
        order = list(source_effective.keys())
        pos = {name: i for i, name in enumerate(order)}
        cells: Dict[str, Dict[str, Any]] = {}
        for p in pairs:
            a, b = p["source_a"], p["source_b"]
            if pos.get(a, -1) > pos.get(b, -1):
                a, b = b, a
            cells.setdefault(a, {})[b] = {
                "overlap": p["overlap"],
                "jaccard": p["jaccard"],
                "rate_a": p["rate_a"] if p["source_a"] == a else p["rate_b"],
                "rate_b": p["rate_b"] if p["source_a"] == a else p["rate_a"],
            }
        matrix = {"order": order, "effective": source_effective, "cells": cells}
        source_overlap = {"pairs": pairs, "source_effective": source_effective, "matrix": matrix}
        return contributions, source_overlap

    @staticmethod
    def _compute_modifier_stats(blocks: List[Rule], allows: List[Rule]) -> Dict[str, int]:
        from collections import Counter
        from itertools import chain
        c: Counter = Counter()
        for r in chain(blocks, allows):
            if r.modifiers:
                for m in r.modifiers.split(","):
                    m = m.strip()
                    if m:
                        c[m] += 1
        return dict(c.most_common())

    @staticmethod
    def _load_previous_domains(path: str) -> Set[str]:
        p = Path(path)
        if not p.exists():
            return set()
        try:
            return {
                line.strip() for line in p.read_text(encoding="utf-8").splitlines()
                if line.strip() and not line.strip().startswith("#") and not line.strip().startswith("!")
            }
        except OSError:
            return set()

    # ── high-level run ──────────────────────────────────────────

    async def run(self, sources: List[SourceMeta]) -> MergeOutcome:
        sources = [s for s in sources if s.enabled]
        if not sources:
            raise ValueError("No enabled sources")

        t0 = time.time()
        (block_map, allow_map,
         regex_blocks, regex_allows,
         raw_count, ok, cached,
         exact_merged, normalized_merged, regex_merged,
         failures, source_raw_counts, source_names) = await self.fetch_all(sources)

        total = len(sources)
        if ok == 0:
            raise RuntimeError("All sources failed to download")
        fail_rate = len(failures) / total
        if fail_rate > self.fail_threshold:
            raise RuntimeError(
                f"Source failure rate {fail_rate:.0%} exceeds threshold "
                f"{self.fail_threshold:.0%}: {[f.name for f in failures]}")

        logger.info("raw rules: %d from %d/%d sources (%d cached); "
                    "block_keys=%d allow_keys=%d regex=%d",
                    raw_count, ok, total, cached,
                    len(block_map), len(allow_map),
                    len(regex_blocks) + len(regex_allows))

        for r in chain(block_map.values(), allow_map.values()):
            r.raw = ""

        badfilter_removed = self._apply_badfilter(block_map, allow_map)
        if badfilter_removed:
            logger.info("badfilter cancellation: removed %d rules", badfilter_removed)

        aggregated_n = wild_agg_n = promoted_n = 0
        if self.aggregation_enabled:
            allow_domains = {r.normalized_domain for r in allow_map.values()
                             if r.normalized_domain}
            promo_counters: Dict[str, int] = {}
            aggregated_blocks, aggregated_n, wild_agg_n, promoted_n = \
                self._aggregate(block_map, allow_domains=allow_domains,
                                counters=promo_counters)
            if promo_counters.get("promotion_multi_level_skipped"):
                logger.info("promotion multi-level skipped: %d",
                            promo_counters["promotion_multi_level_skipped"])
            logger.info("aggregation: exact=%d wildcard=%d promoted=%d",
                        aggregated_n, wild_agg_n, promoted_n)
        else:
            aggregated_blocks = list(block_map.values())

        if self.conflict_resolution_enabled:
            final_blocks, removed_n, conflicts = self._resolve_conflicts(
                aggregated_blocks, list(allow_map.values()), source_names)
        else:
            final_blocks, removed_n, conflicts = aggregated_blocks, 0, []

        final_blocks = sorted(final_blocks + regex_blocks, key=Rule.sort_key)
        final_allows = sorted(list(allow_map.values()) + regex_allows, key=Rule.sort_key)

        contributions, source_overlap = self._compute_stats(
            final_blocks, final_allows, source_names, source_raw_counts)
        modifier_stats = self._compute_modifier_stats(final_blocks, final_allows)

        whitelist_audit: Dict[str, Any] = {}
        if self.whitelist_audit_enabled:
            from .whitelist_audit import audit_whitelist, AuditConfig
            logger.info("running whitelist multi-layer audit...")
            audit_cfg = AuditConfig(
                use_dns=self.whitelist_audit_use_dns,
                use_urlhaus=self.whitelist_audit_use_urlhaus,
                use_threatfox=self.whitelist_audit_use_threatfox,
                use_rdap=self.whitelist_audit_use_rdap,
                use_scam_check=self.whitelist_audit_use_scam_check,
                use_dnsbl=self.whitelist_audit_use_dnsbl,
                cache_results=self.whitelist_audit_cache_results,
                cache_dir=self.whitelist_audit_cache_dir,
                use_virustotal=self.whitelist_audit_use_virustotal,
                virustotal_api_key=self.whitelist_audit_vt_api_key,
                use_ai=self.whitelist_audit_use_ai,
                ai_api_key=self.whitelist_audit_ai_api_key,
                ai_base_url=self.whitelist_audit_ai_base_url,
                ai_model=self.whitelist_audit_ai_model,
                ai_min_confidence=self.whitelist_audit_ai_min_confidence,
                ai_max_domains=self.whitelist_audit_ai_max_domains,
                concurrency=self.whitelist_audit_concurrency,
                urlhaus_delay=self.whitelist_audit_urlhaus_delay,
                new_domain_threshold_days=self.whitelist_audit_new_domain_days,
                ti_mode=self.whitelist_audit_ti_mode,
                feed_ttl_seconds=self.whitelist_audit_feed_ttl,
            )
            whitelist_audit = await audit_whitelist(
                final_allows, source_names, config=audit_cfg,
            )
            logger.info("whitelist audit: %s", whitelist_audit.get("summary", {}))

        added, removed = [], []
        added_allows, removed_allows = [], []
        if self.diff_against:
            diff_path = Path(self.diff_against)
            if diff_path.is_dir():
                blocks_file = str(diff_path / "merged_rules.txt")
                allows_file = diff_path / "whitelist.txt"
            else:
                blocks_file = self.diff_against
                allows_file = None
            new_domains = {b.normalized_domain for b in final_blocks if b.normalized_domain}
            old_domains = self._load_previous_domains(blocks_file)
            added = sorted(new_domains - old_domains)
            removed = sorted(old_domains - new_domains)
            if allows_file and allows_file.exists():
                new_allows = {a.normalized_domain for a in final_allows if a.normalized_domain}
                old_allows = self._load_previous_domains(str(allows_file))
                added_allows = sorted(new_allows - old_allows)
                removed_allows = sorted(old_allows - new_allows)
            logger.info("diff: blocks +%d -%d, allows +%d -%d",
                        len(added), len(removed),
                        len(added_allows), len(removed_allows))

        h = hashlib.sha256()
        for r in final_blocks + final_allows:
            h.update(r.output_raw.encode("utf-8", errors="replace"))
            h.update(b"\n")
        content_version = h.hexdigest()[:12]

        outcome = MergeOutcome(
            blocks=final_blocks,
            allows=final_allows,
            regex_blocks=regex_blocks,
            regex_allows=regex_allows,
            raw_count=raw_count,
            sources_ok=ok,
            sources_total=total,
            sources_cached=cached,
            exact_merged=exact_merged,
            normalized_merged=normalized_merged,
            regex_merged=regex_merged,
            aggregated=aggregated_n,
            wildcard_aggregated=wild_agg_n,
            wildcard_promoted=promoted_n,
            conflict_resolved=removed_n,
            whitelist_blocked=removed_n,
            pattern_dropped=self.pattern_dropped,
            quality_dropped=self.quality_dropped,
            css_dropped=self.css_dropped,
            comment_dropped=self.comment_dropped,
            modifier_stripped=self.modifier_stripped,
            badfilter_removed=badfilter_removed,
            conflicts=conflicts,
            failed_sources=[{"name": f.name, "url": f.url, "error": f.error,
                             "error_type": f.error_type} for f in failures],
            contributions=contributions,
            source_overlap=source_overlap,
            modifier_stats=modifier_stats,
            whitelist_audit=whitelist_audit,
            added=added,
            removed=removed,
            added_allows=added_allows,
            removed_allows=removed_allows,
            elapsed=time.time() - t0,
            content_version=content_version,
        )
        return outcome

    def run_sync(self, sources: List[SourceMeta]) -> MergeOutcome:
        async def _go():
            async with self:
                return await self.run(sources)
        return asyncio.run(_go())
