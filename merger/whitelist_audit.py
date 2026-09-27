"""V5.2 whitelist auditor — multi-layer defense-in-depth decision engine.

Layers (all network layers execute in PARALLEL per domain via asyncio.gather):
  1. DNS resolution     — NXDOMAIN=expired, private-IP=suspicious (free, keyless)
  2. Threat intelligence — URLhaus + ThreatFox (free, keyless, rate-limited)
  3. RDAP registration   — domain age, new domains <30d flagged (free, keyless)
  4. MarketNow scam check— typosquatting / suspicious TLD / unregistered (free)
  5. DNSBL lookups (V5.2)— Spamhaus DBL + SURBL multi (free DNS queries)
  6. VirusTotal          — vendor reputation (optional, needs API key)
  7. Offline classifier  — tldextract + PSL registered-domain matching (free, sync)
  8. AI classification   — LLM semantic fallback for low-confidence domains
                           (optional, needs API key, only called for conf<0.6)

V5.2 additions:
  - All reasons are collected (no early-return fusion) + weighted risk_score.
  - DNSBL layer: Spamhaus DBL (dbl.spamhaus.org) + SURBL (multi.surbl.org)
    reply-code parsing; malware/phishing listings are malicious signals,
    spam/junk/abused listings are suspicious signals.
  - Disk-backed result cache (whitelist_audit_cache.json, default TTL 24h) so
    repeated runs skip the network for already-audited domains.

Parallel execution:
  - All independent network layers (DNS, DNSBL, threat-intel, RDAP, scam,
    VirusTotal) run concurrently via asyncio.gather — total latency ≈ max(layer
    latency) instead of sum(layer latencies).
  - The offline PSL classifier is synchronous and microsecond-fast.
  - The AI layer runs after the gather because it depends on the offline
    confidence score (only low-confidence domains trigger it).
  - A shared aiohttp.ClientSession is used across all domains/layers.

Ratings:
  malicious  🔴  any threat-intel / DNSBL malware-phishing source positive
  suspicious 🟡  DNS NXDOMAIN / private IP / new domain / scam / DNSBL spam
  safe       🟢  DNS resolves normally, no threat hits
  unknown    ⚪  all checks failed

In-memory results are cached with a 24h TTL; optional disk cache persists the
same TTL across processes.
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import logging
import socket
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

from .ai_classifier import classify_with_ai
from .domain_classifier import (
    classify_domain_with_confidence, category_counts,
)
from .models import Rule
from .scam_check import query_scam_check
from .virustotal_audit import query_virustotal
from .whois_audit import query_rdap
from .version import user_agent

URLHAUS_HOST_API = "https://urlhaus-api.abuse.ch/v1/host/"
THREATFOX_API = "https://threatfox-api.abuse.ch/api/v1/"

# ── V5.2 DNSBL zones (free keyless DNS lookups) ───────────────────
# Not listed = NXDOMAIN (the normal case). A 127.0.0.x answer = listed.
DNSBL_LISTS = (
    ("dbl.spamhaus.org", "SpamhausDBL"),
    ("multi.surbl.org", "SURBL"),
)
# Spamhaus returns these prefixes when queried from public/open resolvers —
# they mean "query blocked", not "domain listed". Must never be treated as a
# listing (would false-positive every domain on a public resolver).
_DNSBL_BLOCKED = ("127.255.255.", "127.255.254.")

# Spamhaus DBL return codes (last octet).
_DBL_CODES = {
    10: ("spam", False), 11: ("phishing", True), 12: ("malware", True),
    13: ("botnet-c2", True), 14: ("abused-spam", False),
    15: ("hijacked", False),
}
# SURBL multi.surbl.org is a bitmask in the last octet.
_SURBL_BITS = (
    (4, "scam", True), (8, "junk", False), (16, "phishing", True),
    (32, "malware", True), (64, "abused-ads", False),
)

RATING_MALICIOUS = "malicious"
RATING_SUSPICIOUS = "suspicious"
RATING_SAFE = "safe"
RATING_UNKNOWN = "unknown"

CACHE_TTL = 86400  # 24 hours
AUDIT_CACHE_FILENAME = "whitelist_audit_cache.json"

_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


# Abused / disposable TLDs frequently used in phishing kits. Conservative
# list — a match alone is not enough to mark a domain suspicious.
_SUSPICIOUS_TLDS = frozenset({
    "xyz", "top", "click", "country", "cfd", "sbs", "zip", "mov",
    "gq", "tk", "ml", "cf", "ga", "work", "bond", "rest", "cyou",
    "qpon", "monster", "quest", "icu", "cam", "lol", "pics", "buzz",
})

# Rating → human-readable action recommendation.
_RECOMMEND = {
    "malicious": "remove",
    "suspicious": "review",
    "unknown": "review",
    "safe": "keep",
}
_RECOMMEND_LABEL = {
    "remove": "建议移除",
    "review": "建议复核",
    "keep": "建议保留",
}


def local_heuristics(domain: str) -> Dict[str, Any]:
    """Offline, keyless signals. ``is_risky`` only when score >= 3.

    Checks: punycode/IDN, abused TLD, deep subdomains, over-long domain,
    digit-heavy core label, digit-letter homoglyph substitution.
    """
    flags: List[str] = []
    score = 0
    d = (domain or "").lower().strip(".")
    if not d:
        return {"score": 0, "flags": [], "is_risky": False, "tld": ""}

    if d.startswith("xn--") or ".xn--" in d:
        flags.append("punycode/IDN")
        score += 2

    labels = d.split(".")
    tld = labels[-1] if labels else ""
    if tld in _SUSPICIOUS_TLDS:
        flags.append(f"可疑TLD .{tld}")
        score += 1
    if len(labels) >= 6:
        flags.append(f"子域过深({len(labels)})")
        score += 1
    if len(d) >= 60:
        flags.append(f"域名过长({len(d)})")
        score += 1

    core = labels[-2] if len(labels) >= 2 else (labels[0] if labels else "")
    digits = sum(c.isdigit() for c in core)
    if core and digits >= 3 and len(core) <= 12:
        flags.append("标签含大量数字")
        score += 1
    if core and any(c in core for c in "01") and any(c in core for c in "olil"):
        flags.append("数字字母混用(疑似仿冒)")
        score += 2

    return {
        "score": score,
        "flags": flags,
        "is_risky": score >= 3,
        "tld": tld,
    }


@dataclass
class AuditConfig:
    """Configuration for the multi-layer audit engine."""
    use_dns: bool = True
    use_urlhaus: bool = True
    use_threatfox: bool = True
    use_rdap: bool = True
    use_scam_check: bool = True
    use_virustotal: bool = False
    virustotal_api_key: str = ""
    use_ai: bool = False
    ai_api_key: str = ""
    ai_base_url: str = "https://api.openai.com/v1"
    ai_model: str = "gpt-4o-mini"
    ai_min_confidence: float = 0.6
    ai_max_domains: int = 100
    concurrency: int = 20
    urlhaus_delay: float = 0.2
    new_domain_threshold_days: int = 30
    # V5.2 — DNSBL layer + disk cache (opt-in so offline unit tests stay
    # hermetic; enabled in config/sources.yaml).
    use_dnsbl: bool = False
    # Offline heuristics (punycode, abused TLD, deep subdomains, homoglyphs).
    # Always on by default — zero network cost, provides offline signal.
    use_heuristics: bool = True
    cache_results: bool = False
    cache_dir: str = "cache"
    cache_ttl_seconds: int = CACHE_TTL
    # V5.3: configurable fusion weights (defaults = the V5.2 hard-coded scores,
    # so default behaviour is unchanged). Used by the cache fingerprint AND by
    # _fuse_rating (V6: weights are actually wired into scoring).
    fusion_weights: Dict[str, int] = field(default_factory=lambda: {
        "threat_intel": 40, "dnsbl_malicious": 30, "scam_confirmed": 30,
        "dns_private_ip": 20, "scam_suspicious": 20, "dnsbl_listed": 15,
        "dns_nxdomain": 15, "rdap_new_domain": 15, "heuristics": 10,
    })
    # V5.3: threat-intel mode — "api" (per-domain HTTP, legacy) or
    # "auto" (download feed once, O(1) local lookup, API fallback).
    ti_mode: str = "api"
    feed_ttl_seconds: int = 3600


@dataclass
class _CacheEntry:
    result: Dict[str, Any]
    timestamp: float = field(default_factory=time.time)


# Note: the threat-intel rate-limit semaphore is created per run inside
# audit_whitelist() so it binds to that run's event loop (a module-level
# Semaphore breaks across repeated asyncio.run() calls / pytest loops).
# V5.3: the in-process result cache is likewise per-run (local to
# audit_whitelist) to avoid cross-run / cross-test pollution.


def _is_private_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return any(ip in net for net in _PRIVATE_NETS)


# ── V5.3 disk cache (config-fingerprinted, fixed TTL, v2 format) ───

def _disk_cache_path(config: "AuditConfig") -> Path:
    return Path(config.cache_dir) / AUDIT_CACHE_FILENAME


def _cfg_fingerprint(config: "AuditConfig") -> str:
    """Stable hash of audit-affecting config (layers + weights + thresholds).

    Changing any of these invalidates stale cache entries for this config,
    so flipping a layer switch or a fusion weight produces a fresh subtree
    instead of returning decisions made under the old configuration.
    """
    layers = (
        config.use_dns, config.use_urlhaus, config.use_threatfox,
        config.use_rdap, config.use_scam_check, config.use_dnsbl,
        config.use_virustotal, config.use_ai, config.use_heuristics,
    )
    payload = {
        "schema": 2,
        "layers": layers,
        "fusion_weights": config.fusion_weights,
        "new_domain_threshold_days": config.new_domain_threshold_days,
        "cache_ttl_seconds": config.cache_ttl_seconds,
    }
    raw = json.dumps(payload, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]


def _disk_cache_load(config: "AuditConfig") -> Dict[str, Dict[str, Any]]:
    """Load {domain: result} entries still inside the TTL window (v2 format).

    v1 files (flat ``{"version":1,"entries":{...}}``) are read as if their
    entries belonged to the current config fingerprint, so the first save
    after an upgrade migrates them into the v2 subtree automatically.
    """
    if not config.cache_results:
        return {}
    p = _disk_cache_path(config)
    if not p.exists():
        return {}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        logger.warning("whitelist audit cache unreadable: %s", e)
        return {}
    fp = _cfg_fingerprint(config)
    now = time.time()
    ttl = config.cache_ttl_seconds
    out: Dict[str, Dict[str, Any]] = {}
    if data.get("version", 1) >= 2:
        subtree = (data.get("configs") or {}).get(fp) or {}
        for domain, rec in (subtree.get("entries") or {}).items():
            if now - rec.get("ts", 0) < ttl:
                out[domain] = rec.get("result") or {}
    else:
        for domain, rec in (data.get("entries") or {}).items():
            if now - rec.get("ts", 0) < ttl:
                out[domain] = rec.get("result") or {}
    return out


def _disk_cache_save(config: "AuditConfig", fresh: Dict[str, Dict[str, Any]]) -> None:
    """Persist fresh results to the v2 disk cache (fixed TTL, no ts refresh).

    Existing non-expired entries keep their original ``ts`` (fixed-TTL
    semantics — an entry fetched 23h ago is not "renewed" to now just
    because a later run touched the file). Expired entries are pruned.
    A v1 file on disk is migrated into the current fingerprint subtree.
    """
    if not config.cache_results or not fresh:
        return
    p = _disk_cache_path(config)
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        fp = _cfg_fingerprint(config)
        now = time.time()
        ttl = config.cache_ttl_seconds
        existing_configs: Dict[str, Any] = {}
        if p.exists():
            try:
                raw = json.loads(p.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                raw = {}
            if raw.get("version", 1) >= 2:
                existing_configs = raw.get("configs") or {}
            elif raw.get("entries"):
                existing_configs[fp] = {"entries": raw["entries"]}
        subtree = existing_configs.get(fp) or {}
        old_entries = subtree.get("entries") or {}
        merged: Dict[str, Any] = {}
        for domain, rec in old_entries.items():
            if now - rec.get("ts", 0) < ttl:
                merged[domain] = rec
        for domain, result in fresh.items():
            merged[domain] = {"ts": now, "result": result}
        existing_configs[fp] = {"entries": merged}
        tmp = p.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(
            {"version": 2, "configs": existing_configs},
            ensure_ascii=False), encoding="utf-8")
        tmp.replace(p)
    except OSError as e:
        logger.warning("whitelist audit cache write failed: %s", e)


async def _dns_check(domain: str, timeout: int = 5) -> Dict[str, Any]:
    """Async DNS resolution via DnsChecker (V5.3: portable NXDOMAIN).

    Thin wrapper preserving the legacy ``{nxdomain, ips, error}`` shape so
    ``_fuse_rating`` and existing tests don't need to change.  The actual
    resolution goes through :class:`merger.dnsx.DnsChecker` which uses
    dnspython's explicit rcode (works on glibc / musl / Windows) and falls
    back to getaddrinfo when dnspython is unavailable.
    """
    from .dnsx import DnsChecker
    result = await DnsChecker(timeout=timeout).check(domain)
    error = result.get("error_type")
    if error == "nxdomain":
        error = None
    return {"nxdomain": result["nxdomain"], "ips": result["ips"],
            "error": error}


async def _query_urlhaus(domain: str, session, timeout: int = 8) -> Dict[str, Any]:
    try:
        data = {"host": domain}
        headers = {"User-Agent": user_agent()}
        async with session.post(URLHAUS_HOST_API, data=data,
                                headers=headers, timeout=timeout) as resp:
            if resp.status != 200:
                return {"malicious": False, "error": f"HTTP {resp.status}"}
            result = await resp.json(content_type=None)
            if result.get("query_status") == "ok":
                return {"malicious": True, "error": None}
            return {"malicious": False, "error": None}
    except Exception as e:
        return {"malicious": False, "error": str(e)}


async def _query_threatfox(domain: str, session, timeout: int = 8) -> Dict[str, Any]:
    try:
        data = {"query": "search_ioc", "search_term": domain}
        headers = {"User-Agent": user_agent()}
        async with session.post(THREATFOX_API, json=data,
                                headers=headers, timeout=timeout) as resp:
            if resp.status != 200:
                return {"malicious": False, "error": f"HTTP {resp.status}"}
            result = await resp.json(content_type=None)
            if result.get("query_status") == "ok" and result.get("data"):
                return {"malicious": True, "error": None}
            return {"malicious": False, "error": None}
    except Exception as e:
        return {"malicious": False, "error": str(e)}


async def _query_threat_intel(domain: str, session,
                               config: AuditConfig,
                               ti_sem=None) -> Tuple[Dict, Dict]:
    """Query URLhaus + ThreatFox with rate-limit semaphore.

    Uses a per-run semaphore (default 3 concurrent) instead of a global lock,
    and a fixed small delay rather than idx-proportional sleep.
    Returns (urlhaus_result, threatfox_result).
    """
    urlhaus = {"malicious": False, "error": "disabled"}
    threatfox = {"malicious": False, "error": "disabled"}

    if not (config.use_urlhaus or config.use_threatfox):
        return urlhaus, threatfox

    async with ti_sem:
        # Fixed small delay to avoid burst; NOT idx-proportional.
        if config.urlhaus_delay > 0:
            await asyncio.sleep(config.urlhaus_delay)
        if config.use_urlhaus:
            urlhaus = await _query_urlhaus(domain, session)
        if config.use_threatfox:
            threatfox = await _query_threatfox(domain, session)

    return urlhaus, threatfox


async def _query_threat_intel_dataset(
    domain: str, feed_index,
) -> Tuple[Dict, Dict]:
    """Dataset-mode threat lookup (V5.3) — replaces per-domain API calls.

    Returns (urlhaus_result, threatfox_result) with the same shape as
    ``_query_threat_intel`` so ``_fuse_rating`` is unchanged.
    """
    hit = feed_index.lookup_domain(domain)
    no = {"malicious": False, "error": None}
    if not hit["listed"]:
        return no, no
    source = hit.get("source") or ""
    if source == "ThreatFox":
        return no, {"malicious": True, "error": None}
    return {"malicious": True, "error": None}, no


async def _query_rdap_wrapper(domain: str, session, config: AuditConfig) -> Dict[str, Any]:
    """RDAP query using registered domain (eTLD+1)."""
    try:
        from .domain_classifier import registered_domain
        reg_domain = registered_domain(domain)
        return await query_rdap(reg_domain, session,
                                threshold_days=config.new_domain_threshold_days)
    except Exception as e:
        return {"is_new_domain": False, "domain_age_days": None,
                "registrar": None, "error": str(e)}


# ── V5.2 DNSBL layer ───────────────────────────────────────────────

def parse_dnsbl_response(list_name: str, ip: str) -> Tuple[bool, List[str]]:
    """Interpret a 127.0.0.x DNSBL reply.

    Returns (malicious_signal, labels). Spamhaus DBL uses one code per last
    octet; SURBL multi uses a bitmask. Codes marking phishing / malware /
    scam / botnet produce a malicious signal; spam/junk/abused only warn.
    """
    if not ip.startswith("127."):
        return False, []
    try:
        last = int(ip.rsplit(".", 1)[-1])
    except ValueError:
        return False, []
    bad = False
    labels: List[str] = []
    if list_name == "SpamhausDBL":
        name, mal = _DBL_CODES.get(last, (f"code-{last}", False))
        labels.append(f"{list_name}:{name}")
        bad = mal
    else:  # SURBL-style bitmask
        for bit, name, mal in _SURBL_BITS:
            if last & bit:
                labels.append(f"{list_name}:{name}")
                bad = bad or mal
    return bad, labels


async def _dnsbl_lookup(qname: str, timeout: int) -> List[str]:
    """Resolve a DNSBL query name, returning the A-record answers.

    NXDOMAIN / not-listed raises ``socket.gaierror`` (handled by the caller).
    Factored out so tests can stub resolution without touching asyncio.
    """
    loop = asyncio.get_running_loop()
    infos = await asyncio.wait_for(
        loop.getaddrinfo(qname, None, family=socket.AF_INET), timeout=timeout)
    return [info[4][0] for info in infos]


async def _query_dnsbl(domain: str, timeout: int = 6) -> Dict[str, Any]:
    """Free keyless DNSBL lookups (Spamhaus DBL + SURBL multi).

    NXDOMAIN means "not listed" — the normal, healthy answer — so these
    queries are cheap and safe to fan out. Volume is one lookup per whitelist
    domain per run (plus disk-cache hits skipped entirely).
    """
    hits: List[str] = []
    errors: List[str] = []
    malicious = False
    for zone, list_name in DNSBL_LISTS:
        qname = f"{domain}.{zone}"
        try:
            for ip in await _dnsbl_lookup(qname, timeout):
                if any(ip.startswith(p) for p in _DNSBL_BLOCKED):
                    errors.append(f"{list_name}: query blocked (open resolver)")
                    continue
                bad, labels = parse_dnsbl_response(list_name, ip)
                hits.extend(labels)
                malicious = malicious or bad
        except socket.gaierror:
            continue  # NXDOMAIN / not listed
        except asyncio.TimeoutError:
            errors.append(f"{list_name}: timeout")
        except Exception as e:  # noqa: BLE001
            errors.append(f"{list_name}: {e}")
    return {"listed": bool(hits), "malicious": malicious, "hits": hits,
            "error": "; ".join(errors) or None}


def _fuse_rating(dns, urlhaus, threatfox, rdap, scam, vt, config,
                 dnsbl=None, heuristics=None) -> Tuple[str, List[str], int]:
    """Multi-layer fusion (V5.2): collect ALL reasons + weighted risk score.

    Returns (rating, reasons, risk_score 0-100). Every enabled layer
    contributes its reason and score — no early return — so the audit output
    shows the complete evidence picture for each domain.
    """
    reasons: List[str] = []
    score = 0
    malicious_signal = False
    suspicious_signal = False
    dnsbl = dnsbl or {"listed": False, "malicious": False, "hits": [], "error": None}
    heuristics = heuristics or {"score": 0, "flags": [], "is_risky": False}
    # V6: fusion weights are read from config (defaults equal the original
    # hard-coded scores, so default behaviour is unchanged) and participate
    # in the disk-cache fingerprint.
    w = config.fusion_weights or {}

    # Threat intelligence: any positive → malicious
    ti_sources = []
    if urlhaus.get("malicious"):
        ti_sources.append("URLhaus")
    if threatfox.get("malicious"):
        ti_sources.append("ThreatFox")
    if vt.get("malicious"):
        ti_sources.append("VirusTotal")
    if ti_sources:
        malicious_signal = True
        score += w.get("threat_intel", 40)
        reasons.append(f"威胁情报命中 ({'+'.join(ti_sources)})")

    # V5.2 DNSBL: phishing / malware / scam listings are malicious signals
    if dnsbl.get("malicious"):
        malicious_signal = True
        score += w.get("dnsbl_malicious", 30)
        reasons.append(f"DNSBL 命中（{'+'.join(dnsbl.get('hits', []))}）")
    elif dnsbl.get("listed"):
        suspicious_signal = True
        score += w.get("dnsbl_listed", 15)
        reasons.append(f"DNSBL 列表命中（{'+'.join(dnsbl.get('hits', []))}）")

    # DNS: expired or private IP → suspicious
    if dns.get("nxdomain"):
        suspicious_signal = True
        score += w.get("dns_nxdomain", 15)
        reasons.append("DNS NXDOMAIN（域名已过期，白名单可能无效）")
    elif dns.get("ips") and any(_is_private_ip(ip) for ip in dns["ips"]):
        suspicious_signal = True
        score += w.get("dns_private_ip", 20)
        reasons.append(f"解析到私有/回环 IP: {dns['ips']}")

    # RDAP: newly registered → suspicious
    if rdap.get("is_new_domain"):
        suspicious_signal = True
        score += w.get("rdap_new_domain", 15)
        age = rdap.get("domain_age_days", "?")
        reasons.append(f"新注册域名（{age}天，<{config.new_domain_threshold_days}天阈值）")

    # MarketNow scam check → suspicious
    if scam.get("is_suspicious"):
        suspicious_signal = True
        score += (w.get("scam_confirmed", 30) if scam.get("is_confirmed_scam")
                  else w.get("scam_suspicious", 20))
        decision = scam.get("decision", "?")
        risk = scam.get("risk_score", 0)
        scam_reasons = scam.get("reasons", [])
        detail = "; ".join(scam_reasons[:2]) if scam_reasons else ""
        reasons.append(
            f"诈骗/钓鱼检测 [{decision}, 风险分{risk}]"
            + (f": {detail}" if detail else "")
        )

    # Offline heuristics: only escalate when several signals fire (score>=3).
    if heuristics.get("is_risky"):
        suspicious_signal = True
        score += w.get("heuristics", 10)
        flags = ", ".join(heuristics.get("flags") or []) or f"score={heuristics.get('score', 0)}"
        reasons.append(f"本地启发式风险 ({flags})")

    score = min(score, 100)

    if malicious_signal:
        return RATING_MALICIOUS, reasons, score

    # DNS failure fallbacks: never claim "DNS normal" on errors.
    dns_error = dns.get("error")
    ti_disabled = (not config.use_urlhaus and not config.use_threatfox
                   and not config.use_virustotal)
    ti_all_errors = (
        (not config.use_urlhaus or urlhaus.get("error") not in (None, "disabled"))
        and (not config.use_threatfox or threatfox.get("error") not in (None, "disabled"))
        and (not config.use_virustotal or vt.get("error") not in (None, "disabled"))
    )
    if suspicious_signal:
        return RATING_SUSPICIOUS, reasons, score
    if dns_error and (ti_disabled or ti_all_errors):
        reasons.append(f"检测不完整：DNS 查询失败 ({dns_error})，威胁情报无有效命中")
        return RATING_UNKNOWN, reasons, score
    if dns_error:
        reasons.append(f"DNS 查询失败 ({dns_error})，但威胁情报无命中")
        return RATING_UNKNOWN, reasons, score

    reasons.append("DNS 正常解析，无威胁情报标记")
    return RATING_SAFE, reasons, score


async def audit_whitelist(
    allows: List[Rule],
    source_names: Optional[Dict[str, str]] = None,
    config: Optional[AuditConfig] = None,
    # Backwards-compat kwargs (deprecated, use config instead)
    concurrency: int = 10,
    use_dns: bool = True,
    use_urlhaus: bool = True,
    use_threatfox: bool = True,
    urlhaus_delay: float = 1.0,
) -> Dict[str, Any]:
    """Audit all domain-based whitelist rules with parallel multi-layer fusion.

    All independent network layers execute concurrently per domain.
    """
    if config is None:
        config = AuditConfig(
            use_dns=use_dns, use_urlhaus=use_urlhaus,
            use_threatfox=use_threatfox, concurrency=concurrency,
            urlhaus_delay=urlhaus_delay,
        )

    source_names = source_names or {}
    targets = [a for a in allows if a.normalized_domain]
    if not targets:
        return {"summary": {"total": 0, "safe": 0, "suspicious": 0,
                            "malicious": 0, "unknown": 0}, "rules": []}

    # ── V5.2 disk cache: previously audited domains skip the network ──
    disk_cache = _disk_cache_load(config)
    disk_hits = [0]  # list for nonlocal mutation
    fresh_disk: Dict[str, Dict[str, Any]] = {}
    # V5.3: per-run in-process cache (local, not module-level) to avoid
    # cross-run / cross-test pollution. _audit_one reads/writes this dict.
    result_cache: Dict[str, _CacheEntry] = {}

    # ── Shared HTTP session for all network layers ──
    import aiohttp
    sem = asyncio.Semaphore(config.concurrency)
    ti_sem = asyncio.Semaphore(3)  # per-run, bound to this event loop
    layer_hits = {"dns_nxdomain": 0, "dns_private_ip": 0, "urlhaus": 0,
                  "threatfox": 0, "rdap_new_domain": 0, "scam_check": 0,
                  "virustotal": 0, "ai_classified": 0, "heuristics": 0,
                  "dnsbl_malicious": 0, "dnsbl_listed": 0}
    # AI budget: limit LLM calls to config.ai_max_domains (cost control)
    ai_budget = [config.ai_max_domains]  # list for nonlocal mutation in nested fn

    async with aiohttp.ClientSession() as session:

        # V5.3: build threat-feed index once (ti_mode=auto). On failure
        # _audit_one falls back to per-domain API calls.
        feed_index = None
        if config.ti_mode == "auto" and (config.use_urlhaus
                                         or config.use_threatfox):
            from .threat_feeds import ThreatFeedIndex
            feed_index = ThreatFeedIndex(
                cache_dir=config.cache_dir,
                ttl_seconds=config.feed_ttl_seconds)
            await feed_index.build(session)

        async def _audit_one(rule: Rule) -> Dict[str, Any]:
            domain = rule.normalized_domain
            cache_key = f"audit:{domain}"
            _entry = result_cache.get(cache_key)
            cached = (_entry.result if _entry and
                      (time.time() - _entry.timestamp) < CACHE_TTL else None)
            if cached:
                cached = dict(cached)
                cached["sources"] = [source_names.get(s, s) for s in rule.source_ids]
                cached["rule"] = rule.output_raw
                cached["disk_cache"] = False
                return cached
            if domain in disk_cache:
                disk_hits[0] += 1
                hit = dict(disk_cache[domain])
                hit["sources"] = [source_names.get(s, s) for s in rule.source_ids]
                hit["rule"] = rule.output_raw
                hit["disk_cache"] = True
                result_cache[cache_key] = _CacheEntry(
                    result={k: v for k, v in hit.items()
                            if k not in ("sources", "rule", "disk_cache")})
                return hit

            async with sem:
                # Layer 6: Offline PSL classification (sync, microseconds)
                category, confidence, cat_reason = classify_domain_with_confidence(domain)

                # ── Layers 1-5: parallel network queries ──
                tasks = []
                task_names = []

                if config.use_dns:
                    tasks.append(_dns_check(domain))
                    task_names.append("dns")

                if config.use_urlhaus or config.use_threatfox:
                    if feed_index is not None and feed_index.ready:
                        tasks.append(_query_threat_intel_dataset(
                            domain, feed_index))
                    else:
                        if feed_index is not None:
                            feed_index.stats["api_fallbacks"] += 1
                        tasks.append(_query_threat_intel(
                            domain, session, config, ti_sem=ti_sem))
                    task_names.append("ti")

                if config.use_rdap:
                    tasks.append(_query_rdap_wrapper(domain, session, config))
                    task_names.append("rdap")

                if config.use_scam_check:
                    tasks.append(query_scam_check(domain, session))
                    task_names.append("scam")

                if config.use_dnsbl:
                    tasks.append(_query_dnsbl(domain))
                    task_names.append("dnsbl")

                if config.use_virustotal and config.virustotal_api_key:
                    tasks.append(query_virustotal(
                        domain, config.virustotal_api_key, session))
                    task_names.append("vt")

                # Execute all network layers concurrently
                gathered = await asyncio.gather(*tasks) if tasks else []
                layer_data = dict(zip(task_names, gathered))

                dns = layer_data.get("dns", {"nxdomain": False, "ips": [], "error": "disabled"})
                ti = layer_data.get("ti", ({"malicious": False, "error": "disabled"},
                                           {"malicious": False, "error": "disabled"}))
                urlhaus, threatfox = ti if isinstance(ti, tuple) else (
                    {"malicious": False, "error": "disabled"},
                    {"malicious": False, "error": "disabled"})
                rdap = layer_data.get("rdap", {"is_new_domain": False,
                                               "domain_age_days": None,
                                               "registrar": None, "error": "disabled"})
                scam = layer_data.get("scam", {"is_suspicious": False,
                                               "is_confirmed_scam": False,
                                               "decision": None, "risk_score": 0,
                                               "reasons": [], "error": "disabled"})
                vt = layer_data.get("vt", {"malicious": False, "error": "disabled",
                                           "reputation_score": 0.0,
                                           "malicious_votes": 0})
                dnsbl = layer_data.get("dnsbl", {"listed": False, "malicious": False,
                                                 "hits": [], "error": "disabled"})

                # Offline heuristics (sync, microseconds)
                heur = local_heuristics(domain) if config.use_heuristics else {
                    "score": 0, "flags": [], "is_risky": False, "tld": ""}

                # Layer 7: AI classification (only for low confidence, after gather)
                ai_result = {"category": None, "confidence": 0.0,
                             "reason": "", "error": "disabled"}
                if (config.use_ai and config.ai_api_key
                        and confidence < config.ai_min_confidence
                        and ai_budget[0] > 0):
                    ai_budget[0] -= 1
                    try:
                        ai_result = await classify_with_ai(
                            domain, config.ai_api_key, session,
                            base_url=config.ai_base_url,
                            model=config.ai_model,
                        )
                        if ai_result.get("category") and not ai_result.get("error"):
                            category = ai_result["category"]
                            confidence = max(confidence, ai_result["confidence"] * 0.7)
                            cat_reason = f"AI: {ai_result.get('reason', '')}"
                    except Exception as e:
                        ai_result["error"] = str(e)

            # ── Multi-layer fusion (V5.2: all reasons + risk score) ──
            rating, reasons, risk_score = _fuse_rating(
                dns, urlhaus, threatfox, rdap, scam, vt, config,
                dnsbl=dnsbl, heuristics=heur)

            # Track layer hits
            if dns.get("nxdomain"):
                layer_hits["dns_nxdomain"] += 1
            if dns.get("ips") and any(_is_private_ip(ip) for ip in dns["ips"]):
                layer_hits["dns_private_ip"] += 1
            if urlhaus.get("malicious"):
                layer_hits["urlhaus"] += 1
            if threatfox.get("malicious"):
                layer_hits["threatfox"] += 1
            if rdap.get("is_new_domain"):
                layer_hits["rdap_new_domain"] += 1
            if scam.get("is_suspicious"):
                layer_hits["scam_check"] += 1
            if vt.get("malicious"):
                layer_hits["virustotal"] += 1
            if dnsbl.get("malicious"):
                layer_hits["dnsbl_malicious"] += 1
            elif dnsbl.get("listed"):
                layer_hits["dnsbl_listed"] += 1
            if heur.get("is_risky"):
                layer_hits["heuristics"] += 1
            if ai_result.get("category") and not ai_result.get("error"):
                layer_hits["ai_classified"] += 1

            result = {
                "domain": domain,
                "rule": rule.output_raw,
                "sources": [source_names.get(s, s) for s in rule.source_ids],
                "rating": rating,
                "category": category,
                "category_confidence": round(confidence, 2),
                "category_reason": cat_reason,
                "reason": "; ".join(reasons),
                "dns_ips": dns.get("ips", []),
                "dns_nxdomain": dns.get("nxdomain", False),
                "urlhaus_malicious": urlhaus.get("malicious", False),
                "threatfox_malicious": threatfox.get("malicious", False),
                "rdap_new_domain": rdap.get("is_new_domain", False),
                "rdap_domain_age_days": rdap.get("domain_age_days"),
                "rdap_registrar": rdap.get("registrar"),
                "scam_suspicious": scam.get("is_suspicious", False),
                "scam_decision": scam.get("decision"),
                "scam_risk_score": scam.get("risk_score", 0),
                "virustotal_malicious": vt.get("malicious", False),
                "virustotal_reputation": vt.get("reputation_score", 0.0),
                "dnsbl_listed": dnsbl.get("listed", False),
                "dnsbl_malicious": dnsbl.get("malicious", False),
                "dnsbl_hits": dnsbl.get("hits", []),
                "risk_score": risk_score,
                "heuristics_score": heur.get("score", 0),
                "heuristics_flags": heur.get("flags", []),
                "recommendation": _RECOMMEND.get(rating, "review"),
                "recommendation_label": _RECOMMEND_LABEL.get(
                    _RECOMMEND.get(rating, "review"), "建议复核"),
                "ai_classified": ai_result.get("category") is not None and not ai_result.get("error"),
            }
            stored = {k: v for k, v in result.items()
                      if k not in ("sources", "rule", "disk_cache")}
            result_cache[cache_key] = _CacheEntry(result=stored)
            fresh_disk[domain] = stored
            return result

        tasks = [_audit_one(r) for r in targets]
        # Defensive: a single domain must never take the whole audit down.
        # Exceptions (from any layer) are demoted to an "unknown" record.
        gathered = await asyncio.gather(*tasks, return_exceptions=True)
        results = []
        for r, rule in zip(gathered, targets):
            if isinstance(r, BaseException):
                logger.warning("audit failed for %s: %s",
                               rule.normalized_domain, r)
                results.append({
                    "domain": rule.normalized_domain,
                    "rule": rule.output_raw,
                    "sources": [source_names.get(s, s) for s in rule.source_ids],
                    "rating": RATING_UNKNOWN,
                    "category": "other",
                    "category_confidence": 0.0,
                    "category_reason": "audit exception",
                    "reason": f"审计异常: {r}",
                    "dns_ips": [], "dns_nxdomain": False,
                    "urlhaus_malicious": False, "threatfox_malicious": False,
                    "rdap_new_domain": False, "rdap_domain_age_days": None,
                    "rdap_registrar": None,
                    "scam_suspicious": False, "scam_decision": None,
                    "scam_risk_score": 0,
                    "virustotal_malicious": False, "virustotal_reputation": 0.0,
                    "dnsbl_listed": False, "dnsbl_malicious": False,
                    "dnsbl_hits": [], "risk_score": 0,
                    "heuristics_score": 0, "heuristics_flags": [],
                    "recommendation": "review",
                    "recommendation_label": "建议复核",
                    "ai_classified": False,
                })
            else:
                results.append(r)

    # persist fresh results to the disk cache (V5.2)
    _disk_cache_save(config, fresh_disk)

    # ── summary ──
    summary = {"total": len(results), "safe": 0, "suspicious": 0,
               "malicious": 0, "unknown": 0}
    all_categories = []
    for r in results:
        summary[r["rating"]] += 1
        all_categories.append(r["category"])
    summary["category_counts"] = category_counts(all_categories)
    summary["by_rating"] = {}
    for rating in (RATING_SAFE, RATING_SUSPICIOUS, RATING_MALICIOUS, RATING_UNKNOWN):
        cats = [r["category"] for r in results if r["rating"] == rating]
        summary["by_rating"][rating] = category_counts(cats)
    conf_buckets = {"high(>=0.9)": 0, "medium(0.6-0.89)": 0, "low(<0.6)": 0}
    for r in results:
        c = r.get("category_confidence", 0)
        if c >= 0.9:
            conf_buckets["high(>=0.9)"] += 1
        elif c >= 0.6:
            conf_buckets["medium(0.6-0.89)"] += 1
        else:
            conf_buckets["low(<0.6)"] += 1
    summary["category_confidence"] = conf_buckets
    # V5.2 risk score distribution + top risky domains
    risk_buckets = {"high(>=50)": 0, "medium(20-49)": 0, "low(1-19)": 0, "none(0)": 0}
    for r in results:
        s = r.get("risk_score", 0)
        if s >= 50:
            risk_buckets["high(>=50)"] += 1
        elif s >= 20:
            risk_buckets["medium(20-49)"] += 1
        elif s >= 1:
            risk_buckets["low(1-19)"] += 1
        else:
            risk_buckets["none(0)"] += 1
    summary["risk_score_buckets"] = risk_buckets
    summary["top_risky"] = [
        {"domain": r["domain"], "rating": r["rating"],
         "risk_score": r.get("risk_score", 0), "reason": r["reason"]}
        for r in sorted(results, key=lambda r: -r.get("risk_score", 0))[:10]
        if r.get("risk_score", 0) > 0
    ]
    summary["disk_cache"] = {
        "enabled": config.cache_results,
        "hits": disk_hits[0],
        "stored": len(fresh_disk),
        "path": str(_disk_cache_path(config)) if config.cache_results else None,
    }
    summary["layer_hits"] = layer_hits
    summary["layers_enabled"] = {
        "dns": config.use_dns,
        "urlhaus": config.use_urlhaus,
        "threatfox": config.use_threatfox,
        "rdap": config.use_rdap,
        "scam_check": config.use_scam_check,
        "dnsbl": config.use_dnsbl,
        "virustotal": config.use_virustotal,
        "ai": config.use_ai,
    }
    summary["execution_mode"] = "parallel"
    if feed_index is not None:
        summary["threat_feeds"] = feed_index.stats
    else:
        summary["threat_feeds"] = {"mode": "api"}

    order = {RATING_MALICIOUS: 0, RATING_SUSPICIOUS: 1,
             RATING_UNKNOWN: 2, RATING_SAFE: 3}
    results.sort(key=lambda r: (order.get(r["rating"], 9), r["domain"]))

    return {"summary": summary, "rules": results}
