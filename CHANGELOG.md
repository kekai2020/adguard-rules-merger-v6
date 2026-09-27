# Changelog

## 6.1.0

Refactor & hardening release: dead-code removal, hot-path memory reduction,
configurability completion, defensive audit handling and full V6 version
identity. No breaking changes to the CLI, config schema, or output formats;
rule-file bytes change once (header version string), then stay stable.

### Dead Code Removed
- `exporter._EMPTY_HASH` constant (was already unused — the 6.0.0 entry
  claimed it was gone, but the constant itself survived).
- `AsyncRuleEngine._compute_contributions` and `_compute_source_overlap`
  (production code had already fused them into `_compute_stats`; only tests
  still called them — tests now target `_compute_stats`).
- `config_loader.load_source_metas` (no callers anywhere).
- Dead `idx` parameter of `whitelist_audit._query_threat_intel` / `_audit_one`.

### Performance
- Stats hot path walks provenance via the lazy `models.iter_source_keys`
  generator; `_compute_stats` rows store the integer `source_mask` instead of
  a per-rule source tuple, keeping memory flat on millions of rules.
- `run()` avoids building two full `list(...)` copies when clearing `raw`;
  `_compute_modifier_stats` iterates via `chain`.
- Parser evaluates the CSS/URL-bar drop regex once per line instead of twice.

### Configurability & Correctness
- `_fuse_rating` now actually reads `AuditConfig.fusion_weights` (defaults are
  identical to the previous hard-coded scores, so default ratings are
  unchanged); weights were previously only part of the cache fingerprint.
- `aggregation.promotion_mode` and `whitelist_audit.ti_mode` are validated as
  `Literal[...]` at config load — typos fail fast instead of silently using
  defaults.

### Robustness & Security
- `audit_whitelist` gathers audit tasks with `return_exceptions=True`; a
  single domain that raises can no longer abort the whole whitelist audit
  (exceptions are demoted to an "unknown" record with a warning log).
- HTML report escapes `</` in JSON embedded in `<script>` blocks, closing a
  potential XSS vector via hostile domain labels.
- Report defense-in-depth table/prose now lists all 8 layers (DNSBL row
  added); fixed a stray `colspan="10"` on a 6-column table.
- `import hashlib` / `import traceback` moved to module top.

### Version Identity (V5 → V6)
- CLI name/help (`adguard-rules-merger-v6`), rule-file titles
  (`(V6)`), report titles, CI workflow name, cache key prefix
  (`rule-cache-v6-`), artifact name (`merged-rules-v6`), requirements and
  config header comments. The parsed-sidecar / cache-index schema versions
  are deliberately untouched (they tag the on-disk format, not the product
  version — old sidecars must keep loading).
- Version bumped to **6.1.0** (single source of truth in `merger/version.py`;
  pyproject, README badge and version-consistency tests updated in lockstep).
- AGENTS.md rewritten to match the 6.x reality (was still describing V5 /
  5.2.0–5.3.0 inconsistencies that are long resolved).

### Tests
- 249 unit tests (was 247): fusion weights actually drive the score;
  `_json_for_script` escapes `</script>` (unit + end-to-end hostile label).

## 6.0.0

Major version bump consolidating all V5.3 fixes and design兑现. No breaking
changes to the CLI, config, or output formats — the major bump reflects the
scope of internal hardening and the threat-intel regression fix.

### Bug Fixes
- **Critical**: `_query_threat_intel` function body restored — the `async with
  ti_sem` block was erroneously placed after `_query_threat_intel_dataset`'s
  return, causing URLhaus/ThreatFox to silently return `disabled` under the
  default `ti_mode="api"` configuration.
- Added direct regression test for `_query_threat_intel` (no monkeypatch),
  guarding against future死代码 reintroduction.

### Design兑现 (previously claimed but未落地)
- `_compute_stats` now truly fuses contributions + source_overlap into a single
  `chain(blocks, allows)` traversal + list iteration (was 2 chain traversals).
- `_variant_label` restored to `(child, parent, counters)` signature with
  `promotion_multi_level_skipped` counter for multi-level label changes.
- Graded whitelist files now use real SHA-256 content hash instead of
  `_EMPTY_HASH` constant.
- `CacheEntry.is_negative` dead field removed (negative cache handled by
  engine-level `_negative_cache` dict).
- `threat_feeds._fetch_feed` returns `(blob, from_cache)`; when content hash
  is unchanged, skips re-parsing and only refreshes `last_checked_at`.

### Code Hygiene
- Removed unused `load_source_metas` import from `merge_rules.py`.
- `AsyncRuleEngine.__init__` explicitly initializes `self._badfilter_cancelled`.
- URLhaus feed parser skips non-domain lines (HTML/URL) from UA-verification
  responses.
- `test_config_validate` tests now isolate `output`/`cache` directories to
  `tmp_path` for CI stability.

## 5.3.0

Hardening, memory and test-coverage release. Restores several defensive
guards, merges the useful offline features, and expands the suite.

### Correctness
- MarketNow `CAUTION`/`TRUSTED` labels never escalate to suspicious, even when
  the API returns a high numeric score (centralised in
  `evaluate_scam_decision`). Verified: 0 CAUTION false positives.
- Wildcard promotion skips parents that `$badfilter` just voided
  (`_badfilter_cancelled`), preventing a cancelled `||*.x^` from being
  recreated by sibling promotion.
- Per-run threat-intel semaphore (created inside `audit_whitelist`) so
  repeated `asyncio.run()` / pytest loops no longer share an event-loop-bound
  Semaphore.
- Disk-cache write uses a single shared timestamp for all entries.

### Performance / memory
- `parse_text` streams via `io.StringIO(newline=None)` instead of
  `str.splitlines()`, avoiding a full per-line list (peak −200–400MB on the
  largest source); universal-newlines cover `\n`, `\r` and `\r\n`.
- `_iter_parents` is a generator with an early `min_labels` stop (was a full
  parent list per rule).
- Cache index is dirty-flagged and flushed via `save_if_dirty()` once, rather
  than after every source.
- `mask_to_sources` extracts set bits with `m & -m`; `merge_category`
  interns the winner; graded whitelist files reuse a constant empty hash.
- Domain classifier performs a single PSL extraction per domain and exposes
  the public `registered_domain()` helper.

### Observability
- Failed sources carry a coarse `error_type` (timeout / not_found / auth /
  dns / network), shown in the CLI and stats.

### Tests
- 169 unit tests (was 151): CAUTION/TRUSTED decision guards, `_iter_parents`
  boundaries, badfilter+promotion full-run integration, cache dirty-flag and
  shared-hash eviction, CR/CRLF parse parity.

## 5.2.0

Report accuracy, whitelist-audit depth, and wall-time robustness release.

### Reports
- 按源贡献分析：regex rules are now counted (they used to vanish, making e.g.
  DNS Rebind Protection show `16 3 0 100%`); new columns 输出覆盖 / 覆盖率 /
  独占率 (unique/effective) replace the misleading unique/(unique+shared) ratio.
- 源间重复矩阵: full pairwise matrix with 共同规则数 + Jaccard 重复率 in every
  cell, heat colours in HTML (hover shows both directional rates) and an emoji
  scale (🟥🟧🟨🟩) in Markdown; numbered legend keeps 18-wide matrices readable.
- Matrix lookups are symmetric in both directions (fixed a one-way fallback bug).

### Whitelist audit
- New DNSBL layer: Spamhaus DBL + SURBL free keyless DNS lookups; malware /
  phishing / scam / botnet listings are malicious signals, spam/junk/abused
  are suspicious signals.
- Fusion now collects **all** reasons (no early return) and adds a weighted
  `risk_score` (0-100) per domain; summary gains risk buckets + top-risky list.
- 24h disk cache (`cache/whitelist_audit_cache.json`) — repeat runs skip all
  audit network lookups for unchanged domains (verified: 226/226 cache hits).

### Performance & robustness
- Per-source fetch deadline (`download.source_deadline`, default 120s) covers
  all retry attempts; dead sources fall back to their stale cache instead of
  burning (retries+1)×timeout. Real-world run: 383s → 146s wall.
- Deterministic sort: `sort_key()` / `__lt__` tiebreak on the raw rule, so
  regex rules no longer follow network completion order — identical inputs now
  produce byte-identical output regardless of fetch timing.
- Parsed-rule sidecar persists the drop counters, so cache-hit runs report the
  same diagnostics (pattern/quality/css/comment/modifier) as full parses.
- `output_raw` is memoised (hash + multi-format export stop re-rendering);
  `bin(x).count("1")` replaced with `int.bit_count()`; no list copies on the
  export release path.

### Tests
- 151 unit tests (was 122): DNSBL reply parsing, all-reasons fusion + scoring,
  disk-cache TTL, matrix symmetry, regex contribution accounting, sort
  determinism, deadline retry capping, sidecar counter round-trip.

## 5.1.0

Correctness, memory, and CI-determinism release.

### Fixed
- HTTP 304 with a missing cache body no longer stores an empty source.
- Cache index 304 timestamp is persisted; concurrent stores are locked.
- Comments are counted, not turned into `Rule` objects or raw-count inflation.
- Rule / whitelist / tiered files no longer embed a wall-clock `Generated` line, so identical rules produce a byte-identical commit.
- Cosmetic `$` modifiers (`script`, `third-party`, `popup`, …) are stripped; DNS-meaningful ones (`important`, `badfilter`, `dnstype`, `dnsrewrite`, `client`, …) stay.
- `whitelist_audit.ai.max_domains` is actually passed through to the auditor.
- Per-source `timeout` is honoured on fetch.
- HTML report interpolations are escaped.
- MarketNow `CAUTION` no longer auto-marks a whitelist domain as suspicious.
- GitHub Actions no longer uses a unique `run_id` cache key or a redundant second save; subscription files only are committed; `git pull --rebase` before push.

### Performance
- Provenance is an integer bitmask (`source_mask |=`); no per-rule URL tuples and no `tuple(sorted(set(...)))` on the hot path.
- Unchanged source bodies reuse a parsed-rule sidecar (skip regex parse).
- CPU parse runs in a thread pool so downloads are not stalled.
- `list.sort(key=Rule.sort_key)` once; the previous double-sort is gone.
- Domain classifier uses dict lookup instead of scanning every pattern.

### Config
- Default `whitelist_audit.enabled: false`.
- API keys read from `VIRUSTOTAL_API_KEY` / `OPENAI_API_KEY` when YAML is blank.
- `AsyncRuleEngine.from_config(cfg)` replaces the 40-keyword constructor at the CLI.

### Tests
- Added cache, badfilter, bitmask, local-file merge, header stability, IPv6 hosts, cosmetic-modifier, and comment-skip coverage.
