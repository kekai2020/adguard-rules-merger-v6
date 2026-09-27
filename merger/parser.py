"""V5.1 streaming parser for DNS-layer AdGuard / Hosts / plain-domain lists.

Parsing rules (strict DNS-layer only):
  - AdGuard block:  ``||domain^``            -> block
  - AdGuard allow:  ``@@||domain^``         -> allow
  - Wildcard:       ``||*.domain^``         -> block, wildcard=True
  - Hosts:          ``0.0.0.0 domain``      -> block
  - IPv6 hosts:     ``::1 domain`` / ``:: domain``
  - Plain domain:  ``example.com``          -> block
  - Comment:        ``! ...`` / ``# ...``   -> skipped (not materialised)
  - Regex:          ``/regex/``             -> kept as-is (AGH supports it)
  - ``$ modifiers``: DNS-meaningful flags kept (important, badfilter,
    dnstype, dnsrewrite, client, ctag, ipset, resolver). Cosmetic
    modifiers (script, third-party, popup, ...) are stripped so AGH DNS
    does not ignore the rule.

V5.1:
  - Comments are counted, not turned into Rule objects.
  - Cosmetic $ modifiers stripped; DNS modifiers preserved.
  - IPv6 hosts lines accepted.
  - Per-parse drop counters (thread-safe if each parse uses its own parser).
"""

from __future__ import annotations

import io
import re
from typing import Iterator, List, Optional, Set, Tuple

from .models import Rule, CATEGORY_OTHER


# DNS-layer modifiers AdGuard Home honours. Everything else is cosmetic
# (script/third-party/popup/...) and would make AGH skip or warn on the rule.
_DNS_FLAG_MODS = frozenset({"important", "badfilter"})
_DNS_VALUED_PREFIXES = (
    "dnstype=", "dnsrewrite=", "client=", "ctag=",
    "ipset=", "resolver=",
)


class RuleParser:
    """High-performance streaming parser with drop counters."""

    # ── pre-compiled patterns ──────────────────────────────────
    # ^ is optional when $ modifiers follow directly: ||domain$important
    RE_BLOCK = re.compile(r"^\|\|([^/^\s$]+)\^?")
    RE_ALLOW = re.compile(r"^@@\|\|([^/^\s$]+)\^?")
    RE_WILD_PREFIX = re.compile(r"^\*\.")
    RE_HOSTS = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}\s+(\S+)")
    RE_HOSTS_V6 = re.compile(
        r"^(?:(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}|::1?)\s+(\S+)"
    )
    RE_DOMAIN = re.compile(r"^([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}$")
    RE_WILD_DOMAIN = re.compile(r"^\*\.([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}$")
    RE_CSS = re.compile(r"#@?#|#%#")  # CSS/JS: ##, #@#, #%# (may be domain-prefixed)
    RE_REGEX = re.compile(r"^(?:@@)?/.+/\$?[a-z,]*$")
    RE_URLBAR = re.compile(r"^\|?https?://")
    RE_COMMENT_HASH = re.compile(r"^#(?!#|@#|%)")

    LOCALHOST: Set[str] = frozenset({
        "localhost", "localhost.localdomain",
        "localhost6", "localhost6.localdomain6",
        "local", "localdomain",
    })

    def __init__(
        self,
        strip_www: bool = False,
        quality_filter: bool = True,
        min_domain_length: int = 4,
        max_domain_length: int = 253,
        filter_localhost: bool = True,
        filter_ip_rules: bool = False,
    ) -> None:
        self.pattern_dropped = 0
        self.quality_dropped = 0
        self.css_dropped = 0
        self.comment_dropped = 0
        self.modifier_stripped = 0
        self.strip_www = strip_www
        self.quality_filter_enabled = quality_filter
        self.min_domain_length = min_domain_length
        self.max_domain_length = max_domain_length
        self.filter_localhost = filter_localhost
        self.filter_ip_rules = filter_ip_rules

    def reset_counters(self) -> None:
        self.pattern_dropped = 0
        self.quality_dropped = 0
        self.css_dropped = 0
        self.comment_dropped = 0
        self.modifier_stripped = 0

    # ── helpers ────────────────────────────────────────────────

    @staticmethod
    def _clean(domain: str) -> str:
        d = domain.lower().strip()
        if d.endswith("."):
            d = d[:-1]
        if d.startswith("."):
            d = d[1:]
        return d

    @staticmethod
    def _is_ip(text: str) -> bool:
        parts = text.split(".")
        if len(parts) == 4:
            try:
                return all(0 <= int(p) <= 255 for p in parts)
            except ValueError:
                return False
        return False

    @staticmethod
    def _split_modifiers(s: str) -> Tuple[str, str, bool]:
        """Return (line_without_$section, normalized_modifiers_str, stripped).

        Cosmetic (non-DNS) modifiers are dropped; ``stripped`` is True when
        at least one cosmetic flag was removed.
        """
        i = s.find("$")
        if i == -1:
            return s, "", False
        body = s[:i].strip()
        mod_str = s[i + 1:].strip()
        if not mod_str:
            return body, "", False
        flags = []
        valued = []
        stripped = False
        for m in mod_str.split(","):
            m = m.strip()
            if not m:
                continue
            if "=" in m:
                key, _, val = m.partition("=")
                key = key.strip().lower()
                combined = f"{key}={val.strip()}"
                if combined.startswith(_DNS_VALUED_PREFIXES):
                    valued.append(combined)
                else:
                    stripped = True
            else:
                flag = m.lower()
                if flag in _DNS_FLAG_MODS:
                    flags.append(flag)
                else:
                    stripped = True
        flags = sorted(set(flags))
        valued = sorted(set(valued))
        normalized = ",".join(flags + valued)
        return body, normalized, stripped

    @staticmethod
    def _normalize_regex(raw: str) -> str:
        """Normalize regex rules: strip whitespace + sort trailing $flags.

        Ensures ``/regex/$b,a`` and ``/regex/$a,b`` produce identical output
        (deterministic ordering), which helps dedup and byte-stable diffs.
        """
        s = raw.strip()
        prefix = ""
        body = s
        if body.startswith("@@"):
            prefix = "@@"
            body = body[2:]
        m = re.match(r"^(.+/)\$([a-z,]+)$", body)
        if m:
            flags = sorted(set(f for f in m.group(2).split(",") if f))
            return prefix + m.group(1) + "$" + ",".join(flags)
        return s

    def _valid_dns_domain(self, d: str) -> bool:
        if "*" not in d:
            return True
        return d.startswith("*.") and "*" not in d[2:]

    def _quality_check(self, d: str) -> bool:
        if not self.quality_filter_enabled:
            return True
        check_d = d[2:] if d.startswith("*.") else d
        if len(check_d) < self.min_domain_length:
            return False
        if len(check_d) > self.max_domain_length:
            return False
        if self.filter_localhost:
            if check_d in self.LOCALHOST or check_d.endswith(".localhost") or check_d.endswith(".local"):
                return False
        if self.filter_ip_rules:
            if self._is_ip(check_d):
                return False
        if "." not in check_d:
            return False
        parts = check_d.split(".")
        if any(not p for p in parts):
            return False
        return True

    def _make_rule(self, raw_line: str, d: str, rule_type: str,
                   wildcard: bool, source: str, category: str,
                   modifiers: str = "") -> Optional[Rule]:
        if not d or not self._valid_dns_domain(d):
            if d and "*" in d:
                self.pattern_dropped += 1
            return None
        if not self._quality_check(d):
            self.quality_dropped += 1
            return None
        mod = f"${modifiers}" if modifiers else ""
        if rule_type == "allow":
            raw = f"@@||{d}^{mod}"
        else:
            raw = f"||{d}^{mod}"
        return Rule(raw=raw, domain=d, rule_type=rule_type,
                    wildcard=wildcard, sources=source, category=category,
                    strip_www=self.strip_www, modifiers=modifiers)

    # ── streaming parse ─────────────────────────────────────────

    def parse_stream(
        self,
        lines: Iterator[str],
        source: str = "",
        category: str = CATEGORY_OTHER,
    ) -> Iterator[Rule]:
        re_block = self.RE_BLOCK.match
        re_allow = self.RE_ALLOW.match
        re_hosts = self.RE_HOSTS.match
        re_hosts_v6 = self.RE_HOSTS_V6.match
        re_plain = self.RE_DOMAIN.match
        re_wild_plain = self.RE_WILD_DOMAIN.match
        re_css = self.RE_CSS.search
        re_regex = self.RE_REGEX.match
        re_urlbar = self.RE_URLBAR.match
        re_hash_comment = self.RE_COMMENT_HASH.match
        re_wild = self.RE_WILD_PREFIX.match
        clean = self._clean
        is_ip = self._is_ip
        localhost = self.LOCALHOST
        split_mod = self._split_modifiers
        norm_regex = self._normalize_regex
        RuleCls = Rule
        strip_www = self.strip_www

        for line in lines:
            if not line:
                continue
            s = line.strip()
            if not s:
                continue

            # comments: ! or # (but not ## / #@#) — counted, not materialised
            if s.startswith("!") or re_hash_comment(s):
                self.comment_dropped += 1
                continue

            is_css = re_css(s)
            if is_css or re_urlbar(s):
                if is_css:
                    self.css_dropped += 1
                continue

            # regex rules — kept as-is (light whitespace normalization)
            if re_regex(s):
                s = norm_regex(s)
                rule_type = "allow" if s.startswith("@@") else "block"
                yield RuleCls(raw=s, domain="", rule_type=rule_type,
                              wildcard=False, sources=source,
                              category=category, strip_www=strip_www)
                continue

            s2, modifiers, stripped_mods = split_mod(s)
            if stripped_mods:
                self.modifier_stripped += 1
            if not s2:
                continue

            # allow: @@||domain^
            m = re_allow(s2)
            if m:
                # Anything after the domain + optional ^ (a /path, | anchor, or
                # trailing text) is a URL-layer rule — drop it, don't silently
                # widen to the bare domain (over-blocking).
                if s2[m.end():]:
                    self.pattern_dropped += 1
                    continue
                d = clean(m.group(1))
                r = self._make_rule(s2, d, "allow", re_wild(d) is not None,
                                    source, category, modifiers=modifiers)
                if r:
                    yield r
                continue

            # block: ||domain^
            m = re_block(s2)
            if m:
                if s2[m.end():]:
                    self.pattern_dropped += 1
                    continue
                d = clean(m.group(1))
                r = self._make_rule(s2, d, "block", re_wild(d) is not None,
                                    source, category, modifiers=modifiers)
                if r:
                    yield r
                continue

            # hosts: IPv4 hostname
            m = re_hosts(s2)
            if m:
                d = clean(m.group(1))
                if d in localhost or "*" in d:
                    if "*" in d:
                        self.pattern_dropped += 1
                    continue
                r = self._make_rule(s2, d, "block", False, source, category,
                                    modifiers=modifiers)
                if r:
                    yield r
                continue

            # hosts: IPv6 hostname
            m = re_hosts_v6(s2)
            if m:
                d = clean(m.group(1))
                if d in localhost or "*" in d:
                    if "*" in d:
                        self.pattern_dropped += 1
                    continue
                r = self._make_rule(s2, d, "block", False, source, category,
                                    modifiers=modifiers)
                if r:
                    yield r
                continue

            # plain wildcard domain: *.example.com
            if re_wild_plain(s2) and not is_ip(s2):
                d = clean(s2)
                r = self._make_rule(s2, d, "block", True, source, category,
                                    modifiers=modifiers)
                if r:
                    yield r
                continue

            # plain domain
            if re_plain(s2) and not is_ip(s2):
                d = clean(s2)
                r = self._make_rule(s2, d, "block", False, source, category,
                                    modifiers=modifiers)
                if r:
                    yield r
                continue

    # ── bulk ────────────────────────────────────────────────────

    def parse_text(
        self,
        text: str,
        source: str = "",
        category: str = CATEGORY_OTHER,
    ) -> List[Rule]:
        # Stream lines via StringIO: it iterates on demand without building a
        # full list of every line (str.splitlines() on a 2M-line source peaks
        # an extra 200-400MB). newline=None enables universal-newlines so \n,
        # \r and \r\n are all treated as line separators (StringIO's default
        # newline='\n' would only split on \n).
        return list(self.parse_stream(io.StringIO(text, newline=None),
                                      source, category))

    @staticmethod
    def compact_records(rules: List[Rule]) -> List[tuple]:
        """Serializable tuples for the parsed-rule sidecar cache."""
        recs = []
        for r in rules:
            recs.append((
                r.rule_type, r.normalized_domain, r.wildcard,
                r.modifiers, r.category, r.raw if r.normalized_domain == "" else "",
            ))
        return recs

    @staticmethod
    def rules_from_records(records: List[tuple], source: str,
                           strip_www: bool = False) -> List[Rule]:
        rules: List[Rule] = []
        for rule_type, domain, wildcard, modifiers, category, raw in records:
            rules.append(Rule(
                raw=raw or "",
                domain=domain,
                rule_type=rule_type,
                wildcard=wildcard,
                sources=source,
                category=category,
                strip_www=strip_www,
                modifiers=modifiers,
            ))
        return rules
