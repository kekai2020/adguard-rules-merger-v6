"""Tests for V5 streaming parser."""

from merger.parser import RuleParser
from merger.models import CATEGORY_ADS


def parse_one(text, **kwargs):
    p = RuleParser(**kwargs)
    rules = p.parse_text(text, source="test", category=CATEGORY_ADS)
    return [r for r in rules if r.rule_type != "comment"], p


def test_adguard_block():
    rules, _ = parse_one("||example.com^")
    assert len(rules) == 1
    r = rules[0]
    assert r.rule_type == "block"
    assert r.normalized_domain == "example.com"
    assert r.wildcard is False
    assert r.output_raw == "||example.com^"


def test_adguard_allow():
    rules, _ = parse_one("@@||example.com^")
    assert len(rules) == 1
    assert rules[0].rule_type == "allow"
    assert rules[0].output_raw == "@@||example.com^"


def test_wildcard():
    rules, _ = parse_one("||*.example.com^")
    assert len(rules) == 1
    assert rules[0].wildcard is True
    assert rules[0].normalized_domain == "example.com"


def test_hosts_format():
    rules, _ = parse_one("0.0.0.0 ads.example.com")
    assert len(rules) == 1
    assert rules[0].normalized_domain == "ads.example.com"
    assert rules[0].output_raw == "||ads.example.com^"


def test_hosts_127_format():
    rules, _ = parse_one("127.0.0.1 ads.example.com")
    assert len(rules) == 1
    assert rules[0].normalized_domain == "ads.example.com"


def test_plain_domain():
    rules, _ = parse_one("ads.example.com")
    assert len(rules) == 1
    assert rules[0].normalized_domain == "ads.example.com"


def test_modifier_preserved_important():
    """V5: $ modifiers are preserved (these lists are AGH-curated)."""
    rules, _ = parse_one("||example.com^$important")
    assert len(rules) == 1
    assert rules[0].normalized_domain == "example.com"
    assert rules[0].modifiers == "important"
    assert rules[0].output_raw == "||example.com^$important"


def test_modifier_preserved_badfilter():
    """$badfilter must NOT be truncated — truncating would invert its semantics."""
    rules, _ = parse_one("||pl.ua^$badfilter")
    assert len(rules) == 1
    assert rules[0].modifiers == "badfilter"
    assert rules[0].output_raw == "||pl.ua^$badfilter"


def test_plain_domain_with_modifier():
    rules, _ = parse_one("wykop.pl$badfilter")
    assert len(rules) == 1
    assert rules[0].normalized_domain == "wykop.pl"
    assert rules[0].modifiers == "badfilter"
    assert rules[0].output_raw == "||wykop.pl^$badfilter"


def test_modifier_normalized_lowercase():
    rules, _ = parse_one("||example.com^$Important")
    assert rules[0].modifiers == "important"


def test_modifier_without_caret():
    """||domain$modifier (omitted ^) is valid AdGuard syntax — must parse."""
    rules, _ = parse_one("||deloton.com$important")
    assert len(rules) == 1
    assert rules[0].normalized_domain == "deloton.com"
    assert rules[0].modifiers == "important"
    assert rules[0].output_raw == "||deloton.com^$important"


def test_css_dropped():
    rules, p = parse_one("example.com##.ad-banner")
    assert len(rules) == 0
    assert p.css_dropped == 1


def test_embedded_wildcard_dropped():
    rules, p = parse_one("||*-ads.example.com^")
    assert len(rules) == 0
    assert p.pattern_dropped == 1


def test_regex_kept():
    rules, _ = parse_one("/^192\\.168\\.\\d+\\.\\d+$/")
    assert len(rules) == 1
    assert rules[0].normalized_domain == ""
    assert rules[0].output_raw.startswith("/")


def test_lowercase_and_trailing_dot():
    rules, _ = parse_one("||EXAMPLE.COM.^")
    assert rules[0].normalized_domain == "example.com"


def test_leading_dot_normalized():
    rules, _ = parse_one("||.example.com^")
    # leading dot stripped -> example.com
    assert rules[0].normalized_domain == "example.com"


def test_strip_www():
    rules, _ = parse_one("||www.example.com^", strip_www=True)
    assert rules[0].normalized_domain == "example.com"


def test_no_strip_www_by_default():
    rules, _ = parse_one("||www.example.com^")
    assert rules[0].normalized_domain == "www.example.com"


def test_localhost_filtered():
    rules, p = parse_one("||localhost^")
    assert len(rules) == 0
    assert p.quality_dropped == 1


def test_short_domain_filtered():
    # min_domain_length defaults to 4; "a.co" is 4 chars -> passes; "a.b" is 3 -> drops
    rules, p = parse_one("||a.b^")
    assert len(rules) == 0
    assert p.quality_dropped == 1


def test_comments_not_materialised():
    p = RuleParser()
    rules = p.parse_text("! comment\n||example.com^\n# hash\n")
    assert len(rules) == 1
    assert rules[0].normalized_domain == "example.com"
    assert p.comment_dropped == 2


def test_cosmetic_modifiers_stripped():
    rules, p = parse_one("||example.com^$script,third-party,popup")
    assert len(rules) == 1
    assert rules[0].modifiers == ""
    assert rules[0].output_raw == "||example.com^"
    assert p.modifier_stripped == 1


def test_important_kept_when_mixed_with_cosmetic():
    rules, _ = parse_one("||example.com^$script,important")
    assert rules[0].modifiers == "important"
    assert rules[0].output_raw == "||example.com^$important"


def test_ipv6_hosts():
    rules, _ = parse_one("::1 ads.example.com")
    assert len(rules) == 1
    assert rules[0].normalized_domain == "ads.example.com"


def test_dnstype_modifier_kept():
    rules, _ = parse_one("||example.com^$dnstype=A")
    assert rules[0].modifiers == "dnstype=A"



def test_crlf_input_parses_same_as_lf():
    """StringIO universal-newlines must treat \\r\\n and \\r like \\n."""
    lf = "! comment\n||ads.example.com^\n||track.example.com^\n"
    crlf = "! comment\r\n||ads.example.com^\r\n||track.example.com^\r\n"
    cr_only = "! comment\r||ads.example.com^\r||track.example.com^\r"
    expected = ["ads.example.com", "track.example.com"]
    for text in (lf, crlf, cr_only):
        p = RuleParser()
        assert [r.normalized_domain for r in p.parse_text(text)] == expected

# ── C1: URL-layer rules must be dropped, not silently widened to the domain ──

def test_url_path_rule_dropped():
    rules, p = parse_one("||example.com/path^")
    assert rules == []
    assert p.pattern_dropped == 1


def test_separator_anchor_dropped():
    rules, p = parse_one("||example.com^|")
    assert rules == []
    assert p.pattern_dropped == 1


def test_caret_trailing_text_dropped():
    rules, p = parse_one("||example.com^text")
    assert rules == []
    assert p.pattern_dropped == 1


def test_allow_url_path_dropped():
    rules, p = parse_one("@@||example.com/path^")
    assert rules == []
    assert p.pattern_dropped == 1


def test_important_modifier_not_dropped_by_rest_check():
    rules, p = parse_one("||example.com^$important")
    assert len(rules) == 1
    assert rules[0].normalized_domain == "example.com"
    assert p.pattern_dropped == 0


def test_bare_domain_without_caret_not_dropped():
    rules, p = parse_one("||example.com$important")
    assert len(rules) == 1
    assert rules[0].normalized_domain == "example.com"
    assert p.pattern_dropped == 0

# ── C14: regex flag sort normalization ─────────────────────────────

def test_regex_flags_sorted():
    from merger.parser import RuleParser
    nr = RuleParser._normalize_regex
    assert nr("/regex/$b,a") == "/regex/$a,b"
    assert nr("/regex/$a,b") == "/regex/$a,b"

def test_regex_flags_deduped():
    from merger.parser import RuleParser
    assert RuleParser._normalize_regex("/regex/$a,b,a") == "/regex/$a,b"

def test_regex_flags_allow_prefix_preserved():
    from merger.parser import RuleParser
    assert RuleParser._normalize_regex("@@/regex/$b,a") == "@@/regex/$a,b"

def test_regex_no_flags_unchanged():
    from merger.parser import RuleParser
    assert RuleParser._normalize_regex("/regex/") == "/regex/"

def test_regex_escaped_slash_in_pattern():
    from merger.parser import RuleParser
    assert RuleParser._normalize_regex(r"/a\/b/$b,a") == r"/a\/b/$a,b"
