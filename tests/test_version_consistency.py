"""Version single-source-of-truth guard (M0).

Pins the semver version and scans the static version points that cannot be
derived at runtime (pyproject metadata, README badge, CI cache key) for stale
fragments.  Docstrings / CHANGELOG prose that mention "V5.1" as a *feature*
reference (not a version point) are deliberately not scanned.
"""

from pathlib import Path

from merger import __version__, __version_short__, user_agent

ROOT = Path(__file__).resolve().parent.parent


def test_version_is_6_1_0():
    assert __version__ == "6.1.0"


def test_version_short_is_6_1():
    assert __version_short__ == "6.1"


def test_user_agent_tracks_version():
    assert user_agent() == "AdGuard-Rules-Merger/6.1"
    assert user_agent() == f"AdGuard-Rules-Merger/{__version_short__}"


def test_pyproject_version_aligned():
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert 'version = "6.1.0"' in text
    assert "5.2.0" not in text
    assert "5.3.0" not in text


def test_readme_badge_aligned():
    text = (ROOT / "README.md").read_text(encoding="utf-8")

    assert "Version-6.1.0-blue" in text
    assert "Version-6.0.0-blue" not in text
    assert "Version-5.3.0-blue" not in text
    assert "Version-5.2.0-blue" not in text


def test_ci_cache_key_and_name_aligned():
    text = (ROOT / ".github" / "workflows" / "merge.yml").read_text(encoding="utf-8")
    assert "rule-cache-v51" not in text
    assert "Merge Rules (V5.1)" not in text
    assert "Auto-merge V5.1" not in text


def test_sources_yaml_no_hardcoded_user_agent():
    text = (ROOT / "config" / "sources.yaml").read_text(encoding="utf-8")
    assert "AdGuard-Rules-Merger/5.2" not in text
    assert "user_agent:" not in text