"""Single source of truth for package version metadata.

This module deliberately imports nothing from the rest of ``merger`` so that
every other module (including ``config_loader``) can import it without any
circular-import risk.  All visible version points derive from ``__version__``
here; never hardcode a version string elsewhere at runtime.
"""

__version__ = "6.1.0"
# X.Y fragment derived from __version__ (first two segments only).
__version_short__ = ".".join(__version__.split(".")[:2])


def user_agent() -> str:
    """Return the canonical User-Agent string, bound to the current version."""
    return f"AdGuard-Rules-Merger/{__version_short__}"