"""Blob cache for threat-intel feeds (V5.3).

Independent from SourceCache (which caches parsed Rule records). Stores
raw feed blobs + metadata (content_hash, last_checked_at) so
ThreatFeedIndex can skip re-downloading unchanged feeds.
"""
from __future__ import annotations

import hashlib
import json
import logging
import time
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger(__name__)


class FeedCache:
    """Persists raw feed blobs with content-hash + last-checked metadata."""

    def __init__(self, cache_dir: str = "cache") -> None:
        self._dir = Path(cache_dir) / "feeds"

    def store_blob(self, name: str, blob: bytes) -> str:
        """Store *blob* under *name*, return its sha256 content hash."""
        self._dir.mkdir(parents=True, exist_ok=True)
        h = hashlib.sha256(blob).hexdigest()
        meta = {"content_hash": h, "last_checked_at": time.time(),
                "size": len(blob)}
        (self._dir / f"{name}.blob").write_bytes(blob)
        (self._dir / f"{name}.meta.json").write_text(
            json.dumps(meta, ensure_ascii=False), encoding="utf-8")
        return h

    def load_blob(self, name: str) -> Optional[Tuple[bytes, Dict[str, Any]]]:
        """Return (blob, metadata) or None if not cached."""
        blob_path = self._dir / f"{name}.blob"
        meta_path = self._dir / f"{name}.meta.json"
        if not blob_path.exists() or not meta_path.exists():
            return None
        try:
            blob = blob_path.read_bytes()
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
            return blob, meta
        except (OSError, json.JSONDecodeError) as e:
            logger.warning("feed cache '%s' unreadable: %s", name, e)
            return None

    def update_checked_time(self, name: str) -> None:
        """Refresh last_checked_at without re-storing the blob."""
        self._dir.mkdir(parents=True, exist_ok=True)
        meta_path = self._dir / f"{name}.meta.json"
        if not meta_path.exists():
            return
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
            meta["last_checked_at"] = time.time()
            meta_path.write_text(json.dumps(meta, ensure_ascii=False),
                                 encoding="utf-8")
        except (OSError, json.JSONDecodeError):
            pass