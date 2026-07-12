"""Local cache for exact npm/PyPI package-version metadata."""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_REGISTRY_DB = Path.home() / ".cache" / "sbom-risk" / "registry.sqlite3"


def load(database: str | Path, component_keys: list[str]) -> dict[str, dict]:
    path = Path(database).expanduser()
    if not path.is_file() or not component_keys:
        return {}
    with sqlite3.connect(f"file:{path}?mode=ro", uri=True) as conn:
        rows = []
        for key in component_keys:
            row = conn.execute("SELECT component, metadata FROM registry_metadata WHERE component=?", (key,)).fetchone()
            if row: rows.append(row)
        return {key: json.loads(value) for key, value in rows}


def store(database: str | Path, metadata: dict[str, dict]) -> None:
    if not metadata:
        return
    path = Path(database).expanduser(); path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path) as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS registry_metadata (component TEXT PRIMARY KEY, metadata TEXT NOT NULL, fetched_at TEXT NOT NULL)")
        now = datetime.now(timezone.utc).isoformat()
        conn.executemany("INSERT INTO registry_metadata VALUES (?, ?, ?) ON CONFLICT(component) DO UPDATE SET metadata=excluded.metadata, fetched_at=excluded.fetched_at", ((key, json.dumps(value, separators=(",", ":")), now) for key, value in metadata.items()))


def info(database: str | Path = DEFAULT_REGISTRY_DB) -> dict[str, str] | None:
    path = Path(database).expanduser()
    if not path.is_file():
        return None
    with sqlite3.connect(f"file:{path}?mode=ro", uri=True) as conn:
        count = conn.execute("SELECT COUNT(*) FROM registry_metadata").fetchone()[0]
        latest = conn.execute("SELECT MAX(fetched_at) FROM registry_metadata").fetchone()[0]
    return {"path": str(path), "cached_components": str(count), "last_fetched_at": latest or "unknown"}
