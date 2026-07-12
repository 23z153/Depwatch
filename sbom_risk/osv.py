"""Local-only OSV archive cache.

The explicit sync command downloads public OSV archives. Normal scans only read
this SQLite file and never send project package/version data to an API.
"""
from __future__ import annotations

import json
import os
import sqlite3
import tempfile
import urllib.request
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

DEFAULT_DB = Path.home() / ".cache" / "sbom-risk" / "osv.sqlite3"
DEFAULT_ECOSYSTEMS = ("PyPI", "npm", "Maven", "Go", "crates.io")


def sync_osv(database: str | Path = DEFAULT_DB, ecosystems: Iterable[str] = DEFAULT_ECOSYSTEMS,
             timeout: int = 120, progress=print) -> dict[str, int]:
    """Atomically replace a local SQLite cache from OSV public GCS archives."""
    output = Path(database).expanduser(); output.parent.mkdir(parents=True, exist_ok=True)
    selected = tuple(dict.fromkeys(ecosystems))
    if not selected: raise ValueError("At least one OSV ecosystem is required")
    fd, name = tempfile.mkstemp(prefix="osv-", suffix=".sqlite3", dir=output.parent); os.close(fd)
    counts: dict[str, int] = {}
    try:
        conn = sqlite3.connect(name)
        conn.executescript("CREATE TABLE vulnerabilities (ecosystem TEXT, package TEXT, record TEXT); CREATE INDEX by_package ON vulnerabilities(ecosystem, package); CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT);")
        for ecosystem in selected:
            progress(f"Downloading OSV {ecosystem} archive…")
            with urllib.request.urlopen(f"https://storage.googleapis.com/osv-vulnerabilities/{ecosystem}/all.zip", timeout=timeout) as response:
                with tempfile.SpooledTemporaryFile(max_size=16 * 1024 * 1024) as payload:
                    while chunk := response.read(1024 * 1024): payload.write(chunk)
                    payload.seek(0); counts[ecosystem] = _ingest(conn, payload, ecosystem)
            progress(f"  indexed {counts[ecosystem]:,} affected-package records")
        conn.execute("INSERT INTO metadata VALUES (?, ?)", ("synced_at", datetime.now(timezone.utc).isoformat()))
        conn.execute("INSERT INTO metadata VALUES (?, ?)", ("ecosystems", json.dumps(selected)))
        conn.commit(); conn.close(); os.replace(name, output)
    except Exception:
        Path(name).unlink(missing_ok=True); raise
    return counts


def records_for(database: str | Path, ecosystem: str, package: str) -> list[dict]:
    path = Path(database).expanduser()
    if not path.is_file(): return []
    with sqlite3.connect(f"file:{path}?mode=ro", uri=True) as conn:
        rows = conn.execute("SELECT record FROM vulnerabilities WHERE ecosystem=? AND package=?", (osv_ecosystem(ecosystem), package)).fetchall()
    return [json.loads(row[0]) for row in rows]


def records_for_components(database: str | Path, components: Iterable[tuple[str, str]]) -> dict[tuple[str, str], list[dict]]:
    """Fetch all component records through one read-only SQLite connection.

    Keeping the connection open for the batch avoids filesystem/SQLite setup
    cost per dependency on large lockfiles.
    """
    path = Path(database).expanduser()
    requested = list(dict.fromkeys((ecosystem, package) for ecosystem, package in components))
    found: dict[tuple[str, str], list[dict]] = {(ecosystem, package): [] for ecosystem, package in requested}
    if not path.is_file() or not requested:
        return found
    with sqlite3.connect(f"file:{path}?mode=ro", uri=True) as conn:
        cursor = conn.cursor()
        for ecosystem, package in requested:
            rows = cursor.execute("SELECT record FROM vulnerabilities WHERE ecosystem=? AND package=?", (osv_ecosystem(ecosystem), package)).fetchall()
            found[(ecosystem, package)] = [json.loads(row[0]) for row in rows]
    return found


def info(database: str | Path = DEFAULT_DB) -> dict[str, str] | None:
    path = Path(database).expanduser()
    if not path.is_file(): return None
    with sqlite3.connect(f"file:{path}?mode=ro", uri=True) as conn: return dict(conn.execute("SELECT key, value FROM metadata"))


def osv_ecosystem(ecosystem: str) -> str:
    return {"pypi": "PyPI", "npm": "npm", "maven": "Maven", "golang": "Go", "cargo": "crates.io"}.get(ecosystem.lower(), ecosystem)


def _ingest(conn: sqlite3.Connection, fileobj, fallback: str) -> int:
    count = 0
    with zipfile.ZipFile(fileobj) as archive:
        for member in archive.infolist():
            if member.is_dir() or not member.filename.endswith(".json"): continue
            try: record = json.loads(archive.read(member))
            except (OSError, json.JSONDecodeError): continue
            if record.get("withdrawn"): continue
            text = json.dumps(record, separators=(",", ":"))
            rows = [(item.get("package", {}).get("ecosystem", fallback), item.get("package", {}).get("name"), text) for item in record.get("affected", []) if item.get("package", {}).get("name")]
            conn.executemany("INSERT INTO vulnerabilities VALUES (?, ?, ?)", rows); count += len(rows)
    return count
