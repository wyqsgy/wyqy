"""
Session Management - sqlmap-style persistent session with SQLite
Tracks scan progress, resumes interrupted scans, caches results.
"""
import json
import sqlite3
import time
import hashlib
from pathlib import Path
from typing import Optional, Any
from datetime import datetime
from app.utils.logger import get_logger

logger = get_logger("session")

SESSION_DIR = Path(__file__).parent.parent.parent / "data" / "sessions"


class ScanSession:
    def __init__(self, task_id: str):
        SESSION_DIR.mkdir(parents=True, exist_ok=True)
        self.task_id = task_id
        self.db_path = SESSION_DIR / f"{task_id}.db"
        self._conn: Optional[sqlite3.Connection] = None
        self._init_db()

    def _init_db(self):
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS meta (
                key TEXT PRIMARY KEY,
                value TEXT
            );
            CREATE TABLE IF NOT EXISTS completed_modules (
                module_name TEXT PRIMARY KEY,
                result_count INTEGER DEFAULT 0,
                finished_at TEXT,
                duration REAL
            );
            CREATE TABLE IF NOT EXISTS vuln_cache (
                vuln_id TEXT PRIMARY KEY,
                module TEXT,
                risk_level TEXT,
                target_url TEXT,
                data TEXT,
                created_at TEXT
            );
            CREATE TABLE IF NOT EXISTS request_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT,
                method TEXT,
                status_code INTEGER,
                elapsed REAL,
                payload TEXT,
                timestamp TEXT
            );
            CREATE TABLE IF NOT EXISTS fingerprint_cache (
                target TEXT PRIMARY KEY,
                fingerprint_data TEXT,
                detected_at TEXT,
                ttl INTEGER DEFAULT 86400
            );
        """)
        self._conn.commit()

    def set_meta(self, key: str, value: Any):
        self._conn.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)",
            (key, json.dumps(value))
        )
        self._conn.commit()

    def get_meta(self, key: str, default: Any = None) -> Any:
        row = self._conn.execute(
            "SELECT value FROM meta WHERE key = ?", (key,)
        ).fetchone()
        if row:
            return json.loads(row[0])
        return default

    def mark_module_complete(self, module_name: str, result_count: int = 0, duration: float = 0):
        self._conn.execute(
            "INSERT OR REPLACE INTO completed_modules (module_name, result_count, finished_at, duration) VALUES (?, ?, ?, ?)",
            (module_name, result_count, datetime.utcnow().isoformat(), duration)
        )
        self._conn.commit()

    def is_module_complete(self, module_name: str) -> bool:
        row = self._conn.execute(
            "SELECT 1 FROM completed_modules WHERE module_name = ?", (module_name,)
        ).fetchone()
        return row is not None

    def get_completed_modules(self) -> list[str]:
        rows = self._conn.execute(
            "SELECT module_name FROM completed_modules"
        ).fetchall()
        return [r[0] for r in rows]

    def cache_vuln(self, vuln_id: str, module: str, risk_level: str, target_url: str, data: dict):
        self._conn.execute(
            "INSERT OR REPLACE INTO vuln_cache (vuln_id, module, risk_level, target_url, data, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (vuln_id, module, risk_level, target_url, json.dumps(data), datetime.utcnow().isoformat())
        )
        self._conn.commit()

    def get_cached_vulns(self) -> list[dict]:
        rows = self._conn.execute(
            "SELECT vuln_id, module, risk_level, target_url, data FROM vuln_cache"
        ).fetchall()
        return [
            {"vuln_id": r[0], "module": r[1], "risk_level": r[2], "target_url": r[3], **json.loads(r[4])}
            for r in rows
        ]

    def log_request(self, url: str, method: str, status_code: int, elapsed: float, payload: str = ""):
        self._conn.execute(
            "INSERT INTO request_log (url, method, status_code, elapsed, payload, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
            (url, method, status_code, elapsed, payload, datetime.utcnow().isoformat())
        )
        self._conn.commit()

    def get_request_stats(self) -> dict:
        total = self._conn.execute("SELECT COUNT(*) FROM request_log").fetchone()[0]
        avg_elapsed = self._conn.execute("SELECT AVG(elapsed) FROM request_log").fetchone()[0] or 0
        status_dist = {}
        for row in self._conn.execute("SELECT status_code, COUNT(*) FROM request_log GROUP BY status_code"):
            status_dist[str(row[0])] = row[1]
        return {"total_requests": total, "avg_elapsed": avg_elapsed, "status_distribution": status_dist}

    def cache_fingerprint(self, target: str, data: dict, ttl: int = 86400):
        self._conn.execute(
            "INSERT OR REPLACE INTO fingerprint_cache (target, fingerprint_data, detected_at, ttl) VALUES (?, ?, ?, ?)",
            (target, json.dumps(data), datetime.utcnow().isoformat(), ttl)
        )
        self._conn.commit()

    def get_cached_fingerprint(self, target: str) -> Optional[dict]:
        row = self._conn.execute(
            "SELECT fingerprint_data, detected_at, ttl FROM fingerprint_cache WHERE target = ?", (target,)
        ).fetchone()
        if row:
            detected_at = datetime.fromisoformat(row[1])
            if (datetime.utcnow() - detected_at).total_seconds() < row[2]:
                return json.loads(row[0])
        return None

    def get_progress(self) -> dict:
        completed = len(self.get_completed_modules())
        total = self.get_meta("total_modules", 0)
        vulns = len(self.get_cached_vulns())
        stats = self.get_request_stats()
        return {
            "completed_modules": completed,
            "total_modules": total,
            "progress_pct": int(completed / max(total, 1) * 100),
            "vulns_found": vulns,
            **stats,
        }

    def close(self):
        if self._conn:
            self._conn.close()

    def delete(self):
        self.close()
        if self.db_path.exists():
            self.db_path.unlink()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


_session_cache: dict[str, ScanSession] = {}


def get_session(task_id: str) -> ScanSession:
    if task_id not in _session_cache:
        _session_cache[task_id] = ScanSession(task_id)
    return _session_cache[task_id]


def close_session(task_id: str):
    if task_id in _session_cache:
        _session_cache[task_id].close()
        del _session_cache[task_id]
