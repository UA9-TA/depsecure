import json
import sqlite3
import time
from pathlib import Path
from typing import Optional


class OSVCache:
    def __init__(self, db_path: Optional[Path] = None):
        if db_path is None:
            self.db_path = Path.home() / ".depsecure" / "vuln_cache.db"
        else:
            self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()
        self.ttl = 86400

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """CREATE TABLE IF NOT EXISTS vuln_cache (package TEXT, version TEXT, ecosystem TEXT, response_json TEXT, cached_at INTEGER, PRIMARY KEY (package, version, ecosystem))"""
            )
            conn.commit()

    def get(self, package: str, version: str, ecosystem: str) -> Optional[dict]:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT response_json, cached_at FROM vuln_cache WHERE package = ? AND version = ? AND ecosystem = ?",
                (package, version, ecosystem),
            )
            row = cursor.fetchone()
            if row:
                response_json, cached_at = row
                if time.time() - cached_at < self.ttl:
                    return json.loads(response_json)
                else:
                    self.delete(package, version, ecosystem)
        return None

    def set(self, package: str, version: str, ecosystem: str, response: dict):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT OR REPLACE INTO vuln_cache (package, version, ecosystem, response_json, cached_at) VALUES (?, ?, ?, ?, ?)",
                (package, version, ecosystem, json.dumps(response), int(time.time())),
            )
            conn.commit()

    def delete(self, package: str, version: str, ecosystem: str):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "DELETE FROM vuln_cache WHERE package = ? AND version = ? AND ecosystem = ?",
                (package, version, ecosystem),
            )
            conn.commit()

    def clear(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM vuln_cache")
            conn.commit()
