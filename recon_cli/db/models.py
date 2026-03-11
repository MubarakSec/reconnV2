"""SQLite Database Models for ReconnV2.

This module provides a simple SQLite-based storage for:
- Job history and metadata
- Scan results aggregation
- Host/URL discovery tracking
- Vulnerability findings
"""
from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional
from contextlib import contextmanager

from recon_cli import config


# Database path
DB_PATH = config.RECON_HOME / "data" / "recon.db"


def get_db_path() -> Path:
    """Get database path, ensuring directory exists."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    return DB_PATH


@contextmanager
def get_connection():
    """Get database connection context manager."""
    conn = sqlite3.connect(str(get_db_path()))
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    """Initialize database schema."""
    with get_connection() as conn:
        cursor = conn.cursor()
        
        # Jobs table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS jobs (
                id TEXT PRIMARY KEY,
                target TEXT,
                profile TEXT DEFAULT 'passive',
                status TEXT DEFAULT 'queued',
                stage TEXT,
                queued_at TEXT,
                started_at TEXT,
                finished_at TEXT,
                error TEXT,
                stats TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Hosts table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS hosts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                job_id TEXT NOT NULL,
                hostname TEXT NOT NULL,
                ip TEXT,
                source TEXT,
                resolved BOOLEAN DEFAULT 0,
                live BOOLEAN DEFAULT 0,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (job_id) REFERENCES jobs(id),
                UNIQUE(job_id, hostname)
            )
        """)
        
        # URLs table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS urls (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                job_id TEXT NOT NULL,
                url TEXT NOT NULL,
                hostname TEXT,
                status_code INTEGER,
                title TEXT,
                server TEXT,
                content_type TEXT,
                tls BOOLEAN DEFAULT 0,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (job_id) REFERENCES jobs(id),
                UNIQUE(job_id, url)
            )
        """)
        
        # Vulnerabilities table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                job_id TEXT NOT NULL,
                template_id TEXT,
                name TEXT,
                severity TEXT DEFAULT 'info',
                host TEXT,
                url TEXT,
                matched_at TEXT,
                description TEXT,
                reference TEXT,
                extracted TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (job_id) REFERENCES jobs(id)
            )
        """)
        
        # Secrets table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS secrets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                job_id TEXT NOT NULL,
                secret_type TEXT,
                file_path TEXT,
                url TEXT,
                line_number INTEGER,
                match TEXT,
                entropy REAL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (job_id) REFERENCES jobs(id)
            )
        """)
        
        # Create indexes
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_jobs_target ON jobs(target)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_hosts_job ON hosts(job_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_hosts_hostname ON hosts(hostname)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_urls_job ON urls(job_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_vulns_job ON vulnerabilities(job_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulnerabilities(severity)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_secrets_job ON secrets(job_id)")


@dataclass
class JobModel:
    """Job database model."""
    id: str
    target: Optional[str] = None
    profile: str = "passive"
    status: str = "queued"
    stage: Optional[str] = None
    queued_at: Optional[str] = None
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    error: Optional[str] = None
    stats: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "target": self.target,
            "profile": self.profile,
            "status": self.status,
            "stage": self.stage,
            "queued_at": self.queued_at,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "error": self.error,
            "stats": self.stats,
        }
    
    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "JobModel":
        stats = {}
        if row["stats"]:
            try:
                stats = json.loads(row["stats"])
            except json.JSONDecodeError:
                pass
        
        return cls(
            id=row["id"],
            target=row["target"],
            profile=row["profile"],
            status=row["status"],
            stage=row["stage"],
            queued_at=row["queued_at"],
            started_at=row["started_at"],
            finished_at=row["finished_at"],
            error=row["error"],
            stats=stats,
        )


@dataclass
class HostModel:
    """Host database model."""
    id: Optional[int] = None
    job_id: str = ""
    hostname: str = ""
    ip: Optional[str] = None
    source: Optional[str] = None
    resolved: bool = False
    live: bool = False


@dataclass
class URLModel:
    """URL database model."""
    id: Optional[int] = None
    job_id: str = ""
    url: str = ""
    hostname: Optional[str] = None
    status_code: Optional[int] = None
    title: Optional[str] = None
    server: Optional[str] = None
    content_type: Optional[str] = None
    tls: bool = False


@dataclass
class VulnerabilityModel:
    """Vulnerability database model."""
    id: Optional[int] = None
    job_id: str = ""
    template_id: Optional[str] = None
    name: Optional[str] = None
    severity: str = "info"
    host: Optional[str] = None
    url: Optional[str] = None
    matched_at: Optional[str] = None
    description: Optional[str] = None
    reference: Optional[str] = None
    extracted: Optional[str] = None


@dataclass
class SecretModel:
    """Secret database model."""
    id: Optional[int] = None
    job_id: str = ""
    secret_type: Optional[str] = None
    file_path: Optional[str] = None
    url: Optional[str] = None
    line_number: Optional[int] = None
    match: Optional[str] = None
    entropy: Optional[float] = None
