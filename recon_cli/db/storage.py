"""Storage operations for ReconnV2 database.

CRUD operations for jobs, hosts, URLs, vulnerabilities, and secrets.
"""
from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Dict, List, Optional

from recon_cli.db.models import (
    get_connection,
    init_db,
    JobModel,
    HostModel,
    URLModel,
    VulnerabilityModel,
    SecretModel,
)


class JobStorage:
    """Storage operations for jobs."""
    
    def __init__(self):
        init_db()
    
    def create(self, job: JobModel) -> JobModel:
        """Create a new job."""
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO jobs (id, target, profile, status, stage, queued_at, stats)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                job.id,
                job.target,
                job.profile,
                job.status,
                job.stage,
                job.queued_at or datetime.utcnow().isoformat(),
                json.dumps(job.stats),
            ))
        return job
    
    def get(self, job_id: str) -> Optional[JobModel]:
        """Get a job by ID."""
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM jobs WHERE id = ?", (job_id,))
            row = cursor.fetchone()
            if row:
                return JobModel.from_row(row)
        return None
    
    def update(self, job: JobModel) -> JobModel:
        """Update a job."""
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE jobs SET
                    target = ?,
                    profile = ?,
                    status = ?,
                    stage = ?,
                    started_at = ?,
                    finished_at = ?,
                    error = ?,
                    stats = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            """, (
                job.target,
                job.profile,
                job.status,
                job.stage,
                job.started_at,
                job.finished_at,
                job.error,
                json.dumps(job.stats),
                job.id,
            ))
        return job
    
    def delete(self, job_id: str) -> bool:
        """Delete a job and all related data."""
        with get_connection() as conn:
            cursor = conn.cursor()
            # Delete related data first
            cursor.execute("DELETE FROM hosts WHERE job_id = ?", (job_id,))
            cursor.execute("DELETE FROM urls WHERE job_id = ?", (job_id,))
            cursor.execute("DELETE FROM vulnerabilities WHERE job_id = ?", (job_id,))
            cursor.execute("DELETE FROM secrets WHERE job_id = ?", (job_id,))
            # Delete job
            cursor.execute("DELETE FROM jobs WHERE id = ?", (job_id,))
            return cursor.rowcount > 0
    
    def list_all(self, status: Optional[str] = None, limit: int = 100) -> List[JobModel]:
        """List jobs, optionally filtered by status."""
        with get_connection() as conn:
            cursor = conn.cursor()
            if status:
                cursor.execute(
                    "SELECT * FROM jobs WHERE status = ? ORDER BY created_at DESC LIMIT ?",
                    (status, limit)
                )
            else:
                cursor.execute(
                    "SELECT * FROM jobs ORDER BY created_at DESC LIMIT ?",
                    (limit,)
                )
            return [JobModel.from_row(row) for row in cursor.fetchall()]
    
    def get_stats(self) -> Dict[str, int]:
        """Get job counts by status."""
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT status, COUNT(*) as count
                FROM jobs
                GROUP BY status
            """)
            return {row["status"]: row["count"] for row in cursor.fetchall()}
    
    def search(self, query: str, limit: int = 50) -> List[JobModel]:
        """Search jobs by target."""
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM jobs WHERE target LIKE ? ORDER BY created_at DESC LIMIT ?",
                (f"%{query}%", limit)
            )
            return [JobModel.from_row(row) for row in cursor.fetchall()]


class HostStorage:
    """Storage operations for hosts."""
    
    def __init__(self):
        init_db()
    
    def add(self, host: HostModel) -> HostModel:
        """Add a host."""
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR IGNORE INTO hosts (job_id, hostname, ip, source, resolved, live)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                host.job_id,
                host.hostname,
                host.ip,
                host.source,
                host.resolved,
                host.live,
            ))
            host.id = cursor.lastrowid
        return host
    
    def bulk_add(self, hosts: List[HostModel]) -> int:
        """Add multiple hosts."""
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.executemany("""
                INSERT OR IGNORE INTO hosts (job_id, hostname, ip, source, resolved, live)
                VALUES (?, ?, ?, ?, ?, ?)
            """, [(h.job_id, h.hostname, h.ip, h.source, h.resolved, h.live) for h in hosts])
            return cursor.rowcount
    
    def get_by_job(self, job_id: str, limit: int = 1000) -> List[HostModel]:
        """Get hosts for a job."""
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM hosts WHERE job_id = ? LIMIT ?",
                (job_id, limit)
            )
            return [HostModel(
                id=row["id"],
                job_id=row["job_id"],
                hostname=row["hostname"],
                ip=row["ip"],
                source=row["source"],
                resolved=bool(row["resolved"]),
                live=bool(row["live"]),
            ) for row in cursor.fetchall()]
    
    def count_by_job(self, job_id: str) -> int:
        """Count hosts for a job."""
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM hosts WHERE job_id = ?", (job_id,))
            return cursor.fetchone()[0]


class URLStorage:
    """Storage operations for URLs."""
    
    def __init__(self):
        init_db()
    
    def add(self, url: URLModel) -> URLModel:
        """Add a URL."""
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR IGNORE INTO urls 
                (job_id, url, hostname, status_code, title, server, content_type, tls)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                url.job_id,
                url.url,
                url.hostname,
                url.status_code,
                url.title,
                url.server,
                url.content_type,
                url.tls,
            ))
            url.id = cursor.lastrowid
        return url
    
    def bulk_add(self, urls: List[URLModel]) -> int:
        """Add multiple URLs."""
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.executemany("""
                INSERT OR IGNORE INTO urls 
                (job_id, url, hostname, status_code, title, server, content_type, tls)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, [(u.job_id, u.url, u.hostname, u.status_code, u.title, u.server, u.content_type, u.tls) for u in urls])
            return cursor.rowcount
    
    def get_by_job(self, job_id: str, limit: int = 1000) -> List[URLModel]:
        """Get URLs for a job."""
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM urls WHERE job_id = ? LIMIT ?",
                (job_id, limit)
            )
            return [URLModel(
                id=row["id"],
                job_id=row["job_id"],
                url=row["url"],
                hostname=row["hostname"],
                status_code=row["status_code"],
                title=row["title"],
                server=row["server"],
                content_type=row["content_type"],
                tls=bool(row["tls"]),
            ) for row in cursor.fetchall()]


class VulnerabilityStorage:
    """Storage operations for vulnerabilities."""
    
    def __init__(self):
        init_db()
    
    def add(self, vuln: VulnerabilityModel) -> VulnerabilityModel:
        """Add a vulnerability."""
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO vulnerabilities 
                (job_id, template_id, name, severity, host, url, matched_at, description, reference, extracted)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                vuln.job_id,
                vuln.template_id,
                vuln.name,
                vuln.severity,
                vuln.host,
                vuln.url,
                vuln.matched_at,
                vuln.description,
                vuln.reference,
                vuln.extracted,
            ))
            vuln.id = cursor.lastrowid
        return vuln
    
    def get_by_job(self, job_id: str) -> List[VulnerabilityModel]:
        """Get vulnerabilities for a job."""
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM vulnerabilities WHERE job_id = ? ORDER BY severity",
                (job_id,)
            )
            return [VulnerabilityModel(
                id=row["id"],
                job_id=row["job_id"],
                template_id=row["template_id"],
                name=row["name"],
                severity=row["severity"],
                host=row["host"],
                url=row["url"],
                matched_at=row["matched_at"],
                description=row["description"],
                reference=row["reference"],
                extracted=row["extracted"],
            ) for row in cursor.fetchall()]
    
    def get_by_severity(self, severity: str, limit: int = 100) -> List[VulnerabilityModel]:
        """Get vulnerabilities by severity."""
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM vulnerabilities WHERE severity = ? ORDER BY created_at DESC LIMIT ?",
                (severity, limit)
            )
            return [VulnerabilityModel(
                id=row["id"],
                job_id=row["job_id"],
                template_id=row["template_id"],
                name=row["name"],
                severity=row["severity"],
                host=row["host"],
                url=row["url"],
            ) for row in cursor.fetchall()]
    
    def count_by_severity(self) -> Dict[str, int]:
        """Count vulnerabilities by severity."""
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT severity, COUNT(*) as count
                FROM vulnerabilities
                GROUP BY severity
            """)
            return {row["severity"]: row["count"] for row in cursor.fetchall()}


class SecretStorage:
    """Storage operations for secrets."""
    
    def __init__(self):
        init_db()
    
    def add(self, secret: SecretModel) -> SecretModel:
        """Add a secret."""
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO secrets 
                (job_id, secret_type, file_path, url, line_number, match, entropy)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                secret.job_id,
                secret.secret_type,
                secret.file_path,
                secret.url,
                secret.line_number,
                secret.match,
                secret.entropy,
            ))
            secret.id = cursor.lastrowid
        return secret
    
    def get_by_job(self, job_id: str) -> List[SecretModel]:
        """Get secrets for a job."""
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM secrets WHERE job_id = ?",
                (job_id,)
            )
            return [SecretModel(
                id=row["id"],
                job_id=row["job_id"],
                secret_type=row["secret_type"],
                file_path=row["file_path"],
                url=row["url"],
                line_number=row["line_number"],
                match=row["match"],
                entropy=row["entropy"],
            ) for row in cursor.fetchall()]


# Convenience functions
def sync_job_to_db(job_id: str, job_data: Dict[str, Any]) -> None:
    """Sync a job from filesystem to database."""
    storage = JobStorage()
    existing = storage.get(job_id)
    
    job = JobModel(
        id=job_id,
        target=job_data.get("target"),
        profile=job_data.get("profile", "passive"),
        status=job_data.get("status", "queued"),
        stage=job_data.get("stage"),
        queued_at=job_data.get("queued_at"),
        started_at=job_data.get("started_at"),
        finished_at=job_data.get("finished_at"),
        error=job_data.get("error"),
        stats=job_data.get("stats", {}),
    )
    
    if existing:
        storage.update(job)
    else:
        storage.create(job)


def get_dashboard_stats() -> Dict[str, Any]:
    """Get comprehensive dashboard statistics."""
    job_storage = JobStorage()
    vuln_storage = VulnerabilityStorage()
    
    return {
        "jobs": job_storage.get_stats(),
        "vulnerabilities": vuln_storage.count_by_severity(),
    }
