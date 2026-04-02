from __future__ import annotations

import re
import threading
import secrets
import shutil
import json
import os
import errno
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from recon_cli import config
from recon_cli.jobs.models import JobMetadata, JobPaths, JobSpec
from recon_cli.utils import fs, time as time_utils
from recon_cli.utils.last_run import clear_job_pointers, refresh_job_pointers

logger = logging.getLogger(__name__)


@dataclass
class JobRecord:
    spec: JobSpec
    metadata: JobMetadata
    paths: JobPaths


class JobManager:
    _record_locks: Dict[str, threading.Lock] = {}
    _record_locks_guard = threading.Lock()

    @classmethod
    def _lock_for(cls, job_id: str) -> threading.Lock:
        if not job_id:
            job_id = "unknown"
        with cls._record_locks_guard:
            lock = cls._record_locks.get(job_id)
            if lock is None:
                lock = threading.Lock()
                cls._record_locks[job_id] = lock
            return lock

    @staticmethod
    def is_safe_job_id(job_id: str) -> bool:
        if not job_id:
            return False
        if any(sep in job_id for sep in ("/", "\\", "\x00")):
            return False
        if job_id in {".", ".."}:
            return False
        if len(Path(job_id).parts) != 1:
            return False
        return re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", job_id) is not None

    def __init__(self, home: Path | None = None) -> None:
        self.home = home or config.RECON_HOME
        self.jobs_root = self.home / "jobs"
        self.queued_dir = self.jobs_root / "queued"
        self.running_dir = self.jobs_root / "running"
        self.finished_dir = self.jobs_root / "finished"
        self.failed_dir = self.jobs_root / "failed"

        # Ensure directories exist
        for d in [
            self.queued_dir,
            self.running_dir,
            self.finished_dir,
            self.failed_dir,
        ]:
            d.mkdir(parents=True, exist_ok=True)

    def _sanitize_target(self, target: str) -> str:
        """Sanitize target for use in job ID (filesystem-safe)."""
        # Remove protocol
        clean = re.sub(r"^https?://", "", target)
        # Remove wildcards
        clean = clean.replace("*", "").replace("*.", "")
        # Keep only alphanumeric, dots, and hyphens
        clean = re.sub(r"[^a-zA-Z0-9.-]", "", clean)
        # Truncate to reasonable length
        clean = clean[:30] if len(clean) > 30 else clean
        # Remove leading/trailing dots and hyphens
        clean = clean.strip(".-")
        return clean or "scan"

    def generate_job_id(self, target: str = "") -> str:
        """Generate meaningful job ID: target_YYYYMMDD_HHMMSS_suffix."""
        ts = time_utils.utc_now().strftime("%Y%m%d_%H%M%S")
        suffix = secrets.token_hex(2)

        if target:
            sanitized = self._sanitize_target(target)
            return f"{sanitized}_{ts}_{suffix}"
        return f"scan_{ts}_{suffix}"

    def _lock_path(self, root: Path) -> Path:
        return root / ".lock"

    def acquire_lock(self, job_id: str, owner: Optional[str] = None) -> bool:
        root = self._find_job_dir(job_id)
        if not root:
            return False
        lock_path = self._lock_path(root)
        if lock_path.exists():
            try:
                payload = json.loads(lock_path.read_text(encoding="utf-8"))
            except Exception:
                payload = {}
            pid = payload.get("pid")
            stale_lock = False
            if isinstance(pid, int) and pid > 0:
                try:
                    os.kill(pid, 0)
                except ProcessLookupError:
                    stale_lock = True
                except PermissionError:
                    stale_lock = False
                except OSError:
                    stale_lock = False
            if stale_lock:
                try:
                    lock_path.unlink()
                except FileNotFoundError:
                    pass
            else:
                return False
        payload = {
            "owner": owner or "worker",
            "pid": os.getpid(),
            "timestamp": time_utils.iso_now(),
        }
        try:
            fd = os.open(str(lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except OSError as exc:
            if exc.errno == errno.EEXIST:
                return False
            raise
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(json.dumps(payload))
        except Exception:
            try:
                lock_path.unlink()
            except FileNotFoundError:
                pass
            raise
        return True

    def release_lock(self, job_id: str) -> None:
        root = self._find_job_dir(job_id)
        if not root:
            return
        lock_path = self._lock_path(root)
        try:
            lock_path.unlink()
        except FileNotFoundError:
            pass

    def create_job(
        self,
        target: str,
        profile: str,
        project: Optional[str] = None,
        inline: bool = False,
        wordlist: Optional[str] = None,
        targets_file: Optional[str] = None,
        max_screenshots: Optional[int] = None,
        force: bool = False,
        allow_ip: bool = False,
        initiator: Optional[str] = None,
        active_modules: Optional[List[str]] = None,
        scanners: Optional[List[str]] = None,
        execution_profile: Optional[str] = None,
        runtime_overrides: Optional[Dict[str, Any]] = None,
        insecure: bool = False,
        incremental_from: Optional[str] = None,
        scope_file: Optional[str] = None,
        mode: str = "default",
    ) -> JobRecord:
        job_id = self.generate_job_id(target)
        root = self.queued_dir / job_id
        paths = JobPaths(root)
        paths.root.mkdir(parents=True, exist_ok=True)
        paths.artifacts_dir.mkdir(parents=True, exist_ok=True)
        paths.logs_dir.mkdir(parents=True, exist_ok=True)

        inputs_dir = paths.root / "inputs"
        prepared_wordlist = wordlist
        prepared_targets_file = targets_file
        if targets_file:
            source = Path(targets_file).expanduser()
            try:
                source = source.resolve(strict=True)
            except FileNotFoundError as exc:
                raise FileNotFoundError(
                    f"Targets file not found: {targets_file}"
                ) from exc
            inputs_dir.mkdir(parents=True, exist_ok=True)
            dest = inputs_dir / source.name
            try:
                dest_resolved = dest.resolve()
            except FileNotFoundError:
                dest_resolved = dest.absolute()
            if source != dest_resolved:
                try:
                    shutil.copy2(source, dest)
                except shutil.SameFileError:
                    pass
            prepared_targets_file = str(dest)
        if wordlist:
            source = Path(wordlist).expanduser()
            try:
                source = source.resolve(strict=True)
            except FileNotFoundError as exc:
                raise FileNotFoundError(f"Wordlist not found: {wordlist}") from exc
            inputs_dir.mkdir(parents=True, exist_ok=True)
            dest = inputs_dir / source.name
            try:
                dest_resolved = dest.resolve()
            except FileNotFoundError:
                dest_resolved = dest.absolute()
            if source != dest_resolved:
                try:
                    shutil.copy2(source, dest)
                except shutil.SameFileError:
                    pass
            prepared_wordlist = str(dest)

        prepared_scope_file = scope_file
        if scope_file:
            source = Path(scope_file).expanduser()
            try:
                source = source.resolve(strict=True)
            except FileNotFoundError as exc:
                raise FileNotFoundError(f"Scope file not found: {scope_file}") from exc
            inputs_dir.mkdir(parents=True, exist_ok=True)
            dest = inputs_dir / source.name
            try:
                dest_resolved = dest.resolve()
            except FileNotFoundError:
                dest_resolved = dest.absolute()
            if source != dest_resolved:
                try:
                    shutil.copy2(source, dest)
                except shutil.SameFileError:
                    pass
            prepared_scope_file = str(dest)

        prepared_overrides: Dict[str, Any] = dict(runtime_overrides or {})

        spec = JobSpec(
            job_id=job_id,
            target=target,
            profile=profile,
            project=project,
            inline=inline,
            wordlist=prepared_wordlist,
            targets_file=prepared_targets_file,
            scope_file=prepared_scope_file,
            max_screenshots=max_screenshots,
            force=force,
            allow_ip=allow_ip,
            initiator=initiator,
            active_modules=active_modules or [],
            scanners=scanners or [],
            execution_profile=execution_profile,
            runtime_overrides=prepared_overrides,
            insecure=insecure,
            incremental_from=incremental_from,
            mode=mode,
        )
        metadata = JobMetadata(job_id=job_id, queued_at=time_utils.iso_now())
        if project:
            try:
                from recon_cli.projects import ensure_project

                ensure_project(project)
            except Exception:
                logger.debug("Failed to ensure project %s", project, exc_info=True)
        fs.write_json(paths.spec_path, spec.to_dict())
        fs.write_json(paths.metadata_path, metadata.to_dict())
        paths.results_jsonl.touch(exist_ok=True)
        paths.results_txt.touch(exist_ok=True)
        self._apply_permissions(paths)
        record = JobRecord(spec=spec, metadata=metadata, paths=paths)
        refresh_job_pointers(paths.root)
        return record

    def load_job(self, job_id: str) -> Optional[JobRecord]:
        root = self._find_job_dir(job_id)
        if not root:
            return None
        paths = JobPaths(root)
        spec_payload = fs.read_json(paths.spec_path, default=None)
        metadata_payload = fs.read_json(paths.metadata_path, default=None)
        if not spec_payload or not metadata_payload:
            return None
        spec = JobSpec.from_dict(spec_payload)
        metadata = JobMetadata.from_dict(metadata_payload)
        return JobRecord(spec=spec, metadata=metadata, paths=paths)

    def list_jobs(
        self, status: Optional[str] = None, project: Optional[str] = None
    ) -> List[str]:
        groups = {
            None: [
                self.queued_dir,
                self.running_dir,
                self.finished_dir,
                self.failed_dir,
            ],
            "queued": [self.queued_dir],
            "running": [self.running_dir],
            "finished": [self.finished_dir],
            "partial": [self.finished_dir], # Partial live in finished_dir
            "failed": [self.failed_dir],
        }
        dirs = groups.get(status)
        if dirs is None:
            dirs = groups[None]
        job_ids: List[str] = []
        for directory in dirs:
            if not directory.exists():
                continue
            for child in directory.iterdir():
                if child.is_dir():
                    metadata_payload = fs.read_json(
                        child / config.METADATA_NAME, default={}
                    )
                    
                    # 1. Filter by project
                    if project:
                        spec_payload = fs.read_json(
                            child / config.SPEC_NAME, default={}
                        )
                        if spec_payload.get("project") != project:
                            continue
                    
                    # 2. Filter by status if requested
                    # Since "finished" and "partial" both live in finished_dir,
                    # we need to check metadata to distinguish them if status is provided.
                    if status in {"finished", "partial", "failed", "running", "queued"}:
                        if metadata_payload.get("status") != status:
                            continue
                            
                    job_ids.append(child.name)
        return sorted(job_ids)

    def get_job_counts(self) -> Dict[str, int]:
        """الحصول على أعداد المهام حسب الحالة"""
        return {
            "queued": len(self.list_jobs("queued")),
            "running": len(self.list_jobs("running")),
            "finished": len(self.list_jobs("finished")),
            "failed": len(self.list_jobs("failed")),
        }

    def move_job(self, job_id: str, destination: Path) -> Optional[Path]:
        src = self._find_job_dir(job_id)
        if not src:
            return None
        destination.mkdir(parents=True, exist_ok=True)
        target = destination / src.name
        shutil.move(str(src), str(target))
        refresh_job_pointers(target)
        return target

    def remove_job(self, job_id: str) -> bool:
        root = self._find_job_dir(job_id)
        if not root:
            return False
        clear_job_pointers(root)
        shutil.rmtree(root, ignore_errors=True)
        return True

    def update_spec(self, record: JobRecord) -> None:
        lock = self._lock_for(record.spec.job_id)
        with lock:
            fs.write_json(record.paths.spec_path, record.spec.to_dict())

    def update_metadata(self, record: JobRecord) -> None:
        job_id = record.metadata.job_id or record.spec.job_id
        lock = self._lock_for(job_id)
        with lock:
            metadata_dict = record.metadata.to_dict()
            fs.write_json(record.paths.metadata_path, metadata_dict)
            
            # Sync state to SQLite backend for True Fault Tolerance
            try:
                from recon_cli.db.storage import sync_job_to_db
                job_data = {
                    "target": getattr(record.spec, "target", ""),
                    "profile": getattr(record.spec, "profile", "passive"),
                    **metadata_dict
                }
                sync_job_to_db(job_id, job_data)
            except Exception as e:
                logger.debug("Failed to sync job state to SQLite DB: %s", e)

    def _apply_permissions(self, paths: JobPaths) -> None:
        try:
            paths.root.chmod(0o700)
            paths.artifacts_dir.chmod(0o700)
            paths.results_jsonl.chmod(0o600)
            paths.results_txt.chmod(0o600)
        except PermissionError:
            pass

    def _find_job_dir(self, job_id: str) -> Optional[Path]:
        if not self.is_safe_job_id(job_id):
            return None
        search_locations = [
            self.queued_dir,
            self.running_dir,
            self.finished_dir,
            self.failed_dir,
        ]
        for location in search_locations:
            location_resolved = location.resolve()
            candidate = (location / job_id).resolve()
            if location_resolved not in candidate.parents:
                continue
            if candidate.exists():
                return candidate
        return None
