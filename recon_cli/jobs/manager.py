from __future__ import annotations

import re
import secrets
import shutil
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from recon_cli import config
from recon_cli.jobs.models import JobMetadata, JobPaths, JobSpec
from recon_cli.utils import fs, time as time_utils


@dataclass
class JobRecord:
    spec: JobSpec
    metadata: JobMetadata
    paths: JobPaths


class JobManager:
    def __init__(self, home: Path | None = None) -> None:
        self.home = home or config.RECON_HOME
        config.ensure_base_directories()

    def _sanitize_target(self, target: str) -> str:
        """Sanitize target for use in job ID (filesystem-safe)."""
        # Remove protocol
        clean = re.sub(r'^https?://', '', target)
        # Remove wildcards
        clean = clean.replace('*', '').replace('*.', '')
        # Keep only alphanumeric, dots, and hyphens
        clean = re.sub(r'[^a-zA-Z0-9.-]', '', clean)
        # Truncate to reasonable length
        clean = clean[:30] if len(clean) > 30 else clean
        # Remove leading/trailing dots and hyphens
        clean = clean.strip('.-')
        return clean or 'scan'

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
            return False
        payload = {
            "owner": owner or "worker",
            "pid": os.getpid(),
            "timestamp": time_utils.iso_now(),
        }
        lock_path.write_text(json.dumps(payload), encoding="utf-8")
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
    ) -> JobRecord:
        job_id = self.generate_job_id(target)
        root = config.QUEUED_JOBS / job_id
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
                raise FileNotFoundError(f"Targets file not found: {targets_file}") from exc
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

        prepared_overrides: Dict[str, Any] = dict(runtime_overrides or {})

        spec = JobSpec(
            job_id=job_id,
            target=target,
            profile=profile,
            project=project,
            inline=inline,
            wordlist=prepared_wordlist,
            targets_file=prepared_targets_file,
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
        )
        metadata = JobMetadata(job_id=job_id, queued_at=time_utils.iso_now())
        if project:
            try:
                from recon_cli.projects import ensure_project
                ensure_project(project)
            except Exception:
                pass
        fs.write_json(paths.spec_path, spec.to_dict())
        fs.write_json(paths.metadata_path, metadata.to_dict())
        paths.results_jsonl.touch(exist_ok=True)
        paths.results_txt.touch(exist_ok=True)
        self._apply_permissions(paths)
        return JobRecord(spec=spec, metadata=metadata, paths=paths)

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

    def list_jobs(self, status: Optional[str] = None, project: Optional[str] = None) -> List[str]:
        groups = {
            None: [config.QUEUED_JOBS, config.RUNNING_JOBS, config.FINISHED_JOBS, config.FAILED_JOBS],
            "queued": [config.QUEUED_JOBS],
            "running": [config.RUNNING_JOBS],
            "finished": [config.FINISHED_JOBS],
            "failed": [config.FAILED_JOBS],
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
                    if project:
                        spec_payload = fs.read_json(child / config.SPEC_NAME, default={})
                        if spec_payload.get("project") != project:
                            continue
                    job_ids.append(child.name)
        return sorted(job_ids)

    def move_job(self, job_id: str, destination: Path) -> Optional[Path]:
        src = self._find_job_dir(job_id)
        if not src:
            return None
        destination.mkdir(parents=True, exist_ok=True)
        target = destination / src.name
        shutil.move(str(src), str(target))
        return target

    def remove_job(self, job_id: str) -> bool:
        root = self._find_job_dir(job_id)
        if not root:
            return False
        shutil.rmtree(root, ignore_errors=True)
        return True

    def update_spec(self, record: JobRecord) -> None:
        fs.write_json(record.paths.spec_path, record.spec.to_dict())

    def update_metadata(self, record: JobRecord) -> None:
        fs.write_json(record.paths.metadata_path, record.metadata.to_dict())

    def _apply_permissions(self, paths: JobPaths) -> None:
        try:
            paths.root.chmod(0o700)
            paths.artifacts_dir.chmod(0o700)
            paths.results_jsonl.chmod(0o600)
            paths.results_txt.chmod(0o600)
        except PermissionError:
            pass

    def _find_job_dir(self, job_id: str) -> Optional[Path]:
        search_locations = [
            config.QUEUED_JOBS,
            config.RUNNING_JOBS,
            config.FINISHED_JOBS,
            config.FAILED_JOBS,
        ]
        for location in search_locations:
            candidate = location / job_id
            if candidate.exists():
                return candidate
        return None
