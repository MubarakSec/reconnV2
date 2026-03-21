from __future__ import annotations

import os
import shutil
import uuid
from pathlib import Path

from recon_cli import config


def jobs_last_path() -> Path:
    return config.JOBS_ROOT / "last"


def reports_last_path() -> Path:
    return config.RECON_HOME / "reports" / "last"


def artifacts_last_trace_path() -> Path:
    return config.RECON_HOME / "artifacts" / "last-trace.json"


def artifacts_last_events_path() -> Path:
    return config.RECON_HOME / "artifacts" / "last-trace-events.jsonl"


def resolve_pointer_target(pointer_path: Path) -> Path | None:
    if not os.path.lexists(pointer_path):
        return None
    try:
        if pointer_path.is_symlink():
            return pointer_path.resolve(strict=False)
        if pointer_path.is_file():
            raw = pointer_path.read_text(encoding="utf-8").strip()
            if raw:
                return Path(raw)
    except OSError:
        return None
    return None


def update_last_job_pointer(job_path: Path) -> Path:
    return _replace_pointer(jobs_last_path(), Path(job_path))


def update_last_report_pointer(report_path: Path) -> Path:
    return _replace_pointer(reports_last_path(), Path(report_path))


def update_last_trace_pointers(
    trace_path: Path, events_path: Path | None = None
) -> None:
    trace_file = Path(trace_path)
    if trace_file.exists():
        _replace_pointer(artifacts_last_trace_path(), trace_file)
    if events_path is not None:
        events_file = Path(events_path)
        if events_file.exists():
            _replace_pointer(artifacts_last_events_path(), events_file)


def refresh_job_pointers(job_path: Path) -> None:
    job_root = Path(job_path)
    update_last_job_pointer(job_root)

    trace_path = job_root / config.ARTIFACTS_DIRNAME / "trace.json"
    events_path = job_root / config.ARTIFACTS_DIRNAME / "trace_events.jsonl"
    update_last_trace_pointers(trace_path, events_path)

    latest_report = _latest_report_for_job(job_root)
    if latest_report is not None:
        update_last_report_pointer(latest_report)


def clear_job_pointers(job_path: Path) -> None:
    job_root = Path(job_path)
    for pointer_path in (
        jobs_last_path(),
        reports_last_path(),
        artifacts_last_trace_path(),
        artifacts_last_events_path(),
    ):
        if _pointer_targets_path(pointer_path, job_root):
            _remove_path(pointer_path)


def _latest_report_for_job(job_root: Path) -> Path | None:
    candidates = [path for path in job_root.glob("report.*") if path.is_file()]
    if not candidates:
        return None
    return max(candidates, key=lambda item: (item.stat().st_mtime_ns, item.name))


def _replace_pointer(pointer_path: Path, target_path: Path) -> Path:
    if not target_path.exists():
        return pointer_path
    pointer_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = pointer_path.with_name(f".{pointer_path.name}.{uuid.uuid4().hex}.tmp")
    _remove_path(tmp_path)
    try:
        relative_target = os.path.relpath(str(target_path), str(pointer_path.parent))
        tmp_path.symlink_to(relative_target, target_is_directory=target_path.is_dir())
        tmp_path.replace(pointer_path)
    except OSError:
        _remove_path(tmp_path)
        _remove_path(pointer_path)
        if target_path.is_file():
            try:
                os.link(str(target_path), str(pointer_path))
            except OSError:
                pointer_path.write_text(
                    str(target_path.resolve()) + "\n", encoding="utf-8"
                )
        else:
            pointer_path.write_text(str(target_path.resolve()) + "\n", encoding="utf-8")
    return pointer_path


def _pointer_targets_path(pointer_path: Path, job_root: Path) -> bool:
    if not os.path.lexists(pointer_path):
        return False
    try:
        resolved = pointer_path.resolve(strict=False)
    except OSError:
        return False
    try:
        resolved.relative_to(job_root)
        return True
    except ValueError:
        return resolved == job_root


def _remove_path(path: Path) -> None:
    if path.is_symlink() or path.is_file():
        path.unlink(missing_ok=True)
        return
    if path.exists():
        shutil.rmtree(path, ignore_errors=True)
