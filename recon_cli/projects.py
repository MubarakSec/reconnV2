from __future__ import annotations

from typing import Optional

from recon_cli import config
from recon_cli.utils import fs

PROJECTS_FILE = config.DATA_DIR / "projects.json"


def list_projects() -> list[str]:
    payload = fs.read_json(PROJECTS_FILE, default={})
    if not isinstance(payload, dict):
        return []
    return sorted(payload.keys())


def get_project(name: str) -> Optional[dict]:
    payload = fs.read_json(PROJECTS_FILE, default={})
    if not isinstance(payload, dict):
        return None
    return payload.get(name)


def ensure_project(name: str, scope: Optional[list[str]] = None) -> dict:
    payload = fs.read_json(PROJECTS_FILE, default={})
    if not isinstance(payload, dict):
        payload = {}
    project = payload.get(name, {"name": name, "scope": scope or []})
    if scope is not None:
        project["scope"] = scope
    payload[name] = project
    fs.write_json(PROJECTS_FILE, payload)
    return project
