from __future__ import annotations

from pathlib import Path
import tomllib

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient

from recon_cli.api.app import app


def test_pyproject_requires_python_has_upper_bound():
    data = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    requires_python = data["project"]["requires-python"]
    assert "<3.13" in requires_python


def test_api_version_reports_python_requirement_upper_bound():
    client = TestClient(app)
    response = client.get("/api/version")
    assert response.status_code == 200
    payload = response.json()
    assert payload.get("python_required") == ">=3.10,<3.13"
