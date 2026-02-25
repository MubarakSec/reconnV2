from __future__ import annotations

import pytest


pytest.importorskip("fastapi")

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient as APIClient


def _build_app() -> FastAPI:
    app = FastAPI()

    @app.get("/ping")
    async def ping() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/headers")
    async def headers(request: Request) -> dict[str, str | None]:
        return {
            "x-base": request.headers.get("x-base"),
            "x-extra": request.headers.get("x-extra"),
        }

    return app


def test_compat_testclient_can_call_basic_endpoint() -> None:
    app = _build_app()
    client = APIClient(app)
    response = client.get("/ping")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_compat_testclient_merges_default_and_request_headers() -> None:
    app = _build_app()
    with APIClient(app, headers={"x-base": "1"}) as client:
        response = client.get("/headers", headers={"x-extra": "2"})
    assert response.status_code == 200
    assert response.json() == {"x-base": "1", "x-extra": "2"}
