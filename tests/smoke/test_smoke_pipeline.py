import json
import os
import socket
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Iterator, Optional

import pytest


class _SmokeHandler(BaseHTTPRequestHandler):
    server_version = "SmokeServer/1.0"
    sys_version = ""

    RESPONSES = {
        "/": (200, "text/html", b"<html><body><h1>Smoke</h1></body></html>"),
        "/login": (200, "text/html", b"<html><body>login</body></html>"),
        "/api/": (
            200,
            "application/json",
            json.dumps({"users": ["alice", "bob"]}).encode(),
        ),
        "/api/users": (200, "application/json", json.dumps({"user": "alice"}).encode()),
    }

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler naming
        status, content_type, body = self.RESPONSES.get(
            self.path.rstrip("/") or "/",
            (200, "text/plain", f"unknown path {self.path}".encode()),
        )
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("X-Smoke", "true")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args, **kwargs):  # noqa: D401 - silence server logs
        return


def _free_port(preferred: int = 80) -> Optional[int]:
    try:
        if preferred:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
                try:
                    probe.bind(("127.0.0.1", preferred))
                    return preferred
                except OSError:
                    pass
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            return s.getsockname()[1]
    except PermissionError:
        return None


@pytest.fixture(scope="module")
def smoke_server() -> Iterator[Optional[int]]:
    port = _free_port(80)
    if port is None:
        yield None
        return
    if port != 80:
        yield None
        return
    ThreadingHTTPServer.allow_reuse_address = True
    server = ThreadingHTTPServer(("127.0.0.1", port), _SmokeHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        time.sleep(0.2)
        yield port
    finally:
        server.shutdown()
        thread.join(timeout=5)


@pytest.mark.smoke
def test_quick_pipeline_smoke(tmp_path: Path, smoke_server: Optional[int]):
    env = os.environ.copy()
    env["RECON_HOME"] = str(tmp_path)
    cmd = [
        os.environ.get("PYTHON_EXECUTABLE", os.sys.executable),
        "-m",
        "recon_cli.cli",
        "scan",
        "127.0.0.1",
        "--allow-ip",
        "--profile",
        "quick",
        "--inline",
    ]
    start = time.time()
    result = subprocess.run(cmd, env=env, timeout=240, capture_output=True, text=True)
    if result.returncode != 0:
        pytest.fail(
            "pipeline failed\nstdout: {}\nstderr: {}".format(
                result.stdout, result.stderr
            )
        )
    time.time() - start

    finished = tmp_path / "jobs" / "finished"
    assert finished.exists(), "finished jobs directory missing"
    job_dirs = [p for p in finished.iterdir() if p.is_dir()]
    assert job_dirs, "no finished job found"
    job_dir = max(job_dirs, key=lambda p: p.stat().st_mtime)
    results_jsonl = job_dir / "results.jsonl"
    results_txt = job_dir / "results.txt"
    assert results_jsonl.exists()
    assert results_txt.exists()

    entries = [
        json.loads(line)
        for line in results_jsonl.read_text().splitlines()
        if line.strip()
    ]
    if smoke_server == 80:
        api_entries = [
            entry
            for entry in entries
            if entry.get("type") == "url" and "/api" in entry.get("url", "")
        ]
        assert api_entries, "API endpoints were not discovered"
    else:
        assert entries, "pipeline produced no results in restricted runtime fallback"

    text_content = results_txt.read_text()
    assert "Authorization" not in text_content, "credentials leaked in report"


def test_free_port_returns_none_when_socket_creation_forbidden(
    monkeypatch: pytest.MonkeyPatch,
):
    def _deny_socket(*_args, **_kwargs):
        raise PermissionError(1, "Operation not permitted")

    monkeypatch.setattr(socket, "socket", _deny_socket)
    assert _free_port(80) is None
