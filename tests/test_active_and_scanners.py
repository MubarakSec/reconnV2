import json
from pathlib import Path
from types import SimpleNamespace


from recon_cli.active import modules as active_modules
from recon_cli.scanners import integrations as scanner_integrations


class DummyResponse:
    def __init__(
        self, *, status_code=200, text="", headers=None, content=None, encoding="utf-8"
    ):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}
        self.encoding = encoding
        self._content = content

    def iter_content(self, chunk_size=8192):
        yield self._content or b""

    def close(self):
        return None


class DummySession:
    def __init__(self, response):
        self._response = response
        self.headers = {}

    def get(self, *_, **__):
        return self._response


def test_js_secret_harvest_finds_token(monkeypatch):
    body = "var key = 'AIzaSyAbCdEfGhIjKlMnOpQrStUvWxYz0123456';"
    session = DummySession(
        DummyResponse(text=body, headers={"Content-Type": "application/javascript"})
    )
    url_entries = [
        {"url": "https://ex.com/app.js", "status_code": 200, "score": 10},
    ]
    result = active_modules.run_js_secret_harvest(url_entries, session)
    assert result.payloads, "expected secret finding payloads"
    assert any("google_api" in str(hit) for hit in result.artifact_data[0]["matches"])


def test_backup_hunt_emits_findings(monkeypatch):
    payload = b"A" * (active_modules.MIN_BACKUP_BYTES + 10)
    resp = DummyResponse(
        status_code=200,
        headers={"Content-Length": str(len(payload)), "Content-Type": "text/plain"},
        content=payload,
    )
    session = DummySession(resp)
    url_entries = [{"url": "https://ex.com/index", "status_code": 200, "score": 50}]
    result = active_modules.run_backup_hunt(url_entries, session)
    assert any(p.get("source") == "active-backup" for p in result.payloads)


def test_nuclei_parses_findings(monkeypatch, tmp_path):
    finding = {
        "matched-at": "https://host",
        "templateID": "test-template",
        "host": "host",
        "info": {"severity": "high", "name": "Test"},
    }
    artifact_dir = tmp_path / "artifacts"
    artifact_dir.mkdir()
    monkeypatch.setattr(Path, "unlink", lambda self, missing_ok=True: None)

    def fake_run(cmd, **_kwargs):
        out_path = artifact_dir / "nuclei_host.json"
        out_path.write_text(json.dumps(finding) + "\n", encoding="utf-8")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    executor = SimpleNamespace(run=fake_run)
    monkeypatch.setattr(scanner_integrations.shutil, "which", lambda *_: "nuclei")
    result = scanner_integrations.run_nuclei(
        executor,
        logger=SimpleNamespace(info=lambda *a, **k: None, warning=lambda *a, **k: None),
        host="host",
        base_url="https://host",
        artifact_dir=artifact_dir,
        timeout=5,
    )
    assert result.findings
    assert result.findings[0].payload["priority"] == "high"


def test_wpscan_parses_findings(monkeypatch, tmp_path):
    artifact_dir = tmp_path / "artifacts"
    artifact_dir.mkdir()

    def fake_run(cmd, **_kwargs):
        out_idx = cmd.index("--output") + 1
        out_path = Path(cmd[out_idx])
        out_path.write_text(
            json.dumps({"vulnerabilities": [{"title": "XSS", "severity": "medium"}]}),
            encoding="utf-8",
        )
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    executor = SimpleNamespace(run=fake_run)
    monkeypatch.setattr(scanner_integrations.shutil, "which", lambda *_: "wpscan")
    parsed = scanner_integrations.run_wpscan(
        executor,
        logger=SimpleNamespace(info=lambda *a, **k: None, warning=lambda *a, **k: None),
        host="host",
        base_url="https://host",
        artifact_dir=artifact_dir,
        timeout=5,
    )
    assert parsed.findings
    assert parsed.findings[0].payload["priority"] == "medium"
