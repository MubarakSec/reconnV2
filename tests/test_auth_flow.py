import types
from pathlib import Path

from recon_cli import config
from recon_cli.jobs.manager import JobRecord
from recon_cli.jobs.models import JobMetadata, JobPaths, JobSpec
from recon_cli.pipeline.context import PipelineContext
from recon_cli.utils import auth as auth_mod
from recon_cli.utils import fs


class DummyManager:
    def update_metadata(self, record) -> None:
        return None

    def update_spec(self, record) -> None:
        return None


class FakeCookieJar:
    def __init__(self):
        self._data = {}

    def update(self, data):
        self._data.update(data)

    def get_dict(self):
        return dict(self._data)

    def __iter__(self):
        return iter([])


class FakeResponse:
    def __init__(self, status_code=200, text="ok"):
        self.status_code = status_code
        self.text = text
        self.headers = {}


class FakeSession:
    def __init__(self, response_text="ok", cookie_name=None):
        self.headers = {}
        self.cookies = FakeCookieJar()
        self.verify = True
        self._response_text = response_text
        self._cookie_name = cookie_name

    def request(self, method, url, **kwargs):
        if self._cookie_name:
            self.cookies.update({self._cookie_name: "token"})
        return FakeResponse(status_code=200, text=self._response_text)

    def close(self):
        return None


def fake_requests(response_text="ok", cookie_name=None):
    return types.SimpleNamespace(
        Session=lambda: FakeSession(
            response_text=response_text, cookie_name=cookie_name
        ),
        packages=types.SimpleNamespace(
            urllib3=types.SimpleNamespace(disable_warnings=lambda: None)
        ),
    )


def make_record(tmp_path: Path, runtime_overrides: dict) -> JobRecord:
    root = tmp_path / "job-auth"
    (root / "artifacts").mkdir(parents=True, exist_ok=True)
    (root / "logs").mkdir(parents=True, exist_ok=True)
    paths = JobPaths(root)
    paths.results_jsonl.touch()
    paths.results_txt.touch()
    spec = JobSpec(
        job_id="job-auth",
        target="example.com",
        profile="passive",
        runtime_overrides=runtime_overrides,
    )
    metadata = JobMetadata(job_id="job-auth", queued_at="2020-01-01T00:00:00Z")
    fs.write_json(paths.spec_path, spec.to_dict())
    fs.write_json(paths.metadata_path, metadata.to_dict())
    return JobRecord(spec=spec, metadata=metadata, paths=paths)


def test_auth_manager_enabled_by_profiles(monkeypatch):
    runtime = config.RuntimeConfig().clone(
        enable_authenticated_scan=False,
        auth_profiles=[{"name": "default", "headers": {"X-Test": "1"}}],
    )
    monkeypatch.setattr(auth_mod, "requests", fake_requests())
    manager = auth_mod.build_auth_manager(runtime)
    assert manager is not None


def test_auth_login_success_with_cookie_names(monkeypatch, tmp_path: Path):
    runtime_overrides = {
        "enable_authenticated_scan": True,
        "auth_login_url": "https://example.com/login",
        "auth_login_method": "POST",
        "auth_login_payload": "user=test&pass=secret",
        "auth_login_cookie_names": "sessionid",
    }
    monkeypatch.setattr(auth_mod, "requests", fake_requests(cookie_name="sessionid"))
    record = make_record(tmp_path, runtime_overrides)
    context = PipelineContext(record=record, manager=DummyManager())

    session = context.auth_session("https://example.com/login")
    assert session is not None
    stats = record.metadata.stats.get("auth", {})
    assert stats.get("login_success") == 1


def test_auth_login_fail_regex(monkeypatch, tmp_path: Path):
    runtime_overrides = {
        "enable_authenticated_scan": True,
        "auth_login_url": "https://example.com/login",
        "auth_login_method": "POST",
        "auth_login_payload": "user=test&pass=wrong",
        "auth_login_fail_regex": "invalid",
    }
    monkeypatch.setattr(
        auth_mod, "requests", fake_requests(response_text="invalid credentials")
    )
    record = make_record(tmp_path, runtime_overrides)
    context = PipelineContext(record=record, manager=DummyManager())

    session = context.auth_session("https://example.com/login")
    assert session is not None
    stats = record.metadata.stats.get("auth", {})
    assert stats.get("login_failed") == 1


def test_parse_headers_and_cookies():
    headers = auth_mod.parse_headers("Authorization: Bearer token; X-API-Key: abc")
    cookies = auth_mod.parse_cookies("sessionid=abc; csrftoken=def")
    assert headers.get("Authorization") == "Bearer token"
    assert headers.get("X-API-Key") == "abc"
    assert cookies.get("sessionid") == "abc"
    assert cookies.get("csrftoken") == "def"
