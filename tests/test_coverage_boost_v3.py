import asyncio
import json
import os
import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch, AsyncMock
from datetime import datetime, timedelta

from recon_cli.jobs.streaming import (
    ResultStream,
    AsyncResultStream,
    ResultWriter,
    AsyncResultWriter,
    stream_aggregate,
    stream_filter_write,
    merge_result_files,
    StreamingConfig,
)
from recon_cli.utils.auth import (
    parse_headers,
    parse_cookies,
    parse_cookie_names,
    parse_payload,
    LoginConfig,
    AuthProfile,
    build_profiles,
    AuthSessionManager,
    build_auth_manager,
)
from recon_cli.reports.generator import (
    ReportFormat,
    ReportConfig,
    ReportData,
    ReportGenerator,
    HTMLReportGenerator,
    JSONReportGenerator,
    MarkdownReportGenerator,
    CSVExporter,
    XMLExporter,
)
from recon_cli.reports.executive import (
    ExecutiveSummaryGenerator,
    RiskScore,
    RiskLevel,
    Recommendation,
)
from recon_cli.utils.alerting import (
    Alert,
    AlertRule,
    AlertSeverity,
    AlertStatus,
    AlertLevel,
    Alerter,
    ConsoleChannel,
    EmailChannel,
    SlackChannel,
    DiscordChannel,
    TelegramChannel,
    WebhookChannel,
    AlertManager,
)

# ═══════════════════════════════════════════════════════════
# 1. Tests for recon_cli/jobs/streaming.py
# ═══════════════════════════════════════════════════════════

def test_result_stream(tmp_path):
    file_path = tmp_path / "results.jsonl"
    data = [{"id": 1, "val": "a"}, {"id": 2, "val": "b"}, {"id": 3, "val": "c"}]
    with open(file_path, "w") as f:
        for item in data:
            f.write(json.dumps(item) + "\n")
        f.write("\n")  # Empty line
        f.write("invalid json\n")

    stream = ResultStream(file_path, filter_func=lambda r: r["id"] > 1)
    results = list(stream)
    
    assert len(results) == 2
    assert results[0]["id"] == 2
    assert stream.stats["total"] == 3
    assert stream.stats["filtered"] == 1
    assert stream.count() == 4 # including invalid and empty line count logic in stream.count() is simple sum(1 for line in f if line.strip())

    batches = list(stream.batched(batch_size=1))
    assert len(batches) == 2

    # Non-existent file
    empty_stream = ResultStream(tmp_path / "none.jsonl")
    assert list(empty_stream) == []
    assert empty_stream.count() == 0

@pytest.mark.asyncio
async def test_async_result_stream(tmp_path):
    file_path = tmp_path / "results.jsonl"
    data = [{"id": 1}, {"id": 2}]
    with open(file_path, "w") as f:
        for item in data:
            f.write(json.dumps(item) + "\n")

    async with AsyncResultStream(file_path, buffer_size=10) as stream:
        results = []
        async for res in stream:
            results.append(res)
    
    assert len(results) == 2
    assert results[0]["id"] == 1

    # Non-existent file
    async with AsyncResultStream(tmp_path / "none.jsonl") as stream:
        results = []
        async for res in stream:
            results.append(res)
        assert results == []

def test_result_writer(tmp_path):
    file_path = tmp_path / "out.jsonl"
    with ResultWriter(file_path, buffer_size=2) as writer:
        writer.write({"id": 1})
        assert writer.total_written == 0
        writer.write({"id": 2})
        assert writer.total_written == 2
        writer.write_many([{"id": 3}, {"id": 4}])
        assert writer.total_written == 4
    
    assert writer.total_written == 4
    with open(file_path) as f:
        lines = f.readlines()
        assert len(lines) == 4

@pytest.mark.asyncio
async def test_async_result_writer(tmp_path):
    file_path = tmp_path / "async_out.jsonl"
    async with AsyncResultWriter(file_path, buffer_size=2, flush_interval=0.1) as writer:
        await writer.write({"id": 1})
        await writer.write_many([{"id": 2}, {"id": 3}])
        # Wait for flush
        await asyncio.sleep(0.2)
    
    assert writer.total_written == 3
    with open(file_path) as f:
        assert len(f.readlines()) == 3

def test_streaming_helpers(tmp_path):
    input_path = tmp_path / "input.jsonl"
    data = [{"type": "a", "v": 10}, {"type": "b", "v": 20}, {"type": "a", "v": 5}]
    with open(input_path, "w") as f:
        for item in data:
            f.write(json.dumps(item) + "\n")

    # Aggregate
    agg = stream_aggregate(
        input_path,
        key_func=lambda r: r["type"],
        agg_func=lambda acc, r: {"sum": acc.get("sum", 0) + r["v"]}
    )
    assert agg["a"]["sum"] == 15
    assert agg["b"]["sum"] == 20

    # Filter and write
    output_path = tmp_path / "filtered.jsonl"
    count = stream_filter_write(input_path, output_path, lambda r: r["type"] == "b")
    assert count == 1

    # Merge
    merged_path = tmp_path / "merged.jsonl"
    count = merge_result_files([input_path, output_path], merged_path, dedup_key=lambda r: f"{r['type']}-{r['v']}")
    assert count == 3 # original has 3 unique, filtered has 1 that is duplicate of one in original

# ═══════════════════════════════════════════════════════════
# 2. Tests for recon_cli/utils/auth.py
# ═══════════════════════════════════════════════════════════

def test_auth_parsers():
    assert parse_headers(None) == {}
    assert parse_headers({"X-Test": "Val"}) == {"X-Test": "Val"}
    assert parse_headers([{"A": "1"}, {"B": "2"}]) == {"A": "1", "B": "2"}
    assert parse_headers('{"C": "3"}') == {"C": "3"}
    assert parse_headers("D: 4\nE: 5") == {"D": "4", "E": "5"}
    assert parse_headers("F=6;G=7") == {"F": "6", "G": "7"}

    assert parse_cookies("name=val; foo=bar") == {"name": "val", "foo": "bar"}
    assert parse_cookies({"c1": "v1"}) == {"c1": "v1"}

    assert parse_cookie_names("c1, c2") == ["c1", "c2"]
    assert parse_cookie_names(["c3"]) == ["c3"]

    assert parse_payload("a=1&b=2") == {"a": "1", "b": "2"}
    assert parse_payload('{"json": true}') == {"json": True}
    assert parse_payload(None) is None

def test_auth_profile_build():
    class Config:
        auth_profiles = [{"name": "p1", "headers": "H1: V1"}]
        enable_authenticated_scan = True

    profiles = build_profiles(Config())
    assert len(profiles) == 1
    assert profiles[0].name == "p1"

    # Legacy
    class LegacyConfig:
        auth_headers = "H2: V2"
        auth_login_url = "http://example.com/login"
        auth_login_method = "POST"

    profiles = build_profiles(LegacyConfig())
    assert len(profiles) == 1
    assert profiles[0].headers["H2"] == "V2"
    assert profiles[0].login.url == "http://example.com/login"

def test_auth_session_manager():
    profile = AuthProfile(
        name="test",
        headers={"Global": "1"},
        bearer="token123",
        basic_user="user",
        basic_pass="pass",
        login=LoginConfig(url="https://{host}/login", success_regex="OK")
    )
    
    with patch("requests.Session") as mock_session_cls:
        mock_session = mock_session_cls.return_value
        mock_session.headers = {}
        mock_session.cookies = MagicMock()
        
        manager = AuthSessionManager(profile, verify_tls=False, default_host="target.com")
        
        # Test header preparation
        headers = manager.prepare_headers({"Local": "2"})
        assert headers["Global"] == "1"
        assert headers["Local"] == "2"
        assert "Authorization" in headers

        # Test URL resolution
        assert manager._resolve_login_url("site.com") == "https://site.com/login"
        assert manager._resolve_login_url(None) == "https://target.com/login"

        # Test login
        mock_response = MagicMock()
        mock_response.text = "Login OK"
        mock_response.status_code = 200
        mock_session.request.return_value = mock_response
        
        assert manager.ensure_login("site.com") is True
        mock_session.request.assert_called()

        # Error path
        mock_session.request.side_effect = Exception("Network error")
        manager._login_cache = {}
        assert manager.ensure_login("site.com") is False

def test_build_auth_manager():
    class Config:
        enable_authenticated_scan = True
        auth_profile_name = "p1"
        auth_profiles = [{"name": "p1", "headers": "H: V"}]
    
    manager = build_auth_manager(Config())
    assert manager is not None
    assert manager.profile.name == "p1"

# ═══════════════════════════════════════════════════════════
# 3. Tests for recon_cli/reports/generator.py
# ═══════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_report_generator(tmp_path):
    job_data = {
        "id": "job1",
        "targets": ["example.com"],
        "findings": [
            {"severity": "high", "title": "Vuln 1", "host": "example.com"},
            {"severity": "low", "title": "Vuln 2", "host": "example.com"}
        ],
        "hosts": [{"ip": "1.1.1.1", "hostname": "example.com"}]
    }

    config = ReportConfig(title="Test Report", severity_filter=["high"])
    generator = ReportGenerator(config)

    # JSON Report
    json_report = await generator.generate(job_data, format=ReportFormat.JSON)
    report_dict = json.loads(json_report)
    assert report_dict["job"]["id"] == "job1"
    assert len(report_dict["findings"]) == 1 # Filtered to high

    # Markdown Report
    md_report = await generator.generate(job_data, format=ReportFormat.MARKDOWN)
    assert "# Test Report" in md_report

    # CSV Report
    csv_report = await generator.generate(job_data, format=ReportFormat.CSV)
    assert "severity,title" in csv_report

    # XML Report
    xml_report = await generator.generate(job_data, format=ReportFormat.XML)
    assert "<report>" in xml_report

    # HTML Report
    html_report = await generator.generate(job_data, format=ReportFormat.HTML)
    assert "<!DOCTYPE html>" in html_report

    # File output
    out_file = tmp_path / "report.json"
    await generator.generate(job_data, format=ReportFormat.JSON, output_path=out_file)
    assert out_file.exists()

def test_report_data_parsing():
    data = ReportData.from_job({"id": "j1", "start_time": "2023-01-01T10:00:00Z", "end_time": "2023-01-01T11:00:00Z"})
    assert data.job_id == "j1"
    assert data.duration == "1:00:00"

# ═══════════════════════════════════════════════════════════
# 4. Tests for recon_cli/reports/executive.py
# ═══════════════════════════════════════════════════════════

def test_executive_summary_generator():
    data = {
        "targets": ["target.com"],
        "findings": [
            {"type": "finding", "severity": "critical", "title": "Critical issue"},
            {"type": "finding", "severity": "high", "title": "High issue"},
            {"type": "finding", "severity": "medium", "title": "Medium issue"},
            {"type": "finding", "severity": "low", "title": "Low issue"}
        ],
        "hosts": [{"ip": "1.2.3.4"}]
    }

    gen = ExecutiveSummaryGenerator(author="Test Author")
    summary = gen.generate(data)

    assert summary.author == "Test Author"
    assert summary.critical_count == 1
    assert summary.risk_score.level in [RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]
    assert len(summary.key_findings) >= 2
    assert len(summary.recommendations) > 0

    # Output formats
    assert "EXECUTIVE SUMMARY" in summary.to_text()
    assert "<html>" in summary.to_html()
    assert summary.to_dict()["risk"]["grade"] in ["A", "B", "C", "D", "F"]

def test_risk_score_calculation():
    # Minimal
    score = RiskScore.calculate([])
    assert score.level == RiskLevel.MINIMAL
    assert score.score == 0.0

    # Critical
    score = RiskScore.calculate([{"type": "finding", "severity": "critical"}] * 10)
    assert score.level == RiskLevel.CRITICAL
    assert score.score > 8.0

def test_executive_compare():
    gen = ExecutiveSummaryGenerator()
    curr = {"findings": [{"type": "finding", "severity": "high"}] * 5}
    prev = {"findings": [{"type": "finding", "severity": "high"}] * 2}
    
    summary = gen.compare(curr, prev)
    assert summary.trend_data["trend"] == "degrading"
    assert "3 new findings" in summary.trend_data["change"]

# ═══════════════════════════════════════════════════════════
# 5. Tests for recon_cli/utils/alerting.py
# ═══════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_alerter_core():
    alerter = Alerter()
    
    # Rule
    rule = AlertRule(
        name="test-rule",
        condition=lambda ctx: ctx.get("val", 0) > 10,
        message="Val is high: {val}",
        severity=AlertSeverity.HIGH,
        cooldown_seconds=1
    )
    alerter.add_rule(rule)

    # Channel
    mock_channel = AsyncMock(spec=WebhookChannel)
    mock_channel.name = MagicMock(return_value="mock")
    mock_channel.send.return_value = True
    alerter.add_channel(mock_channel)

    # Check - Should fire
    alerts = await alerter.check({"val": 15})
    assert len(alerts) == 1
    assert alerts[0].name == "test-rule"
    mock_channel.send.assert_called_once()

    # Check - Cooldown
    alerts = await alerter.check({"val": 20})
    assert len(alerts) == 0

    # Status
    active = alerter.get_active_alerts()
    assert len(active) == 1
    assert active[0].status == AlertStatus.FIRING

    # Resolve
    alerter.resolve(active[0].id)
    assert len(alerter.get_active_alerts()) == 0
    assert alerter.get_history()[0].status == AlertStatus.RESOLVED

    # Stats
    stats = alerter.stats()
    assert stats["total_history"] == 1

@pytest.mark.asyncio
async def test_notification_channels():
    alert = Alert(name="Test", message="Msg", severity=AlertSeverity.CRITICAL)

    # Console
    with patch("builtins.print") as mock_print:
        chan = ConsoleChannel()
        await chan.send(alert)
        mock_print.assert_called()

    # Email
    with patch("smtplib.SMTP") as mock_smtp_cls:
        mock_smtp = mock_smtp_cls.return_value
        chan = EmailChannel("host", 587, "user", "pass", "from@me.com", ["to@you.com"])
        success = await chan.send(alert)
        assert success is True
        mock_smtp.login.assert_called_with("user", "pass")
        mock_smtp.sendmail.assert_called()

    # Webhook / Slack / Discord (Mocking aiohttp)
    with patch("aiohttp.ClientSession.post") as mock_post:
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_post.return_value.__aenter__.return_value = mock_resp
        
        # Slack
        chan = SlackChannel("http://slack.hook")
        await chan.send(alert)
        mock_post.assert_called()

        # Webhook
        chan = WebhookChannel("http://web.hook")
        await chan.send(alert)

@pytest.mark.asyncio
async def test_alert_manager():
    manager = AlertManager(rate_limit_per_minute=2, dedupe_window_seconds=1)
    mock_chan = AsyncMock()
    mock_chan.send.return_value = True
    manager.add_channel("mock", mock_chan)

    alert = Alert(title="T1", message="M1", level=AlertLevel.ERROR)

    # Send 1
    res = await manager.send_alert(alert)
    assert res["mock"] is True

    # Duplicate
    res = await manager.send_alert(alert)
    assert res == {}

    # Rate limit
    await asyncio.sleep(1.1) # wait for dedupe window
    alert2 = Alert(title="T2", message="M2", level=AlertLevel.ERROR)
    await manager.send_alert(alert2) # Send 2
    
    alert3 = Alert(title="T3", message="M3", level=AlertLevel.ERROR)
    res = await manager.send_alert(alert3) # Send 3 - should be rate limited
    assert res == {}

@pytest.mark.asyncio
async def test_alert_manager_send_test():
    manager = AlertManager()
    
    with patch("aiohttp.ClientSession.post") as mock_post:
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_post.return_value.__aenter__.return_value = mock_resp
        
        # Test telegram
        success = await manager.send_test("telegram", {"bot_token": "abc", "chat_id": "123"})
        assert success is True

        # Test slack
        success = await manager.send_test("slack", {"webhook_url": "http://slack"})
        assert success is True
