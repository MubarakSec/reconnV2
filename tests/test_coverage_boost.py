import asyncio
import json
import logging
import os
import socket
import shutil
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch, AsyncMock, mock_open

import pytest
import yaml
from recon_cli.utils.async_dns import (
    DNSRecord, DNSResult, DNSCache, AsyncDNSResolver,
    bulk_resolve, filter_resolvable, run_bulk_resolve
)
from recon_cli.utils.config_migrate import (
    ConfigMigrator, migrate_config, MIGRATIONS, MigrationRule
)
from recon_cli.utils.structured_logging import (
    StructuredFormatter, PrettyFormatter, ContextLogger,
    setup_logging, get_logger, set_trace_id, get_trace_id,
    set_job_context, clear_context, LogContext,
    log_stage_start, log_stage_end, log_tool_execution, log_finding
)
from recon_cli.utils.telegram_bot import TelegramBot
from recon_cli.utils.error_recovery import (
    ErrorSeverity, RecoveryAction, ErrorContext, RecoveryStrategy,
    PartialResultSaver, GracefulDegradation, RecoveryContext,
    error_recovery_context, with_recovery, graceful_stage,
    ErrorReportGenerator, GlobalRecoveryHandler, get_recovery_handler
)

# ═══════════════════════════════════════════════════════════
# 1. Async DNS Tests
# ═══════════════════════════════════════════════════════════

def test_dns_models():
    record = DNSRecord(domain="example.com", record_type="A", value="1.2.3.4", ttl=0)
    assert record.is_expired
    
    result = DNSResult(domain="example.com", records=[record])
    assert result.has_records
    assert "1.2.3.4" in result.a_records
    assert result.to_dict()["domain"] == "example.com"

def test_dns_cache():
    cache = DNSCache(default_ttl=1)
    record = DNSRecord(domain="example.com", record_type="A", value="1.2.3.4", ttl=300)
    cache.set(record)
    assert cache.get("example.com") == record
    assert cache.stats["hits"] == 1
    
    expired_record = DNSRecord(domain="old.com", record_type="A", value="1.1.1.1", ttl=-1)
    cache.set(expired_record)
    assert cache.get("old.com") is None
    assert cache.stats["misses"] == 1
    
    cache.set_many([record])
    assert cache.clear_expired() >= 0

@pytest.mark.asyncio
async def test_async_dns_resolver():
    with patch("pathlib.Path.exists", return_value=True):
        with patch("builtins.open", mock_open(read_data="8.8.8.8\n# comment\n1.1.1.1")):
            resolvers = AsyncDNSResolver.load_resolvers("fake.txt")
            assert "8.8.8.8" in resolvers

    resolver = AsyncDNSResolver(use_cache=True)
    
    # Mock A record lookup
    mock_lookup = MagicMock(return_value=("example.com", [], ["1.2.3.4"]))
    with patch("asyncio.get_event_loop") as mock_loop:
        mock_loop.return_value.run_in_executor = AsyncMock(return_value=("example.com", [], ["1.2.3.4"]))
        
        res = await resolver.resolve("example.com")
        assert res.has_records
        assert res.a_records == ["1.2.3.4"]
        
        # Test cache
        res_cached = await resolver.resolve("example.com")
        assert resolver.get_stats()["cached"] == 1

    # Test failure
    with patch("asyncio.get_event_loop") as mock_loop:
        mock_loop.return_value.run_in_executor = AsyncMock(side_effect=socket.gaierror("fail"))
        res = await resolver._resolve_single("fail.com")
        assert res.error is not None

    # Test ImportError for non-A records
    with patch("asyncio.get_event_loop") as mock_loop:
        with patch.dict("sys.modules", {"dns.resolver": None}):
            res = await resolver._resolve_single("example.com", record_type="MX")
            assert "dnspython not installed" in res.error

    # Test MX record lookup with mock dnspython
    with patch("asyncio.get_event_loop") as mock_loop:
        mock_dns = MagicMock()
        mock_dns.resolve.return_value = [MagicMock(exchange="mail.com")]
        with patch.dict("sys.modules", {"dns.resolver": mock_dns}):
            # Need to mock the lambda inside run_in_executor
            mock_loop.return_value.run_in_executor = AsyncMock(return_value=[MagicMock(__str__=lambda x: "mail.com")])
            res = await resolver._resolve_single("example.com", record_type="MX")
            assert res.has_records
            assert res.records[0].record_type == "MX"

    # Test TimeoutError
    with patch("asyncio.get_event_loop") as mock_loop:
        mock_loop.return_value.run_in_executor = AsyncMock(side_effect=asyncio.TimeoutError())
        res = await resolver._resolve_single("timeout.com")
        assert "timeout" in res.error

    # Test generic Exception
    with patch("asyncio.get_event_loop") as mock_loop:
        mock_loop.return_value.run_in_executor = AsyncMock(side_effect=RuntimeError("unknown"))
        res = await resolver._resolve_single("error.com")
        assert "unknown" in res.error

    # Test resolve with multiple types
    with patch("asyncio.get_event_loop") as mock_loop:
        mock_loop.return_value.run_in_executor = AsyncMock(return_value=("example.com", [], ["1.1.1.1"]))
        res = await resolver.resolve("example.com", record_types=["A", "CNAME"])
        assert len(res.records) >= 1

def test_dns_cache_stats_hit_rate():
    cache = DNSCache()
    assert cache.stats["hit_rate"] == 0
    cache.set(DNSRecord("a.com", "A", "1.1.1.1"))
    cache.get("a.com")
    assert cache.stats["hit_rate"] == 1.0

# ═══════════════════════════════════════════════════════════
# 2. Config Migrate Tests
# ═══════════════════════════════════════════════════════════

def test_config_migration_v1_to_1_1():
    config = {
        "version": "1.0.0",
        "notifications": {"webhook": "http://slack"}
    }
    from recon_cli.utils.config_migrate import migrate_v1_to_v1_1
    new_config = migrate_v1_to_v1_1(config)
    assert new_config["version"] == "1.1.0"
    assert new_config["notifications"]["slack_webhook"] == "http://slack"
    assert "jobs" in new_config

def test_config_migrator_no_path():
    migrator = ConfigMigrator()
    migrator.config = {"version": "9.9.9"}
    result = migrator.migrate()
    assert not result.success
    assert "No migration path" in result.errors[0]

def test_config_migrator_transform_failure():
    with patch("recon_cli.utils.config_migrate.MIGRATIONS", [
        MigrationRule("0.0.0", "1.0.0", "fail", lambda x: 1/0)
    ]):
        migrator = ConfigMigrator()
        result = migrator.migrate()
        assert not result.success
        assert "Migration failed" in result.errors[0]

def test_config_validation_more():
    migrator = ConfigMigrator()
    migrator.config = {
        "version": "1.1.0",
        "pipeline": {"max_concurrent": "high"}, # Wrong type
        "http": {"max_connections": 50},
        "logging": {"level": "INFO"}
    }
    is_valid, errors = migrator.validate()
    assert not is_valid
    assert any("should be int" in e for e in errors)
    
    # Missing section
    migrator.config = {"version": "1.1.0"}
    is_valid, errors = migrator.validate()
    assert not is_valid
    assert any("Missing required section" in e for e in errors)

def test_config_migrator_io(tmp_path):
    config_file = tmp_path / "config.yaml"
    config_file.write_text("version: '1.0.0'\npipeline: {max_concurrent: 5}")
    
    migrator = ConfigMigrator(config_file)
    assert migrator.get_version() == "1.0.0"
    assert migrator.needs_migration()
    
    result = migrator.migrate()
    assert result.success
    
    save_path = migrator.save(backup=True)
    assert save_path.exists()
    assert any(save_path.parent.glob("*.backup_*"))

def test_config_validation():
    migrator = ConfigMigrator()
    migrator.config = {
        "version": "1.1.0",
        "pipeline": {"max_concurrent": 1000}, # Out of range
        "http": {"max_connections": 50},
        "logging": {"level": "INFO"}
    }
    is_valid, errors = migrator.validate()
    assert not is_valid
    assert any("pipeline.max_concurrent" in e for e in errors)

def test_migrate_config_cli(tmp_path):
    config_file = tmp_path / "old.json"
    config_file.write_text(json.dumps({"concurrent": 5}))
    
    with patch("builtins.print"):
        success = migrate_config(str(config_file), dry_run=True)
        assert success

# ═══════════════════════════════════════════════════════════
# 3. Structured Logging Tests
# ═══════════════════════════════════════════════════════════

def test_structured_formatter():
    formatter = StructuredFormatter(extra_fields={"app": "reconn"})
    record = logging.LogRecord(
        name="test", level=logging.INFO, pathname="test.py",
        lineno=10, msg="Hello %s", args=("World",), exc_info=None
    )
    
    set_trace_id("trace-123")
    set_job_context("job-456")
    
    output = json.loads(formatter.format(record))
    assert output["message"] == "Hello World"
    assert output["trace_id"] == "trace-123"
    assert output["job_id"] == "job-456"
    assert output["app"] == "reconn"
    
    clear_context()
    assert get_trace_id() is None

def test_structured_formatter_extra():
    formatter = StructuredFormatter()
    record = logging.LogRecord(
        name="test", level=logging.INFO, pathname="test.py",
        lineno=10, msg="Hello", args=(), exc_info=None
    )
    # Manually add 'extra' dictionary which StructuredFormatter looks for
    record.extra = {"custom_field": "custom_val"}
    
    output = json.loads(formatter.format(record))
    assert output["custom_field"] == "custom_val"

def test_pretty_formatter():
    clear_context()
    formatter = PrettyFormatter()
    record = logging.LogRecord(
        name="test", level=logging.INFO, pathname="test.py",
        lineno=10, msg="Hello", args=(), exc_info=None
    )
    output = formatter.format(record)
    assert "INFO" in output
    assert "Hello" in output

    # Test with context - note trace_id is truncated to 8 chars
    set_trace_id("testtraceid")
    set_job_context("testjobid")
    try:
        output_ctx = formatter.format(record)
        assert "testtrac" in output_ctx
        assert "testjobid" in output_ctx
    finally:
        clear_context()

def test_log_context():
    clear_context()
    with LogContext(job_id="job1", trace_id="trace1"):
        assert get_trace_id() == "trace1"
    assert get_trace_id() is None


def test_setup_logging(tmp_path):
    log_file = tmp_path / "app.log"
    setup_logging(level="DEBUG", json_format=True, log_file=log_file)
    # Use 'stage' which is in StructuredFormatter's common list
    logger = get_logger("test_logger", stage="core")
    logger.info("Test message")
    
    assert log_file.exists()
    content = log_file.read_text()
    assert "Test message" in content
    assert '"stage": "core"' in content

def test_log_helpers():
    logger = MagicMock()
    log_stage_start(logger, "dns", "example.com")
    log_stage_end(logger, "dns", 1.5, True)
    log_tool_execution(logger, "subfinder", "example.com")
    log_finding(logger, "vulnerability", "example.com", "high")
    assert logger.info.call_count == 4

# ═══════════════════════════════════════════════════════════
# 4. Telegram Bot Tests
# ═══════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_telegram_bot_commands():
    bot = TelegramBot(token="fake_token", allowed_chat_id="12345")
    bot.send_message = AsyncMock()
    
    # Test /start
    await bot.handle_command("12345", "/start")
    bot.send_message.assert_called()
    
    # Test unauthorized (standard)
    await bot.handle_command("999", "/start")
    assert "Unauthorized" in bot.send_message.call_args[0][1]

    # Test unauthorized (discovery mode)
    bot.discovery_mode = True
    bot.allowed_chat_ids = set()
    await bot.handle_command("888", "hello")
    assert "Your Telegram Chat ID is" in bot.send_message.call_args[0][1]
    bot.discovery_mode = False
    bot.allowed_chat_ids = {"12345"}

    # Test empty message
    await bot.handle_command("12345", "")
    
    # Mock manager
    bot.manager = MagicMock()
    
    # Test /status
    bot.manager.get_job_counts.return_value = {"running": 1, "queued": 2, "finished": 3, "failed": 4}
    await bot.handle_command("12345", "/status")
    assert "Running: 1" in bot.send_message.call_args[0][1]

    # Test /list
    bot.manager.list_jobs.return_value = ["job1"]
    job_mock = MagicMock()
    job_mock.metadata.job_id = "job1"
    job_mock.metadata.status = "finished"
    job_mock.spec.target = "example.com"
    job_mock.spec.profile = "full"
    bot.manager.load_job.return_value = job_mock
    await bot.handle_command("12345", "/list")
    assert "job1" in bot.send_message.call_args[0][1]

    # Test /scan
    bot.manager.create_job.return_value.metadata.job_id = "job_new"
    await bot.handle_command("12345", "/scan target1")
    assert "job_new" in bot.send_message.call_args[0][1]
    
    # Test /scan error
    bot.manager.create_job.side_effect = Exception("Launch fail")
    await bot.handle_command("12345", "/scan target2")
    assert "Error" in bot.send_message.call_args[0][1]
    bot.manager.create_job.side_effect = None

    # Test /report
    bot.manager.load_job.return_value = job_mock
    with patch("recon_cli.jobs.summary.generate_summary_data", return_value={"counts": {"subdomains": 10}}):
        await bot.handle_command("12345", "/report job1")
        assert "subdomains: 10" in bot.send_message.call_args[0][1]
    
    # Test /report not found
    bot.manager.load_job.return_value = None
    await bot.handle_command("12345", "/report job_missing")
    assert "not found" in bot.send_message.call_args[0][1]

    # Test /cancel
    bot.manager.load_job.return_value = job_mock
    job_mock.paths.root = MagicMock()
    await bot.handle_command("12345", "/cancel job1")
    assert "Stop request sent" in bot.send_message.call_args[0][1]

    # Test unknown command
    await bot.handle_command("12345", "/unknown")
    assert "Unknown command" in bot.send_message.call_args[0][1]

@pytest.mark.asyncio
async def test_telegram_bot_network_errors():
    bot = TelegramBot(token="fake_token", allowed_chat_id="12345")
    
    # Test send_message network failure
    with patch("aiohttp.ClientSession.post") as mock_post:
        mock_post.return_value.__aenter__.return_value.status = 500
        mock_post.return_value.__aenter__.return_value.text = AsyncMock(return_value="Internal Error")
        await bot.send_message("12345", "hello")
    
    # Test send_message exception
    with patch("aiohttp.ClientSession.post", side_effect=Exception("network down")):
        await bot.send_message("12345", "hello")

    # Test get_updates network failure
    with patch("aiohttp.ClientSession.get") as mock_get:
        mock_get.return_value.__aenter__.return_value.status = 500
        mock_get.return_value.__aenter__.return_value.text = AsyncMock(return_value="Error")
        await bot.get_updates()

    # Test get_updates exception
    with patch("aiohttp.ClientSession.get", side_effect=Exception("error")):
        await bot.get_updates()

@pytest.mark.asyncio
async def test_telegram_bot_loop():
    bot = TelegramBot(token="t", allowed_chat_id="1")
    bot.get_updates = AsyncMock(side_effect=[
        [{"update_id": 100, "message": {"chat": {"id": 1}, "text": "/status"}}],
        Exception("stop loop") # To break the while loop in a testable way
    ])
    bot.handle_command = AsyncMock()
    
    # We need to limit the loop or mock asyncio.sleep to raise exception
    with patch("asyncio.sleep", side_effect=[None, asyncio.CancelledError()]):
        try:
            await bot.start()
        except Exception as e:
            if str(e) != "stop loop":
                raise
        except asyncio.CancelledError:
            pass
    
    assert bot.offset == 101
    bot.stop()
    assert not bot.running

# ═══════════════════════════════════════════════════════════
# 5. Error Recovery Tests
# ═══════════════════════════════════════════════════════════

def test_error_context():
    ctx = ErrorContext(stage_name="test", target="example.com")
    ctx.add_partial_result({"found": "subdomain.com"})
    ctx.record_recovery_attempt(RecoveryAction.RETRY, True)
    
    try:
        raise ValueError("Oops")
    except Exception as e:
        ctx.mark_failed(e)
    
    data = ctx.to_dict()
    assert data["exception"]["type"] == "ValueError"
    assert data["partial_results_count"] == 1
    assert json.loads(ctx.to_json())["error_id"] == ctx.error_id

def test_recovery_strategy():
    strategy = RecoveryStrategy()
    assert strategy.get_action(TimeoutError(), "passive", 1) == RecoveryAction.RETRY
    assert strategy.get_action(PermissionError(), "passive", 1) == RecoveryAction.ABORT
    assert strategy.get_action(ValueError(), "screenshot", 1) == RecoveryAction.SKIP
    assert strategy.get_retry_delay(2) == 2.0

def test_partial_result_saver(tmp_path):
    saver = PartialResultSaver(tmp_path, "job1")
    saver.add_result("dns", {"ip": "1.1.1.1"})
    path = saver.save_checkpoint("dns")
    assert path.exists()
    
    loaded = saver.load_checkpoint("dns")
    assert len(loaded) == 1
    assert loaded[0]["ip"] == "1.1.1.1"
    
    final_path = tmp_path / "final.jsonl"
    saver.merge_with_final(final_path)
    assert final_path.exists()
    
    saver.cleanup()
    assert not (tmp_path / "partial").exists()

def test_graceful_degradation():
    gd = GracefulDegradation()
    gd.disable_feature("port_scan", "too slow")
    assert not gd.is_feature_enabled("port_scan")
    
    gd.use_fallback("dns", "local")
    assert gd.get_fallback("dns") == "local"
    
    should, action = gd.should_continue(ValueError("skip me"), "screenshot", 1)
    assert should
    assert action == RecoveryAction.SKIP

def test_recovery_context_manager(tmp_path):
    with pytest.raises(ValueError):
        with error_recovery_context("test_stage", output_dir=tmp_path) as ctx:
            ctx.record_result({"key": "val"})
            raise ValueError("Failure")
    
    # Verify partial results were saved on error
    assert (tmp_path / "partial" / "test_stage_partial.jsonl").exists()

def test_recovery_decorators():
    @with_recovery("decorated_stage")
    def fail_func(target):
        raise RuntimeError("Fail")
    
    with pytest.raises(RuntimeError):
        fail_func("example.com")

    @graceful_stage(optional=True, fallback=lambda x: "fallback_val")
    def optional_fail(x):
        raise ValueError("Optional fail")
    
    assert optional_fail(1) == "fallback_val"

def test_partial_result_saver_edge_cases(tmp_path):
    saver = PartialResultSaver(tmp_path, "job1")
    # Test adding multiple results
    saver.add_results("stage1", [{"a": 1}, {"b": 2}])
    assert len(saver.get_results("stage1")) == 2
    
    # Test saving empty stage
    saver.save_checkpoint("empty_stage")
    
    # Test loading non-existent checkpoint
    assert saver.load_checkpoint("missing") == []
    
    # Test JSONDecodeError during load
    cp_file = tmp_path / "partial" / "corrupt_partial.jsonl"
    cp_file.write_text("invalid json\n{\"valid\": true}")
    results = saver.load_checkpoint("corrupt")
    assert len(results) == 1

def test_error_report_generator_summary(tmp_path):
    gen = ErrorReportGenerator("job1", tmp_path)
    # Empty summary
    assert gen.generate_summary()["total_errors"] == 0
    
    # Multi-error summary
    gen.add_error(ErrorContext(stage_name="s1", severity=ErrorSeverity.CRITICAL))
    gen.add_error(ErrorContext(stage_name="s2", severity=ErrorSeverity.LOW))
    summary = gen.generate_summary()
    assert summary["total_errors"] == 2
    assert summary["errors_by_severity"]["critical"] == 1
    assert summary["recoverable_count"] == 1

def test_global_recovery_handler_singleton():
    h1 = GlobalRecoveryHandler()
    h2 = get_recovery_handler()
    assert h1 is h2
    
    h1.set_strategy(RecoveryStrategy())
    h1.start_recovery("stage_x")
    h1.end_recovery("stage_x")
    h1.reset()
    assert len(h1.get_all_errors()) == 0

# ═══════════════════════════════════════════════════════════
# Main Entry Point
# ═══════════════════════════════════════════════════════════
if __name__ == "__main__":
    pytest.main([__file__])
