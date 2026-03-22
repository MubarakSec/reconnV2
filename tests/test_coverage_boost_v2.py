
import json
import sqlite3
import os
import shutil
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
import subprocess
from unittest.mock import MagicMock, patch, mock_open

import pytest
from dataclasses import asdict

# Target imports
from recon_cli.inventory import AssetInventory, Asset, AssetType, AssetStatus, RiskLevel, AssetRelation
from recon_cli.utils.diff import ScanDiff, ResultNormalizer, ChangeType, Severity, HistoryTracker, ScanSnapshot, Change
from recon_cli.utils.health import (
    HealthChecker, HealthStatus, HealthCheck, HealthReport, 
    check_disk_space, check_memory, check_cpu, 
    DatabaseHealthCheck, DiskHealthCheck, MemoryHealthCheck, ExternalServiceHealthCheck,
    HealthRegistry, get_system_status, create_health_router, create_metrics_router
)
from recon_cli.scanners.integrations import (
    run_nuclei, run_nuclei_batch, run_wpscan, run_ffuf, 
    run_katana, run_dnsx, run_tlsx, run_httpx_extended,
    ScannerFinding, ScannerExecution
)
from recon_cli.pipeline.stage_extended_validation import ExtendedValidationStage
from recon_cli.pipeline.context import PipelineContext
from recon_cli.tools.executor import CommandExecutor

# ═══════════════════════════════════════════════════════════
# 1. recon_cli/inventory.py
# ═══════════════════════════════════════════════════════════

class TestInventory:
    @pytest.fixture
    def inventory(self, tmp_path):
        db_path = tmp_path / "test_inventory.db"
        return AssetInventory(db_path)

    def test_asset_dataclass(self):
        asset = Asset(type=AssetType.DOMAIN, value="example.com")
        d = asset.to_dict()
        assert d["value"] == "example.com"
        assert d["type"] == "domain"
        
        asset2 = Asset.from_dict(d)
        assert asset2.value == "example.com"
        assert asset2.type == AssetType.DOMAIN

    def test_inventory_crud(self, inventory):
        # Add
        asset = inventory.add(AssetType.DOMAIN, "example.com", source="test")
        assert asset.id is not None
        assert asset.value == "example.com"
        
        # Add existing (updates last_seen)
        old_last_seen = asset.last_seen
        asset2 = inventory.add(AssetType.DOMAIN, "example.com")
        assert asset2.id == asset.id
        
        # Get
        fetched = inventory.get(asset.id)
        assert fetched.value == "example.com"
        
        # Update
        fetched.notes = "updated notes"
        assert inventory.update(fetched)
        assert inventory.get(asset.id).notes == "updated notes"
        
        # Delete
        assert inventory.delete(asset.id)
        assert inventory.get(asset.id) is None

    def test_inventory_search_and_count(self, inventory):
        dom = inventory.add(AssetType.DOMAIN, "example.com", tags=["prod"])
        sub = inventory.add(AssetType.SUBDOMAIN, "api.example.com", parent_id=dom.id, status=AssetStatus.ACTIVE)
        
        assert inventory.count() == 2
        assert inventory.count(type=AssetType.DOMAIN) == 1
        
        results = inventory.search(type=AssetType.SUBDOMAIN)
        assert len(results) == 1
        assert results[0].value == "api.example.com"
        
        results = inventory.search(value_contains="api")
        assert len(results) == 1
        
        results = inventory.search(tag="prod")
        assert len(results) == 1
        
        assert inventory.find_by_value("example.com").id == dom.id

    def test_inventory_relations(self, inventory):
        a1 = inventory.add(AssetType.DOMAIN, "a.com")
        a2 = inventory.add(AssetType.IP, "1.1.1.1")
        
        rel = inventory.add_relation(a1.id, a2.id, "resolves_to")
        assert rel is not None
        
        rels = inventory.get_relations(a1.id, direction="outgoing")
        assert len(rels) == 1
        assert rels[0][1].value == "1.1.1.1"
        
        rels = inventory.get_relations(a2.id, direction="incoming")
        assert len(rels) == 1
        assert rels[0][1].value == "a.com"

    def test_inventory_tree(self, inventory):
        root = inventory.add(AssetType.DOMAIN, "root.com")
        c1 = inventory.add(AssetType.SUBDOMAIN, "c1.root.com", parent_id=root.id)
        c2 = inventory.add(AssetType.SUBDOMAIN, "c2.root.com", parent_id=root.id)
        gc1 = inventory.add(AssetType.IP, "1.1.1.1", parent_id=c1.id)
        
        tree = inventory.get_tree(root.id)
        assert tree["asset"]["value"] == "root.com"
        assert len(tree["children"]) == 2

    def test_inventory_bulk_and_import(self, inventory):
        # Bulk add
        count = inventory.bulk_add([
            {"type": "domain", "value": "b1.com"},
            {"type": "ip", "value": "2.2.2.2"}
        ])
        assert count == 2
        
        # Import from scan
        results = [
            {"subdomain": "s1.test.com"},
            {"ip": "3.3.3.3"},
            {"port": 80, "host": "s1.test.com"},
            {"url": "https://test.com/api"},
            {"vulnerability": {"id": "VULN-1"}, "severity": "high"}
        ]
        stats = inventory.import_from_scan(results)
        assert stats["imported"] == 5

    def test_inventory_export_import_file(self, inventory, tmp_path):
        inventory.add(AssetType.DOMAIN, "export.com")
        json_file = tmp_path / "export.json"
        csv_file = tmp_path / "export.csv"
        
        assert inventory.export(json_file, format="json") == 1
        assert inventory.export(csv_file, format="csv") == 1
        
        new_inv = AssetInventory(tmp_path / "new.db")
        assert new_inv.import_file(json_file, format="json") == 1
        assert new_inv.import_file(csv_file, format="csv") == 1

    def test_inventory_stats(self, inventory):
        inventory.add(AssetType.DOMAIN, "stats.com", risk_level=RiskLevel.HIGH)
        stats = inventory.stats()
        assert stats["total"] == 1
        assert stats["by_type"]["domain"] == 1
        assert stats["by_risk"]["high"] == 1

# ═══════════════════════════════════════════════════════════
# 2. recon_cli/utils/diff.py
# ═══════════════════════════════════════════════════════════

class TestDiff:
    def test_normalizer(self):
        norm = ResultNormalizer()
        results = [
            {"subdomain": "a.com", "ip": "1.1.1.1"},
            {"url": "https://b.com", "status": 200},
            {"cve": "CVE-2021-1234", "severity": "high"}
        ]
        normalized = norm.normalize(results)
        assert "subdomain" in normalized
        assert "endpoint" in normalized
        assert "vulnerability" in normalized
        
        # Test key generation fallback
        other = norm.normalize([{"foo": "bar"}])
        assert "other" in other

    def test_scan_diff(self):
        diff = ScanDiff()
        old = [{"subdomain": "a.com"}, {"subdomain": "b.com"}]
        new = [{"subdomain": "b.com", "extra": "info"}, {"subdomain": "c.com"}]
        
        changes = diff.compare(old, new)
        # a.com removed, b.com modified, c.com added
        types = [c.change_type for c in changes]
        assert ChangeType.ADDED in types
        assert ChangeType.REMOVED in types
        assert ChangeType.MODIFIED in types
        
        summary = diff.summarize(changes)
        assert summary.added == 1
        assert summary.removed == 1
        assert summary.modified == 1
        
        report = diff.format_report(changes, summary)
        assert "SCAN COMPARISON REPORT" in report

    def test_history_tracker(self, tmp_path):
        tracker = HistoryTracker(tmp_path / "history")
        results = [{"subdomain": "a.com"}]
        
        tracker.save_snapshot("s0", "target.com", results)
        snap = tracker.save_snapshot("s1", "target.com", results)
        assert snap.scan_id == "s1"
        
        latest = tracker.get_latest("target.com")
        assert latest.scan_id == "s1"
        
        new_results = [{"subdomain": "a.com"}, {"subdomain": "b.com"}]
        changes = tracker.compare_with_latest("target.com", new_results)
        assert len(changes) == 1
        assert changes[0].change_type == ChangeType.ADDED
        
        trend = tracker.get_trend("target.com")
        assert "dates" in trend
        
        # Cleanup
        tracker.save_snapshot("s2", "target.com", results)
        assert tracker.cleanup("target.com", keep=1) == 2

# ═══════════════════════════════════════════════════════════
# 3. recon_cli/utils/health.py
# ═══════════════════════════════════════════════════════════

class TestHealth:
    @pytest.mark.asyncio
    async def test_health_checker(self):
        checker = HealthChecker(version="2.0.0")
        checker.add_check("const_ok", lambda: True)
        checker.add_check("const_fail", lambda: False)
        
        async def async_check():
            return HealthCheck(name="async", status=HealthStatus.HEALTHY)
        
        checker.add_check("async", async_check)
        
        report = await checker.check()
        assert report.status == HealthStatus.UNHEALTHY # because const_fail
        assert len(report.checks) == 3
        
        assert await checker.check_liveness() is True
        assert await checker.check_readiness() is False

    def test_default_checks(self):
        # Disk
        with patch("shutil.disk_usage", return_value=(100, 50, 50)):
            res = check_disk_space()
            assert res.status == HealthStatus.HEALTHY
        
        with patch("shutil.disk_usage", return_value=(100, 96, 4)):
            res = check_disk_space()
            assert res.status == HealthStatus.UNHEALTHY

        # Memory
        with patch("psutil.virtual_memory") as mock_mem:
            mock_mem.return_value.percent = 50
            res = check_memory()
            assert res.status == HealthStatus.HEALTHY

        # CPU
        with patch("psutil.cpu_percent", return_value=50):
            res = check_cpu()
            assert res.status == HealthStatus.HEALTHY

    @pytest.mark.asyncio
    async def test_extra_health_checks(self):
        # Database
        db_check = DatabaseHealthCheck("db", connection_string=":memory:")
        res = await db_check.check()
        assert res.status == HealthStatus.HEALTHY
        
        # Disk (HealthCheck subclass)
        disk_check = DiskHealthCheck("disk")
        with patch("shutil.disk_usage", return_value=(100, 50, 50)):
            res = await disk_check.check()
            assert res.status == HealthStatus.HEALTHY
            
        # Memory (HealthCheck subclass)
        mem_check = MemoryHealthCheck("mem")
        with patch("psutil.virtual_memory") as mock_mem:
            mock_mem.return_value.percent = 50
            res = await mem_check.check()
            assert res.status == HealthStatus.HEALTHY

        # External Service
        with patch("aiohttp.ClientSession.get") as mock_get:
            mock_get.return_value.__aenter__.return_value.status = 200
            svc_check = ExternalServiceHealthCheck("svc", "http://api.com")
            res = await svc_check.check()
            assert res.status == HealthStatus.HEALTHY

    @pytest.mark.asyncio
    async def test_registry_and_status(self):
        registry = HealthRegistry()
        registry.register(HealthCheck("ok", status=HealthStatus.HEALTHY))
        assert await registry.get_overall_status() == HealthStatus.HEALTHY
        
        d = await registry.to_dict()
        assert d["status"] == "healthy"
        
        checker = HealthChecker()
        status = await get_system_status(checker)
        assert status.health == HealthStatus.HEALTHY

# ═══════════════════════════════════════════════════════════
# 4. recon_cli/scanners/integrations.py
# ═══════════════════════════════════════════════════════════

class TestScannerIntegrations:
    @pytest.fixture
    def executor(self):
        mock = MagicMock(spec=CommandExecutor)
        return mock

    @pytest.fixture
    def logger(self):
        return MagicMock()

    def test_run_nuclei(self, executor, logger, tmp_path):
        def mock_run(*args, **kwargs):
            artifact_path = tmp_path / "nuclei_test.com.json"
            artifact_path.write_text(json.dumps({
                "templateID": "test-id",
                "host": "test.com",
                "matched-at": "http://test.com",
                "info": {"severity": "high", "name": "Test Finding"}
            }) + "\n")
            return subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        
        executor.run.side_effect = mock_run
        
        with patch("shutil.which", return_value="/usr/bin/nuclei"):
            exec_res = run_nuclei(executor, logger, "test.com", "http://test.com", tmp_path, 10)
            assert len(exec_res.findings) >= 1
            assert exec_res.findings[0].payload["source"] == "scanner-nuclei"

    def test_run_nuclei_batch(self, executor, logger, tmp_path):
        executor.run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        with patch("shutil.which", return_value="/usr/bin/nuclei"):
            exec_res = run_nuclei_batch(executor, logger, ["t1.com", "t2.com"], tmp_path, 10)
            assert exec_res.stats["targets"] == 2

    def test_run_wpscan(self, executor, logger, tmp_path):
        artifact_path = tmp_path / "wpscan_test.com.json"
        artifact_path.write_text(json.dumps({
            "vulnerabilities": [{"title": "Vuln 1", "severity": "medium"}]
        }))
        executor.run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        with patch("shutil.which", return_value="/usr/bin/wpscan"):
            exec_res = run_wpscan(executor, logger, "test.com", "http://test.com", tmp_path, 10)
            assert len(exec_res.findings) == 1

    def test_run_ffuf(self, executor, logger, tmp_path):
        artifact_path = tmp_path / "ffuf_test.com.json"
        artifact_path.write_text(json.dumps({
            "results": [{"url": "http://test.com/secret", "status": 200}]
        }))
        executor.run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        with patch("shutil.which", return_value="/usr/bin/ffuf"):
            with patch("pathlib.Path.exists", return_value=True):
                exec_res = run_ffuf(executor, logger, "test.com", "http://test.com", tmp_path, 10)
                assert len(exec_res.findings) == 1

    def test_run_katana(self, executor, logger, tmp_path):
        artifact_path = tmp_path / "katana_test.com.json"
        artifact_path.write_text(json.dumps({"url": "http://test.com/page1"}) + "\n")
        executor.run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        with patch("shutil.which", return_value="/usr/bin/katana"):
            exec_res = run_katana(executor, logger, "test.com", "http://test.com", tmp_path, 10)
            assert len(exec_res.findings) == 1

    def test_run_dnsx(self, executor, logger, tmp_path):
        artifact_path = tmp_path / "dnsx_output.json"
        artifact_path.write_text(json.dumps({"host": "a.test.com", "a": ["1.1.1.1"]}) + "\n")
        executor.run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        with patch("shutil.which", return_value="/usr/bin/dnsx"):
            exec_res = run_dnsx(executor, logger, ["a.test.com"], tmp_path, 10)
            assert len(exec_res.findings) == 1

    def test_run_tlsx(self, executor, logger, tmp_path):
        artifact_path = tmp_path / "tlsx_output.json"
        artifact_path.write_text(json.dumps({"host": "test.com", "expired": True}) + "\n")
        executor.run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        with patch("shutil.which", return_value="/usr/bin/tlsx"):
            exec_res = run_tlsx(executor, logger, ["test.com"], tmp_path, 10)
            assert len(exec_res.findings) == 1
            assert "expired_cert" in exec_res.findings[0].payload["vulnerabilities"]

    def test_run_httpx_extended(self, executor, logger, tmp_path):
        artifact_path = tmp_path / "httpx_extended.json"
        artifact_path.write_text(json.dumps({"host": "test.com", "tech": ["nginx"]}) + "\n")
        executor.run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        with patch("shutil.which", return_value="/usr/bin/httpx"):
            exec_res = run_httpx_extended(executor, logger, ["test.com"], tmp_path, 10)
            assert len(exec_res.findings) == 1

# ═══════════════════════════════════════════════════════════
# 5. recon_cli/pipeline/stage_extended_validation.py
# ═══════════════════════════════════════════════════════════

class TestExtendedValidationStage:
    @pytest.fixture
    def context(self):
        ctx = MagicMock(spec=PipelineContext)
        ctx.logger = MagicMock()
        ctx.runtime_config = MagicMock()
        ctx.runtime_config.enable_extended_validation = True
        ctx.runtime_config.extended_validation_max_duration = 3600
        ctx.runtime_config.extended_validation_max_probes = 1000
        ctx.runtime_config.enable_redirect_validation = True
        ctx.record = MagicMock()
        tmp_dir = Path(tempfile.gettempdir())
        ctx.record.paths.root = tmp_dir
        ctx.record.paths.ensure_subdir.return_value = tmp_dir
        ctx.record.metadata.stats = {}
        ctx.get_results.return_value = []
        ctx.url_allowed.return_value = True
        ctx.signal_index.return_value = {"by_host": {}}
        ctx.results = MagicMock()
        return ctx

    def test_is_enabled(self, context):
        stage = ExtendedValidationStage()
        assert stage.is_enabled(context) is True
        context.runtime_config.enable_extended_validation = False
        assert stage.is_enabled(context) is False

    def test_score_adjustment(self):
        stage = ExtendedValidationStage()
        assert stage._adjust_score(50, "redirect", "https://evil.com") > 50
        assert stage._adjust_score(50, "redirect", "1") < 50
        assert stage._adjust_score(50, "lfi", "../etc/passwd") > 50

    def test_open_redirect_check(self):
        stage = ExtendedValidationStage()
        assert stage._is_open_redirect("http://a.com", "http://evil.com/token", "http://evil.com/token") is True
        assert stage._is_open_redirect("http://a.com", "http://a.com/path", "http://a.com/path") is False

    def test_lfi_check(self):
        stage = ExtendedValidationStage()
        assert stage._looks_like_lfi("root:x:0:0:") is True
        assert stage._looks_like_lfi("[extensions]") is True
        assert stage._looks_like_lfi("normal text") is False

    def test_collect_candidates(self, context):
        stage = ExtendedValidationStage()
        context.get_results.return_value = [
            {"type": "url", "url": "http://test.com?redirect=http://google.com", "score": 50},
            {"type": "parameter", "name": "file", "examples": ["http://test.com?file=abc.txt"], "score": 30},
            {"type": "form", "action": "http://test.com/login", "method": "post", "inputs": [{"name": "url"}], "score": 20}
        ]
        candidates = stage._collect_candidates(context, {})
        assert len(candidates["redirect"]) >= 2
        assert len(candidates["lfi"]) >= 1

    def test_execute_minimal(self, context):
        stage = ExtendedValidationStage()
        context.get_results.return_value = []
        # Should finish quickly without errors
        stage.execute(context)


