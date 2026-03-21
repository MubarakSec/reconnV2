from __future__ import annotations

import pytest
import logging
from pathlib import Path
from recon_cli.utils.performance import ConnectionPool, PoolConfig
from recon_cli.inventory import AssetInventory, Asset, AssetType, AssetStatus, RiskLevel
from recon_cli.utils.cache import HybridCache, CacheConfig
from recon_cli.utils.async_dns import AsyncDNSResolver
from recon_cli.utils.config_migrate import ConfigMigrator
from recon_cli.utils.diff import ScanDiff
from recon_cli.utils.error_aggregator import ErrorAggregator
from recon_cli.utils.memory import MemoryTracker
from recon_cli.utils.structured_logging import ContextLogger
from recon_cli.utils.telegram_bot import TelegramBot

def test_performance_pool(tmp_path):
    config = PoolConfig(timeout=1)
    pool = ConnectionPool(config)
    assert pool is not None
    # Singleton check
    assert ConnectionPool() is pool

def test_inventory_basics(tmp_path):
    db_path = tmp_path / "test_inventory.db"
    inventory = AssetInventory(db_path)
    asset = inventory.add(type=AssetType.DOMAIN, value="example.com")
    assert asset.id is not None
    
    found = inventory.get(asset.id)
    assert found is not None
    assert found.value == "example.com"

def test_hybrid_cache(tmp_path):
    cache_dir = tmp_path / "cache"
    cache = HybridCache(cache_dir)
    cache.set("key", "value")
    assert cache.get("key") == "value"

@pytest.mark.asyncio
async def test_async_resolver():
    resolver = AsyncDNSResolver()
    # Basic init check
    assert resolver is not None

def test_results_diff():
    diff = ScanDiff()
    # Basic init check
    assert diff is not None

def test_error_aggregator():
    aggregator = ErrorAggregator()
    aggregator.add(ValueError("test error"))
    assert aggregator.total_count == 1

def test_memory_tracker():
    tracker = MemoryTracker()
    snapshot = tracker.checkpoint("test")
    assert snapshot is not None

def test_config_migrator(tmp_path):
    config_file = tmp_path / "config.yaml"
    config_file.write_text("version: 1.0", encoding="utf-8")
    migrator = ConfigMigrator()
    assert migrator is not None

def test_context_logger():
    base_logger = logging.getLogger("test")
    logger = ContextLogger(base_logger, {})
    assert logger is not None

def test_telegram_bot():
    bot = TelegramBot("token", "chat_id")
    assert bot is not None

def test_diff_snapshots(tmp_path):
    from recon_cli.utils.diff import HistoryTracker
    from datetime import datetime
    history = HistoryTracker(tmp_path / "history")
    results = [{"type": "domain", "value": "example.com"}]
    snapshot = history.save_snapshot("scan-1", "example.com", results)
    assert snapshot.target == "example.com"
    assert len(history.get_snapshots("example.com")) == 1

def test_inventory_full(tmp_path):
    db_path = tmp_path / "inventory_full.db"
    inventory = AssetInventory(db_path)
    
    # Test search
    inventory.add(AssetType.DOMAIN, "target1.com", risk_level=RiskLevel.HIGH)
    inventory.add(AssetType.DOMAIN, "target2.com", risk_level=RiskLevel.CRITICAL)
    
    results = inventory.search(type=AssetType.DOMAIN)
    assert len(results) == 2
    
    # Test update
    asset = results[0]
    asset.status = AssetStatus.ACTIVE
    inventory.update(asset)
    updated = inventory.get(asset.id)
    assert updated.status == AssetStatus.ACTIVE

def test_config_migrate_full(tmp_path):
    import json
    config_path = tmp_path / "old_config.json"
    config_data = {"version": "0.1.0", "old_key": "value"}
    with open(config_path, "w") as f:
        json.dump(config_data, f)
        
    migrator = ConfigMigrator(config_path)
    assert migrator.get_version() == "0.1.0"
    
    # Test migration path
    result = migrator.migrate("0.2.0")
    assert result is not None

def test_error_recovery_strategies(tmp_path):
    from recon_cli.utils.error_recovery import RecoveryStrategy, RecoveryAction, error_recovery_context
    
    strategy = RecoveryStrategy(default_action=RecoveryAction.SKIP)
    try:
        with error_recovery_context("test_strategy", strategy=strategy) as ctx:
            raise ValueError("Failure")
    except ValueError:
        pass
    
    assert not ctx.is_success
    assert ctx.error_context.exception_type == "ValueError"
