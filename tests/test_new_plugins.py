"""
Tests for New Plugin System
"""

import pytest
from pathlib import Path
from datetime import datetime
from unittest.mock import Mock, patch, MagicMock


class TestPluginMetadata:
    """Tests for PluginMetadata"""
    
    def test_default_metadata(self):
        """Test default metadata creation"""
        from recon_cli.plugins import PluginMetadata, PluginType
        
        meta = PluginMetadata(
            name="TestPlugin",
            version="1.0.0",
            description="Test plugin"
        )
        
        assert meta.name == "TestPlugin"
        assert meta.version == "1.0.0"
        assert meta.author == "Unknown"
        assert meta.plugin_type == PluginType.PROCESSOR
        assert meta.dependencies == []
    
    def test_metadata_to_dict(self):
        """Test metadata serialization"""
        from recon_cli.plugins import PluginMetadata, PluginType
        
        meta = PluginMetadata(
            name="TestPlugin",
            version="1.0.0",
            description="Test plugin",
            author="Test Author",
            plugin_type=PluginType.SCANNER,
            tags=["test", "demo"]
        )
        
        result = meta.to_dict()
        
        assert result["name"] == "TestPlugin"
        assert result["plugin_type"] == "scanner"
        assert result["tags"] == ["test", "demo"]

    def test_metadata_to_dict_exports_strict_config_schema(self):
        from recon_cli.plugins import PluginMetadata

        meta = PluginMetadata(
            name="SchemaPlugin",
            version="1.0.0",
            description="Plugin with config schema",
            config_schema={
                "api_key": {"type": "str", "required": True},
                "timeout": {"type": "int", "default": 30},
            },
        )

        payload = meta.to_dict()
        config_schema = payload["config_schema"]

        assert config_schema["type"] == "object"
        assert config_schema["additionalProperties"] is False
        assert "api_key" in config_schema["properties"]
        assert "timeout" in config_schema["properties"]
        assert "api_key" in config_schema["required"]


class TestPluginResult:
    """Tests for PluginResult"""
    
    def test_success_result(self):
        """Test successful result"""
        from recon_cli.plugins import PluginResult
        
        result = PluginResult(
            success=True,
            data={"key": "value"},
            execution_time=1.5
        )
        
        assert result.success is True
        assert result.data == {"key": "value"}
        assert result.error is None
    
    def test_error_result(self):
        """Test error result"""
        from recon_cli.plugins import PluginResult
        
        result = PluginResult(
            success=False,
            error="Something went wrong"
        )
        
        assert result.success is False
        assert result.error == "Something went wrong"


class TestPluginInterface:
    """Tests for PluginInterface base class"""
    
    def test_scanner_plugin(self):
        """Test ScannerPlugin base class"""
        from recon_cli.plugins import ScannerPlugin, PluginMetadata, PluginType
        
        class MyScannerPlugin(ScannerPlugin):
            METADATA = PluginMetadata(
                name="MyScanner",
                version="1.0.0",
                description="My scanner plugin",
                plugin_type=PluginType.SCANNER
            )
            
            def scan(self, target, options=None):
                return [{"host": target, "type": "host"}]
        
        plugin = MyScannerPlugin()
        assert plugin.METADATA.name == "MyScanner"
        
        result = plugin.execute({"target": "example.com"})
        assert result.success is True
        assert len(result.data) == 1
    
    def test_scanner_plugin_no_target(self):
        """Test ScannerPlugin without target"""
        from recon_cli.plugins import ScannerPlugin, PluginMetadata, PluginType
        
        class MyScannerPlugin(ScannerPlugin):
            METADATA = PluginMetadata(
                name="MyScanner",
                version="1.0.0",
                description="My scanner plugin",
                plugin_type=PluginType.SCANNER
            )
            
            def scan(self, target, options=None):
                return []
        
        plugin = MyScannerPlugin()
        result = plugin.execute({})  # No target
        
        assert result.success is False
        assert "No target" in result.error
    
    def test_enricher_plugin(self):
        """Test EnricherPlugin base class"""
        from recon_cli.plugins import EnricherPlugin, PluginMetadata, PluginType
        
        class MyEnricherPlugin(EnricherPlugin):
            METADATA = PluginMetadata(
                name="MyEnricher",
                version="1.0.0",
                description="My enricher plugin",
                plugin_type=PluginType.ENRICHER
            )
            
            def enrich(self, data):
                data["enriched"] = True
                return data
        
        plugin = MyEnricherPlugin()
        result = plugin.execute({"data": {"host": "example.com"}})
        
        assert result.success is True
        assert result.data["enriched"] is True
    
    def test_notifier_plugin(self):
        """Test NotifierPlugin base class"""
        from recon_cli.plugins import NotifierPlugin, PluginMetadata, PluginType
        
        class MyNotifierPlugin(NotifierPlugin):
            METADATA = PluginMetadata(
                name="MyNotifier",
                version="1.0.0",
                description="My notifier plugin",
                plugin_type=PluginType.NOTIFIER
            )
            
            def send(self, message, **kwargs):
                return True
        
        plugin = MyNotifierPlugin()
        result = plugin.execute({"message": "Test message"})
        
        assert result.success is True
    
    def test_validate_config_required_missing(self):
        """Test config validation with missing required field"""
        from recon_cli.plugins import ScannerPlugin, PluginMetadata, PluginType
        
        class ConfigPlugin(ScannerPlugin):
            METADATA = PluginMetadata(
                name="ConfigPlugin",
                version="1.0.0",
                description="Plugin with config",
                plugin_type=PluginType.SCANNER,
                config_schema={
                    "api_key": {"required": True},
                }
            )
            
            def scan(self, target, options=None):
                return []
        
        plugin = ConfigPlugin()  # No config
        assert plugin.validate_config() is False
    
    def test_validate_config_success(self):
        """Test successful config validation"""
        from recon_cli.plugins import ScannerPlugin, PluginMetadata, PluginType
        
        class ConfigPlugin(ScannerPlugin):
            METADATA = PluginMetadata(
                name="ConfigPlugin",
                version="1.0.0",
                description="Plugin with config",
                plugin_type=PluginType.SCANNER,
                config_schema={
                    "api_key": {"required": True},
                }
            )
            
            def scan(self, target, options=None):
                return []
        
        plugin = ConfigPlugin({"api_key": "test123"})
        assert plugin.validate_config() is True
        assert plugin.config == {"api_key": "test123"}

    def test_validate_config_applies_defaults(self):
        from recon_cli.plugins import ScannerPlugin, PluginMetadata, PluginType

        class ConfigPlugin(ScannerPlugin):
            METADATA = PluginMetadata(
                name="ConfigPlugin",
                version="1.0.0",
                description="Plugin with defaults",
                plugin_type=PluginType.SCANNER,
                config_schema={
                    "timeout": {"type": "int", "default": 15},
                    "enabled": {"type": "bool", "default": True},
                },
            )

            def scan(self, target, options=None):
                return []

        plugin = ConfigPlugin({})
        assert plugin.validate_config() is True
        assert plugin.config["timeout"] == 15
        assert plugin.config["enabled"] is True

    def test_validate_config_rejects_type_mismatch(self):
        from recon_cli.plugins import ScannerPlugin, PluginMetadata, PluginType

        class ConfigPlugin(ScannerPlugin):
            METADATA = PluginMetadata(
                name="ConfigPlugin",
                version="1.0.0",
                description="Plugin with typed config",
                plugin_type=PluginType.SCANNER,
                config_schema={
                    "timeout": {"type": "int", "required": True},
                },
            )

            def scan(self, target, options=None):
                return []

        plugin = ConfigPlugin({"timeout": "fast"})
        assert plugin.validate_config() is False
        assert plugin.config_error is not None
        assert "timeout" in plugin.config_error

    def test_validate_config_rejects_extra_fields(self):
        from recon_cli.plugins import ScannerPlugin, PluginMetadata, PluginType

        class ConfigPlugin(ScannerPlugin):
            METADATA = PluginMetadata(
                name="ConfigPlugin",
                version="1.0.0",
                description="Plugin with strict config",
                plugin_type=PluginType.SCANNER,
                config_schema={
                    "api_key": {"type": "str", "required": True},
                },
            )

            def scan(self, target, options=None):
                return []

        plugin = ConfigPlugin({"api_key": "test123", "unexpected": True})
        assert plugin.validate_config() is False
        assert plugin.config_error is not None
        assert "unexpected" in plugin.config_error

    def test_validate_config_supports_nested_objects(self):
        from recon_cli.plugins import ScannerPlugin, PluginMetadata, PluginType

        class ConfigPlugin(ScannerPlugin):
            METADATA = PluginMetadata(
                name="NestedPlugin",
                version="1.0.0",
                description="Plugin with nested config",
                plugin_type=PluginType.SCANNER,
                config_schema={
                    "auth": {
                        "type": "object",
                        "properties": {
                            "token": {"type": "str", "required": True},
                            "retries": {"type": "int", "default": 2},
                        },
                        "required": ["token"],
                    }
                },
            )

            def scan(self, target, options=None):
                return []

        plugin = ConfigPlugin({"auth": {"token": "abc"}})
        assert plugin.validate_config() is True
        assert plugin.config["auth"]["token"] == "abc"
        assert plugin.config["auth"]["retries"] == 2


class TestPluginLoader:
    """Tests for PluginLoader"""
    
    def test_initialization(self):
        """Test loader initialization"""
        from recon_cli.plugins import PluginLoader
        
        loader = PluginLoader()
        assert loader.plugins == {}
        assert loader.plugin_dirs == []
    
    def test_add_plugin_directory(self, tmp_path):
        """Test adding plugin directory"""
        from recon_cli.plugins import PluginLoader
        
        loader = PluginLoader()
        loader.add_plugin_directory(tmp_path)
        
        assert tmp_path in loader.plugin_dirs
    
    def test_add_nonexistent_directory(self, tmp_path):
        """Test adding non-existent directory"""
        from recon_cli.plugins import PluginLoader
        
        loader = PluginLoader()
        fake_path = tmp_path / "nonexistent"
        loader.add_plugin_directory(fake_path)
        
        assert fake_path not in loader.plugin_dirs
    
    def test_list_plugins_empty(self):
        """Test listing plugins when none loaded"""
        from recon_cli.plugins import PluginLoader
        
        loader = PluginLoader()
        plugins = loader.list_plugins()
        
        assert plugins == []
    
    def test_get_plugin_not_found(self):
        """Test getting non-existent plugin"""
        from recon_cli.plugins import PluginLoader
        
        loader = PluginLoader()
        plugin = loader.get_plugin("nonexistent")
        
        assert plugin is None
    
    def test_execute_plugin_not_found(self):
        """Test executing non-existent plugin"""
        from recon_cli.plugins import PluginLoader
        
        loader = PluginLoader()
        result = loader.execute_plugin("nonexistent", {})
        
        assert result.success is False
        assert "not found" in result.error

    def test_load_plugin_surfaces_validation_errors(self, tmp_path):
        from recon_cli.plugins import PluginLoader, PluginMetadata, PluginType, ScannerPlugin

        class ConfigPlugin(ScannerPlugin):
            METADATA = PluginMetadata(
                name="ConfigPlugin",
                version="1.0.0",
                description="Plugin with typed config",
                plugin_type=PluginType.SCANNER,
                config_schema={"timeout": {"type": "int", "required": True}},
            )

            def scan(self, target, options=None):
                return []

        loader = PluginLoader()
        loader.plugins["ConfigPlugin"] = MagicMock(
            plugin_class=ConfigPlugin,
            metadata=ConfigPlugin.METADATA,
            path=tmp_path / "plugin.py",
            status=None,
            instance=None,
            error=None,
        )

        plugin = loader.load_plugin("ConfigPlugin", {"timeout": "fast"})

        assert plugin is None
        assert loader.plugins["ConfigPlugin"].error is not None
        assert "timeout" in loader.plugins["ConfigPlugin"].error


class TestPluginRegistrySingleton:
    """Tests for PluginRegistry singleton"""
    
    def test_singleton(self):
        """Test registry is singleton"""
        from recon_cli.plugins import PluginRegistry
        
        registry1 = PluginRegistry()
        registry2 = PluginRegistry()
        
        assert registry1 is registry2
    
    def test_get_registry(self):
        """Test get_registry function"""
        from recon_cli.plugins import get_registry
        
        registry = get_registry()
        assert registry is not None
    
    def test_register_hook(self):
        """Test hook registration"""
        from recon_cli.plugins import PluginRegistry
        
        registry = PluginRegistry()
        
        callback = Mock()
        registry.register_hook("test_event", callback)
        
        assert "test_event" in registry.hooks
        assert callback in registry.hooks["test_event"]
    
    def test_trigger_hook(self):
        """Test hook triggering"""
        from recon_cli.plugins import PluginRegistry
        
        registry = PluginRegistry()
        
        callback = Mock(return_value="result")
        registry.register_hook("trigger_test", callback)
        
        results = registry.trigger_hook("trigger_test", "arg1", key="value")
        
        callback.assert_called_once_with("arg1", key="value")
        assert results == ["result"]


class TestExamplePlugins:
    """Tests for example plugins"""
    
    def test_example_scanner(self):
        """Test ExampleScanner plugin"""
        from recon_cli.plugins import ExampleScanner
        
        plugin = ExampleScanner()
        assert plugin.METADATA.name == "ExampleScanner"
        
        results = plugin.scan("example.com")
        assert len(results) == 1
        assert results[0]["host"] == "example.com"
    
    def test_json_enricher(self):
        """Test JSONEnricher plugin"""
        from recon_cli.plugins import JSONEnricher
        
        plugin = JSONEnricher()
        
        data = {"host": "example.com"}
        enriched = plugin.enrich(data)
        
        assert enriched["host"] == "example.com"
        assert "enriched_at" in enriched
        assert enriched["enriched_by"] == "JSONEnricher"
    
    @patch("requests.request")
    def test_webhook_notifier_success(self, mock_request):
        """Test WebhookNotifier success"""
        from recon_cli.plugins import WebhookNotifier
        
        mock_request.return_value.status_code = 200
        
        plugin = WebhookNotifier({"webhook_url": "http://example.com/hook"})
        result = plugin.send("Test message")
        
        assert result is True
        mock_request.assert_called_once()
    
    @patch("requests.request")
    def test_webhook_notifier_failure(self, mock_request):
        """Test WebhookNotifier failure"""
        from recon_cli.plugins import WebhookNotifier
        
        mock_request.return_value.status_code = 500
        
        plugin = WebhookNotifier({"webhook_url": "http://example.com/hook"})
        result = plugin.send("Test message")
        
        assert result is False
    
    def test_webhook_notifier_no_url(self):
        """Test WebhookNotifier without URL"""
        from recon_cli.plugins import WebhookNotifier
        
        plugin = WebhookNotifier({})  # No webhook_url
        result = plugin.send("Test message")
        
        assert result is False
