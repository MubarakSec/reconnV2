# ReconnV2 Plugin Development Guide | دليل تطوير الإضافات

<div dir="rtl">

## 📋 نظرة عامة

هذا الدليل يشرح كيفية إنشاء إضافات مخصصة لـ ReconnV2. نظام الإضافات يسمح بتوسيع وظائف الأداة بسهولة.

</div>

---

## 🔌 Plugin Types

ReconnV2 supports four plugin types:

| Type | Class | Purpose |
|------|-------|---------|
| Scanner | `ScannerPlugin` | Custom scanning tools |
| Enricher | `EnricherPlugin` | Data enrichment |
| Reporter | `ReporterPlugin` | Report formats |
| Notifier | `NotifierPlugin` | Notification channels |

---

## 📁 Plugin Directory

Place your plugins in one of these locations:

```
~/.recon_cli/plugins/           # User plugins
recon_cli/plugins/              # Built-in plugins
```

---

## 🏗️ Plugin Structure

### Basic Plugin Template

```python
from recon_cli.plugins import (
    PluginInterface,
    PluginMetadata,
    PluginType,
    PluginResult
)

class MyPlugin(PluginInterface):
    """My custom plugin"""
    
    METADATA = PluginMetadata(
        name="MyPlugin",
        version="1.0.0",
        description="Description of my plugin",
        author="Your Name",
        plugin_type=PluginType.PROCESSOR,
        dependencies=["requests"],
        config_schema={
            "api_key": {"type": "str", "required": True},
            "timeout": {"type": "int", "default": 30}
        },
        tags=["custom", "example"]
    )
    
    def execute(self, context: dict) -> PluginResult:
        """Execute plugin logic"""
        try:
            # Your logic here
            result_data = self._do_work(context)
            
            return PluginResult(
                success=True,
                data=result_data,
                execution_time=1.5
            )
        except Exception as e:
            return PluginResult(
                success=False,
                error=str(e)
            )
    
    def _do_work(self, context):
        # Implementation
        pass
```

---

## 🔍 Scanner Plugin

### Template

```python
from recon_cli.plugins import ScannerPlugin, PluginMetadata, PluginType

class MyScannerPlugin(ScannerPlugin):
    """Custom security scanner"""
    
    METADATA = PluginMetadata(
        name="MyScanner",
        version="1.0.0",
        description="Custom security scanner using XYZ API",
        author="Your Name",
        plugin_type=PluginType.SCANNER,
        config_schema={
            "api_key": {"type": "str", "required": True},
            "rate_limit": {"type": "int", "default": 10}
        },
        tags=["scanner", "api"]
    )
    
    def scan(self, target: str, options: dict = None) -> list[dict]:
        """
        Perform scan on target.
        
        Args:
            target: Domain/IP to scan
            options: Additional scan options
            
        Returns:
            List of discovered items
        """
        results = []
        options = options or {}
        
        api_key = self.config.get("api_key")
        rate_limit = self.config.get("rate_limit", 10)
        
        # Make API request
        import requests
        response = requests.get(
            f"https://api.example.com/scan",
            params={"target": target},
            headers={"X-API-Key": api_key},
            timeout=30
        )
        
        if response.status_code == 200:
            data = response.json()
            
            for item in data.get("results", []):
                results.append({
                    "type": "host",
                    "host": item["hostname"],
                    "ip": item.get("ip"),
                    "source": "MyScanner",
                    "data": item
                })
        
        return results
```

### Usage

```python
# In code
plugin = MyScannerPlugin({"api_key": "xxx"})
results = plugin.scan("example.com")

# Via CLI
recon run-plugin MyScanner --target example.com
```

---

## 🔄 Enricher Plugin

### Template

```python
from recon_cli.plugins import EnricherPlugin, PluginMetadata, PluginType

class GeoIPEnricher(EnricherPlugin):
    """Enrich hosts with geolocation data"""
    
    METADATA = PluginMetadata(
        name="GeoIPEnricher",
        version="1.0.0",
        description="Add geolocation info to hosts",
        author="Your Name",
        plugin_type=PluginType.ENRICHER,
        tags=["enricher", "geoip"]
    )
    
    def enrich(self, data: dict) -> dict:
        """
        Enrich data with additional information.
        
        Args:
            data: Data to enrich (e.g., host info)
            
        Returns:
            Enriched data
        """
        enriched = data.copy()
        
        ip = data.get("ip")
        if ip:
            # Lookup geolocation
            geo = self._lookup_ip(ip)
            enriched["geo"] = geo
        
        enriched["enriched_by"] = self.METADATA.name
        enriched["enriched_at"] = datetime.now().isoformat()
        
        return enriched
    
    def _lookup_ip(self, ip: str) -> dict:
        """Lookup IP geolocation"""
        import requests
        
        try:
            response = requests.get(
                f"https://ipapi.co/{ip}/json/",
                timeout=10
            )
            if response.status_code == 200:
                return response.json()
        except:
            pass
        
        return {}
```

---

## 📄 Reporter Plugin

### Template

```python
from pathlib import Path
from recon_cli.plugins import ReporterPlugin, PluginMetadata, PluginType

class MarkdownReporter(ReporterPlugin):
    """Generate Markdown reports"""
    
    METADATA = PluginMetadata(
        name="MarkdownReporter",
        version="1.0.0",
        description="Generate Markdown format reports",
        author="Your Name",
        plugin_type=PluginType.REPORTER,
        config_schema={
            "include_toc": {"type": "bool", "default": True}
        },
        tags=["reporter", "markdown"]
    )
    
    def generate_report(
        self,
        job_data: dict,
        results: list[dict],
        output_path: Path
    ) -> Path:
        """
        Generate report file.
        
        Args:
            job_data: Job metadata
            results: Scan results
            output_path: Output file path
            
        Returns:
            Path to generated report
        """
        target = job_data.get("target", "Unknown")
        
        # Build markdown content
        lines = [
            f"# Security Report: {target}",
            "",
            f"**Date:** {job_data.get('created_at', 'N/A')}",
            f"**Profile:** {job_data.get('profile', 'N/A')}",
            "",
        ]
        
        # Add table of contents
        if self.config.get("include_toc", True):
            lines.extend([
                "## Table of Contents",
                "- [Hosts](#hosts)",
                "- [Vulnerabilities](#vulnerabilities)",
                "",
            ])
        
        # Hosts section
        hosts = [r for r in results if r.get("type") == "host"]
        lines.extend([
            "## Hosts",
            "",
            f"Found **{len(hosts)}** hosts.",
            "",
            "| Host | IP | Status |",
            "|------|----|----|",
        ])
        
        for host in hosts:
            lines.append(
                f"| {host.get('host', 'N/A')} | "
                f"{host.get('ip', 'N/A')} | "
                f"{host.get('status_code', '-')} |"
            )
        
        # Vulnerabilities section
        vulns = [r for r in results if r.get("type") == "vulnerability"]
        lines.extend([
            "",
            "## Vulnerabilities",
            "",
            f"Found **{len(vulns)}** vulnerabilities.",
            "",
        ])
        
        for vuln in vulns:
            severity = vuln.get("severity", "info").upper()
            lines.extend([
                f"### [{severity}] {vuln.get('name', 'Unknown')}",
                "",
                f"- **Host:** {vuln.get('host', 'N/A')}",
                f"- **Template:** {vuln.get('template_id', 'N/A')}",
                "",
            ])
        
        # Write file
        content = "\n".join(lines)
        output_path = Path(output_path)
        output_path.write_text(content, encoding="utf-8")
        
        return output_path
```

---

## 📢 Notifier Plugin

### Template

```python
from recon_cli.plugins import NotifierPlugin, PluginMetadata, PluginType

class MattermostNotifier(NotifierPlugin):
    """Send notifications to Mattermost"""
    
    METADATA = PluginMetadata(
        name="MattermostNotifier",
        version="1.0.0",
        description="Mattermost webhook notifications",
        author="Your Name",
        plugin_type=PluginType.NOTIFIER,
        config_schema={
            "webhook_url": {"type": "str", "required": True},
            "channel": {"type": "str", "default": "security"},
            "username": {"type": "str", "default": "ReconnV2"}
        },
        tags=["notifier", "mattermost"]
    )
    
    def send(self, message: str, **kwargs) -> bool:
        """
        Send notification.
        
        Args:
            message: Message to send
            **kwargs: Additional options
            
        Returns:
            True if sent successfully
        """
        import requests
        
        webhook_url = self.config.get("webhook_url")
        if not webhook_url:
            return False
        
        payload = {
            "channel": self.config.get("channel", "security"),
            "username": self.config.get("username", "ReconnV2"),
            "text": message,
            "icon_emoji": ":shield:"
        }
        
        # Add attachments if provided
        if "attachments" in kwargs:
            payload["attachments"] = kwargs["attachments"]
        
        try:
            response = requests.post(
                webhook_url,
                json=payload,
                timeout=30
            )
            return response.status_code == 200
        except Exception as e:
            self.logger.error(f"Failed to send: {e}")
            return False
```

---

## ⚙️ Configuration Schema

Define configuration options using `config_schema`:

```python
config_schema = {
    # Required string
    "api_key": {
        "type": "str",
        "required": True,
        "description": "API key for authentication"
    },
    
    # Optional integer with default
    "timeout": {
        "type": "int",
        "default": 30,
        "description": "Request timeout in seconds"
    },
    
    # Boolean option
    "verify_ssl": {
        "type": "bool",
        "default": True
    },
    
    # List option
    "tags": {
        "type": "list",
        "default": []
    }
}
```

---

## 🔄 Lifecycle Methods

### Initialize

```python
def initialize(self) -> bool:
    """Called when plugin is loaded"""
    # Setup connections, validate config, etc.
    try:
        self._client = APIClient(self.config["api_key"])
        self._initialized = True
        return True
    except Exception as e:
        self.logger.error(f"Init failed: {e}")
        return False
```

### Cleanup

```python
def cleanup(self) -> None:
    """Called when plugin is unloaded"""
    if hasattr(self, "_client"):
        self._client.close()
    self._initialized = False
```

### Validate Config

```python
def validate_config(self) -> bool:
    """Validate configuration"""
    if not self.config.get("api_key"):
        self.logger.error("API key is required")
        return False
    
    if self.config.get("timeout", 30) < 1:
        self.logger.error("Timeout must be positive")
        return False
    
    return True
```

---

## 🧪 Testing Plugins

### Unit Tests

```python
# tests/test_my_plugin.py

import pytest
from unittest.mock import patch, Mock

class TestMyScanner:
    """Tests for MyScanner plugin"""
    
    def test_initialization(self):
        """Test plugin initializes correctly"""
        from my_plugin import MyScannerPlugin
        
        plugin = MyScannerPlugin({"api_key": "test123"})
        assert plugin.validate_config() is True
    
    def test_missing_config(self):
        """Test fails with missing config"""
        from my_plugin import MyScannerPlugin
        
        plugin = MyScannerPlugin({})
        assert plugin.validate_config() is False
    
    @patch("requests.get")
    def test_scan_success(self, mock_get):
        """Test successful scan"""
        from my_plugin import MyScannerPlugin
        
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = {
            "results": [{"hostname": "sub.example.com", "ip": "1.2.3.4"}]
        }
        
        plugin = MyScannerPlugin({"api_key": "test123"})
        results = plugin.scan("example.com")
        
        assert len(results) == 1
        assert results[0]["host"] == "sub.example.com"
    
    @patch("requests.get")
    def test_scan_error(self, mock_get):
        """Test scan handles errors"""
        from my_plugin import MyScannerPlugin
        
        mock_get.return_value.status_code = 500
        
        plugin = MyScannerPlugin({"api_key": "test123"})
        results = plugin.scan("example.com")
        
        assert results == []
```

### Run Tests

```bash
pytest tests/test_my_plugin.py -v
```

---

## 📦 Packaging

### Plugin Package Structure

```
my_scanner_plugin/
├── __init__.py
├── scanner.py
├── requirements.txt
├── README.md
└── tests/
    └── test_scanner.py
```

### `__init__.py`

```python
from .scanner import MyScannerPlugin

__all__ = ["MyScannerPlugin"]
```

### `requirements.txt`

```
requests>=2.28.0
```

---

## 🔗 Registry & Hooks

### Using the Registry

```python
from recon_cli.plugins import get_registry

registry = get_registry()
registry.setup()

# List all plugins
scanners = registry.get_scanners()
for meta in scanners:
    print(f"{meta.name} v{meta.version}")

# Run a scanner
result = registry.run_scanner("MyScanner", "example.com")
```

### Event Hooks

```python
# Register a hook
registry.register_hook("scan.completed", my_callback)

def my_callback(job_id, results):
    """Called when scan completes"""
    print(f"Job {job_id} completed with {len(results)} results")

# Trigger hooks (internal)
registry.trigger_hook("scan.completed", job_id, results)
```

### Available Events

| Event | Arguments |
|-------|-----------|
| `scan.started` | `job_id, target` |
| `scan.completed` | `job_id, results` |
| `scan.failed` | `job_id, error` |
| `vulnerability.found` | `job_id, vuln` |
| `secret.found` | `job_id, secret` |

---

## 📝 Best Practices

### 1. Error Handling

```python
def scan(self, target, options=None):
    try:
        results = self._perform_scan(target)
        return results
    except requests.Timeout:
        self.logger.warning(f"Timeout scanning {target}")
        return []
    except Exception as e:
        self.logger.error(f"Scan error: {e}")
        return []
```

### 2. Rate Limiting

```python
import time

def scan(self, target, options=None):
    rate_limit = self.config.get("rate_limit", 10)
    delay = 1.0 / rate_limit
    
    results = []
    for item in items_to_scan:
        result = self._scan_item(item)
        results.append(result)
        time.sleep(delay)  # Respect rate limit
    
    return results
```

### 3. Logging

```python
def scan(self, target, options=None):
    self.logger.info(f"Starting scan: {target}")
    self.logger.debug(f"Options: {options}")
    
    # ... scan logic ...
    
    self.logger.info(f"Completed: {len(results)} results")
    return results
```

### 4. Configuration Validation

```python
def validate_config(self) -> bool:
    # Check required fields
    if not self.config.get("api_key"):
        self.logger.error("api_key is required")
        return False
    
    # Validate format
    api_key = self.config["api_key"]
    if len(api_key) < 20:
        self.logger.error("api_key seems invalid")
        return False
    
    return True
```

---

<div align="center">

Made with ❤️ for Security Researchers

</div>
