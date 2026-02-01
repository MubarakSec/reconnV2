# Contributing to ReconnV2 | المساهمة في ReconnV2

<div dir="rtl">

## 🎯 مرحباً بك!

شكراً لاهتمامك بالمساهمة في ReconnV2! نرحب بجميع المساهمات سواء كانت:

- 🐛 إصلاح الأخطاء
- ✨ ميزات جديدة
- 📚 تحسين التوثيق
- 🧪 إضافة اختبارات
- 🔌 إضافات جديدة

</div>

---

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Making Changes](#making-changes)
- [Pull Request Process](#pull-request-process)
- [Style Guidelines](#style-guidelines)
- [Testing](#testing)
- [Plugin Development](#plugin-development)

---

## 📜 Code of Conduct

This project adheres to a Code of Conduct. By participating, you are expected to:

- Be respectful and inclusive
- Accept constructive criticism gracefully
- Focus on what is best for the community
- Show empathy towards other community members

---

## 🚀 Getting Started

### Prerequisites

- Python 3.10+
- Git
- pip or pipx

### Fork and Clone

1. Fork the repository on GitHub
2. Clone your fork locally:

```bash
git clone https://github.com/YOUR_USERNAME/reconnV2.git
cd reconnV2
```

3. Add the upstream remote:

```bash
git remote add upstream https://github.com/ORIGINAL_OWNER/reconnV2.git
```

---

## 🛠️ Development Setup

### Create Virtual Environment

```bash
# Create venv
python -m venv .venv

# Activate (Linux/macOS)
source .venv/bin/activate

# Activate (Windows)
.venv\Scripts\activate
```

### Install Dependencies

```bash
# Install in development mode
pip install -e ".[dev]"

# Or install basic + dev dependencies
pip install -e .
pip install pytest pytest-cov ruff mypy
```

### Verify Installation

```bash
# Check CLI works
recon --help

# Run tests
pytest tests/ -v
```

---

## 📝 Making Changes

### 1. Create a Branch

```bash
# Update main first
git checkout main
git pull upstream main

# Create feature branch
git checkout -b feature/your-feature-name

# Or for bug fixes
git checkout -b fix/bug-description
```

### 2. Branch Naming Convention

| Type | Format | Example |
|------|--------|---------|
| Feature | `feature/description` | `feature/add-shodan-scanner` |
| Bug Fix | `fix/description` | `fix/rate-limiter-crash` |
| Docs | `docs/description` | `docs/api-reference` |
| Test | `test/description` | `test/cache-module` |
| Refactor | `refactor/description` | `refactor/pipeline-stages` |

### 3. Make Your Changes

- Write clean, readable code
- Add comments where necessary
- Update documentation if needed
- Add tests for new features

### 4. Commit Your Changes

```bash
# Stage changes
git add .

# Commit with descriptive message
git commit -m "feat: add Shodan scanner integration"
```

#### Commit Message Format

```
<type>: <description>

[optional body]

[optional footer]
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation
- `style`: Formatting
- `refactor`: Code restructuring
- `test`: Adding tests
- `chore`: Maintenance

**Examples:**
```
feat: add PDF report generation

- Implemented WeasyPrint and ReportLab support
- Added Arabic language support
- Created executive summary generation

Closes #123
```

---

## 🔄 Pull Request Process

### 1. Push Your Branch

```bash
git push origin feature/your-feature-name
```

### 2. Create Pull Request

1. Go to GitHub and create a Pull Request
2. Fill in the PR template
3. Link related issues

### 3. PR Checklist

- [ ] Code follows style guidelines
- [ ] Tests pass locally
- [ ] New tests added for new features
- [ ] Documentation updated
- [ ] Commit messages follow convention
- [ ] No merge conflicts

### 4. Review Process

1. Maintainers will review your PR
2. Address any feedback
3. Once approved, your PR will be merged

---

## 🎨 Style Guidelines

### Python Style

We use **Ruff** for linting and formatting:

```bash
# Check linting
ruff check recon_cli/

# Fix issues automatically
ruff check --fix recon_cli/

# Format code
ruff format recon_cli/
```

### Key Style Rules

```python
# Use type hints
def scan_target(target: str, options: dict[str, Any] | None = None) -> list[dict]:
    ...

# Use dataclasses for data structures
@dataclass
class ScanResult:
    host: str
    ip: str
    status: int

# Use descriptive names
def calculate_vulnerability_score(findings: list[dict]) -> float:
    ...

# Document public functions
def execute_scan(target: str) -> ScanResult:
    """
    Execute security scan on target.
    
    Args:
        target: Domain or IP to scan
        
    Returns:
        ScanResult with findings
        
    Raises:
        ScanError: If scan fails
    """
    ...
```

### Import Order

```python
# 1. Standard library
import json
import logging
from pathlib import Path

# 2. Third-party
import requests
from rich import print

# 3. Local
from recon_cli.config import settings
from recon_cli.utils import helpers
```

---

## 🧪 Testing

### Run Tests

```bash
# All tests
pytest tests/ -v

# With coverage
pytest tests/ --cov=recon_cli --cov-report=html

# Specific test file
pytest tests/test_cache.py -v

# Specific test
pytest tests/test_cache.py::TestMemoryCache::test_get_set -v
```

### Writing Tests

```python
# tests/test_my_feature.py

import pytest
from recon_cli.my_module import MyClass

class TestMyClass:
    """Tests for MyClass"""
    
    def test_basic_functionality(self):
        """Test basic usage"""
        obj = MyClass()
        result = obj.do_something("input")
        assert result == "expected"
    
    def test_error_handling(self):
        """Test error cases"""
        obj = MyClass()
        with pytest.raises(ValueError):
            obj.do_something(None)
    
    @pytest.fixture
    def sample_data(self):
        """Fixture for test data"""
        return {"key": "value"}
    
    def test_with_fixture(self, sample_data):
        """Test using fixture"""
        obj = MyClass()
        result = obj.process(sample_data)
        assert "key" in result
```

### Test Coverage Requirements

- New features should have **>80%** coverage
- Bug fixes should include regression tests

---

## 🔌 Plugin Development

### Creating a Scanner Plugin

```python
# my_scanner.py

from recon_cli.plugins import ScannerPlugin, PluginMetadata, PluginType

class MyScannerPlugin(ScannerPlugin):
    """Custom scanner plugin"""
    
    METADATA = PluginMetadata(
        name="MyScanner",
        version="1.0.0",
        description="My custom security scanner",
        author="Your Name",
        plugin_type=PluginType.SCANNER,
        config_schema={
            "api_key": {"type": "str", "required": True},
            "timeout": {"type": "int", "default": 30}
        },
        tags=["custom", "scanner"]
    )
    
    def scan(self, target: str, options: dict = None) -> list[dict]:
        """
        Perform scan on target.
        
        Args:
            target: Target to scan
            options: Scan options
            
        Returns:
            List of findings
        """
        results = []
        
        # Your scanning logic here
        api_key = self.config.get("api_key")
        timeout = self.config.get("timeout", 30)
        
        # Make API calls, process results
        # ...
        
        results.append({
            "type": "host",
            "host": target,
            "source": "MyScanner",
            "data": {"key": "value"}
        })
        
        return results
```

### Plugin Directory

Place plugins in `~/.recon_cli/plugins/` or `recon_cli/plugins/`.

### Testing Plugins

```python
# tests/test_my_plugin.py

def test_my_scanner():
    from my_scanner import MyScannerPlugin
    
    plugin = MyScannerPlugin({"api_key": "test123"})
    assert plugin.validate_config() is True
    
    results = plugin.scan("example.com")
    assert len(results) > 0
```

---

## 📚 Documentation

### Adding Documentation

1. Update README.md for user-facing changes
2. Add docstrings to all public functions
3. Update DEVELOPMENT_PLAN.md for architectural changes

### Docstring Format

```python
def my_function(param1: str, param2: int = 10) -> dict:
    """
    Brief description of function.
    
    Longer description if needed, explaining the purpose
    and any important details.
    
    Args:
        param1: Description of param1
        param2: Description of param2 (default: 10)
        
    Returns:
        Dictionary containing:
            - key1: Description
            - key2: Description
            
    Raises:
        ValueError: If param1 is empty
        
    Example:
        >>> result = my_function("test", 20)
        >>> print(result)
        {'status': 'success'}
    """
    ...
```

---

## 🆘 Getting Help

- 📖 Read the documentation
- 🔍 Search existing issues
- 💬 Open a new issue for questions
- 📧 Contact maintainers

---

## 🙏 Thank You!

Your contributions make ReconnV2 better for everyone. We appreciate your time and effort!

---

<div align="center">

Made with ❤️ by the ReconnV2 Community

</div>
