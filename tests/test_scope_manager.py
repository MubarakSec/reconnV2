from __future__ import annotations

import json
from pathlib import Path
from recon_cli.utils.scope import ScopeManager

def test_scope_manager_wildcards():
    manager = ScopeManager(include_patterns=["*.example.com", "target.org"])
    assert manager.is_allowed("example.com")
    assert manager.is_allowed("sub.example.com")
    assert manager.is_allowed("deep.sub.example.com")
    assert manager.is_allowed("target.org")
    assert not manager.is_allowed("other.com")

def test_scope_manager_exclusions():
    manager = ScopeManager(
        include_patterns=["*.example.com"],
        exclude_patterns=["!out.example.com", "dev.example.com"]
    )
    # The ! prefix was handled in from_file, but direct constructor takes clean patterns
    manager = ScopeManager(
        include_patterns=["*.example.com"],
        exclude_patterns=["out.example.com", "dev.example.com"]
    )
    assert manager.is_allowed("example.com")
    assert manager.is_allowed("www.example.com")
    assert not manager.is_allowed("out.example.com")
    assert not manager.is_allowed("dev.example.com")

def test_scope_manager_h1_json(tmp_path: Path):
    h1_data = {
        "targets": [
            {"identifier": "*.in-scope.com", "instruction": "in-scope"},
            {"identifier": "out-of-scope.com", "instruction": "out-of-scope"}
        ]
    }
    scope_file = tmp_path / "scope.json"
    scope_file.write_text(json.dumps(h1_data))
    
    manager = ScopeManager.from_file(scope_file)
    assert manager.is_allowed("in-scope.com")
    assert manager.is_allowed("sub.in-scope.com")
    assert not manager.is_allowed("out-of-scope.com")
    assert not manager.is_allowed("random.com")

def test_scope_manager_plain_text(tmp_path: Path):
    content = "*.example.com\n!secret.example.com\n"
    scope_file = tmp_path / "scope.txt"
    scope_file.write_text(content)
    
    manager = ScopeManager.from_file(scope_file)
    assert manager.is_allowed("example.com")
    assert manager.is_allowed("www.example.com")
    assert not manager.is_allowed("secret.example.com")
