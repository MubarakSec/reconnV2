from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Any

from recon_cli import config
from recon_cli.utils.sanitizer import redact

RULES_PATH = config.RECON_HOME / "config" / "rules.json"


def load_rules() -> List[Dict[str, Any]]:
    if not RULES_PATH.exists():
        return []
    try:
        data = json.loads(RULES_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []
    if not isinstance(data, list):
        return []
    return [r for r in data if isinstance(r, dict)]


def apply_rules(entry: Dict[str, object], rules: List[Dict[str, Any]]) -> List[str]:
    tags: List[str] = []
    etype = entry.get("type")
    url = entry.get("url") or ""
    host = entry.get("hostname") or ""
    for rule in rules:
        cond = rule.get("when", {})
        add_tags = rule.get("add_tags", [])
        if not add_tags:
            continue
        if not isinstance(add_tags, list):
            continue
        match = True
        if "url_contains" in cond:
            substr = str(cond["url_contains"])
            if substr and substr not in str(url):
                match = False
        if "host_contains" in cond:
            substr = str(cond["host_contains"])
            if substr and substr not in str(host):
                match = False
        if "type_is" in cond and cond.get("type_is") != etype:
            match = False
        if match:
            tags.extend(add_tags)
    return tags
