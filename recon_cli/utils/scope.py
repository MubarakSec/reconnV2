from __future__ import annotations

import json
import re
from pathlib import Path
from typing import List, Optional, Set, Dict, Any
from urllib.parse import urlparse


class ScopeManager:
    """
    Manages scan scope, including inclusions, exclusions, and wildcard patterns.
    Supports HackerOne and Bugcrowd JSON formats.
    """

    def __init__(
        self,
        include_patterns: Optional[List[str]] = None,
        exclude_patterns: Optional[List[str]] = None,
    ):
        self.include_rules = self._compile_rules(include_patterns or [])
        self.exclude_rules = self._compile_rules(exclude_patterns or [])

    def _compile_rules(self, patterns: List[str]) -> List[re.Pattern]:
        rules = []
        for p in patterns:
            p = p.strip()
            if not p:
                continue
            # Convert wildcard *.example.com to regex
            # We want to match example.com and anything ending in .example.com
            regex_str = re.escape(p).replace(r"\*", ".*")
            if p.startswith("*."):
                # Special case for *.domain.com to also match domain.com
                base_domain = re.escape(p[2:])
                regex_str = rf"^(.*\.)?{base_domain}$"
            else:
                regex_str = f"^{regex_str}$"
            rules.append(re.compile(regex_str, re.IGNORECASE))
        return rules

    def is_allowed(self, target: str) -> bool:
        """
        Check if a hostname or URL is allowed by the scope.
        """
        if not target:
            return False

        # Extract hostname if target is a URL
        hostname = target
        if "://" in target:
            try:
                hostname = urlparse(target).hostname or target
            except ValueError:
                pass
        
        hostname = hostname.lower().strip()

        # 1. Check exclusions (highest priority)
        for rule in self.exclude_rules:
            if rule.match(hostname):
                return False

        # 2. If no include rules, everything not excluded is allowed
        if not self.include_rules:
            return True

        # 3. Check inclusions
        for rule in self.include_rules:
            if rule.match(hostname):
                return True

        return False

    @classmethod
    def from_file(cls, file_path: Path) -> ScopeManager:
        """
        Parse a scope file. Supports:
        - Plain text (one pattern per line)
        - HackerOne JSON
        - Bugcrowd JSON
        """
        if not file_path.exists():
            return cls()

        content = file_path.read_text(encoding="utf-8").strip()
        if not content:
            return cls()

        include_patterns: List[str] = []
        exclude_patterns: List[str] = []

        # Try parsing as JSON first
        try:
            data = json.loads(content)
            if isinstance(data, dict):
                # HackerOne format
                if "targets" in data and isinstance(data["targets"], list):
                    # Some H1 exports have a 'targets' key
                    for t in data["targets"]:
                        p = t.get("identifier")
                        if not p: continue
                        if t.get("instruction") == "out-of-scope":
                            exclude_patterns.append(p)
                        else:
                            include_patterns.append(p)
                # Alternative H1/Bugcrowd or custom formats
                elif "in_scope" in data or "out_of_scope" in data:
                    in_scope = data.get("in_scope", [])
                    out_scope = data.get("out_of_scope", [])
                    for item in in_scope:
                        p = item.get("identifier") or item.get("target") or item.get("endpoint")
                        if p: include_patterns.append(p)
                    for item in out_scope:
                        p = item.get("identifier") or item.get("target") or item.get("endpoint")
                        if p: exclude_patterns.append(p)
                elif "targets" in data and isinstance(data["targets"], dict):
                    # Bugcrowd specific sometimes
                    in_scope = data["targets"].get("in_scope", [])
                    out_scope = data["targets"].get("out_of_scope", [])
                    for item in in_scope:
                        p = item.get("target")
                        if p: include_patterns.append(p)
                    for item in out_scope:
                        p = item.get("target")
                        if p: exclude_patterns.append(p)
            elif isinstance(data, list):
                # Simple list of patterns
                include_patterns.extend([str(item) for item in data])
        except json.JSONDecodeError:
            # Fallback to plain text
            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if line.startswith("!"):
                    exclude_patterns.append(line[1:])
                else:
                    include_patterns.append(line)

        return cls(include_patterns, exclude_patterns)
