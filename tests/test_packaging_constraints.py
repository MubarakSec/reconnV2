from __future__ import annotations

from pathlib import Path
import tomllib

def test_pyproject_requires_python_has_upper_bound():
    data = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    requires_python = data["project"]["requires-python"]
    assert "<3.15" in requires_python
