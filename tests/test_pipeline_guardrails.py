from __future__ import annotations

import ast
from pathlib import Path


def _source_files() -> list[Path]:
    root = Path(__file__).resolve().parents[1] / "recon_cli"
    return sorted(path for path in root.rglob("*.py") if path.is_file())


def test_all_recon_modules_are_syntax_valid():
    errors: list[str] = []
    for path in _source_files():
        source = path.read_text(encoding="utf-8")
        try:
            ast.parse(source, filename=str(path))
        except SyntaxError as exc:
            errors.append(f"{path}: {exc.msg} (line {exc.lineno})")

    assert not errors, "Syntax errors found:\n" + "\n".join(errors)


def test_no_duplicate_top_level_class_names_per_file():
    duplicates: list[str] = []
    for path in _source_files():
        source = path.read_text(encoding="utf-8")
        module = ast.parse(source, filename=str(path))
        class_lines: dict[str, list[int]] = {}
        for node in module.body:
            if isinstance(node, ast.ClassDef):
                class_lines.setdefault(node.name, []).append(node.lineno)

        for class_name, lines in class_lines.items():
            if len(lines) > 1:
                duplicates.append(f"{path}: class {class_name} defined at {lines}")

    assert not duplicates, "Duplicate top-level classes found:\n" + "\n".join(duplicates)
