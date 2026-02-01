from pathlib import Path

from recon_cli import rules as rules_engine
from recon_cli.pipeline.stages import ScoringStage
from recon_cli.utils import fs


def test_apply_rules_adds_tags(tmp_path: Path, monkeypatch):
    rules_path = tmp_path / "rules.json"
    rules_path.write_text(
        '[{"when":{"url_contains":"admin"},"add_tags":["custom:admin"]},{"when":{"host_contains":"api"},"add_tags":["custom:api"]}]',
        encoding="utf-8",
    )
    monkeypatch.setattr(rules_engine, "RULES_PATH", rules_path)
    rules = rules_engine.load_rules()
    entry = {"type": "url", "url": "https://example.com/admin", "hostname": "api.example.com"}
    tags = rules_engine.apply_rules(entry, rules)
    assert "custom:admin" in tags
    assert "custom:api" in tags


def test_scoring_stage_applies_rules(monkeypatch, tmp_path: Path):
    rules_path = tmp_path / "rules.json"
    rules_path.write_text('[{"when":{"url_contains":"admin"},"add_tags":["custom:admin"]}]', encoding="utf-8")
    monkeypatch.setattr(rules_engine, "RULES_PATH", rules_path)
    stage = ScoringStage()
    stage.rules = rules_engine.load_rules()
    # Build minimal context stub
    class DummyManager:
        def update_metadata(self, record): ...
    class DummyPaths:
        def __init__(self, root):
            self.root = root
        @property
        def results_jsonl(self): return self.root / "results.jsonl"
        def artifact(self, name): return self.root / name
    class DummyRecord:
        def __init__(self, root):
            self.paths = DummyPaths(root)
            self.metadata = type("M", (), {"stats": {}})()
    root = tmp_path / "job"
    root.mkdir()
    record = DummyRecord(root)
    record.paths.results_jsonl.write_text('{"type":"url","url":"https://ex.com/admin","hostname":"ex.com","tags":[]}\n', encoding="utf-8")
    context = type("Ctx", (), {"record": record, "manager": DummyManager(), "logger": type("L", (), {"info": lambda *a, **k: None})(), "runtime_config": type("RC", (), {})()})()
    stage.execute(context)
    entries = (root / "results.jsonl").read_text(encoding="utf-8")
    assert "custom:admin" in entries
