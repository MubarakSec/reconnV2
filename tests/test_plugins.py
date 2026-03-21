from pathlib import Path

# Import from plugins package (exports stage plugin loader)
import recon_cli.plugins as plugins_module
from recon_cli.pipeline.stages import Stage


def test_load_stage_plugins(monkeypatch, tmp_path: Path):
    plugin_file = tmp_path / "plugin_stage.py"
    plugin_file.write_text(
        """
from recon_cli.pipeline.stages import Stage

class DemoStage(Stage):
    name = "demo_stage"
    def execute(self, context):
        context.record.metadata.stats["demo_stage_ran"] = True
""",
        encoding="utf-8",
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    monkeypatch.setenv("RECON_PLUGIN_STAGES", "plugin_stage:DemoStage")
    stages = plugins_module.load_stage_plugins()
    assert stages, "Expected plugin stage to load"
    assert isinstance(stages[0], Stage)
    assert getattr(stages[0], "name", "") == "demo_stage"
