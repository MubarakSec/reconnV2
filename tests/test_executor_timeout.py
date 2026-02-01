import subprocess

import pytest

from recon_cli.tools.executor import CommandExecutor, CommandError


class DummyLogger:
    def info(self, *a, **k): ...
    def error(self, *a, **k): ...
    def warning(self, *a, **k): ...


def test_command_executor_timeout():
    executor = CommandExecutor(DummyLogger())
    with pytest.raises(CommandError):
        executor.run([subprocess.sys.executable, "-c", "import time; time.sleep(2)"], timeout=1)
