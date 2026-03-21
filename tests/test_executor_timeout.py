import subprocess
import sys

import pytest

from recon_cli.tools.executor import CommandExecutor, CommandError


class DummyLogger:
    def info(self, *a, **k): ...
    def error(self, *a, **k): ...
    def warning(self, *a, **k): ...


def test_command_executor_timeout():
    executor = CommandExecutor(DummyLogger())
    with pytest.raises(CommandError):
        executor.run(
            [subprocess.sys.executable, "-c", "import time; time.sleep(2)"], timeout=1
        )


def test_command_executor_handles_non_utf8_stderr_bytes():
    executor = CommandExecutor(DummyLogger())
    result = executor.run(
        [
            sys.executable,
            "-c",
            "import sys; sys.stderr.buffer.write(b'\\xff\\xfe\\x98\\n')",
        ],
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0
    assert isinstance(result.stderr, str)
