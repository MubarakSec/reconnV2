from __future__ import annotations

import shlex
import shutil
import subprocess
from pathlib import Path
from typing import Iterable, Mapping, Optional

from recon_cli.utils.sanitizer import redact as redact_text


class CommandError(RuntimeError):
    def __init__(self, message: str, returncode: int | None = None) -> None:
        super().__init__(message)
        self.returncode = returncode


class CommandExecutor:
    def __init__(self, logger) -> None:
        self.logger = logger

    @staticmethod
    def available(command: str) -> bool:
        return shutil.which(command) is not None

    def run(
        self,
        command: Iterable[str],
        cwd: Optional[Path] = None,
        env: Optional[Mapping[str, str]] = None,
        timeout: Optional[int] = None,
        check: bool = True,
        capture_output: bool = False,
        redact: bool = True,
    ) -> subprocess.CompletedProcess:
        cmd_list = [str(part) for part in command]
        command_str = " ".join(shlex.quote(part) for part in cmd_list)
        message = redact_text(command_str) if redact else command_str
        self.logger.info("Executing: %s", message)
        try:
            completed = subprocess.run(
                cmd_list,
                cwd=str(cwd) if cwd else None,
                env=dict(env) if env else None,
                timeout=timeout,
                capture_output=capture_output,
                text=True,
                check=check,
            )
        except FileNotFoundError as exc:
            missing = redact_text(cmd_list[0]) if redact else cmd_list[0]
            self.logger.error("Command not found: %s", missing)
            raise CommandError(f"Command not found: {cmd_list[0]}") from exc
        except subprocess.CalledProcessError as exc:
            if capture_output:
                stderr_text = exc.stderr or ""
                if redact:
                    stderr_text = redact_text(stderr_text) or ""
                self.logger.error("Command failed (%s): %s", exc.returncode, stderr_text)
            else:
                self.logger.error("Command failed (%s)", exc.returncode)
            if check:
                raise CommandError(f"Command failed ({exc.returncode})", exc.returncode) from exc
            completed = exc
        return completed

    def run_to_file(
        self,
        command: Iterable[str],
        output_path: Path,
        cwd: Optional[Path] = None,
        env: Optional[Mapping[str, str]] = None,
        redact: bool = True,
    ) -> subprocess.CompletedProcess:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        completed = subprocess.run(
            [str(part) for part in command],
            cwd=str(cwd) if cwd else None,
            env=dict(env) if env else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
        )
        output = completed.stdout or ""
        if redact:
            output = redact_text(output) or ""
        completed.stdout = output
        with output_path.open("w", encoding="utf-8") as handle:
            handle.write(output)
        if completed.returncode != 0:
            self.logger.warning("Command exited with %s (non-zero)", completed.returncode)
        return completed
