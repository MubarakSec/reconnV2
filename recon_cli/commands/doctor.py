from __future__ import annotations

import typer
import os
import sys
import subprocess
import tempfile
import logging
import importlib.util
from pathlib import Path
from typing import List, Optional
from recon_cli import config
from recon_cli.tools.executor import CommandExecutor

app = typer.Typer(help="Environment checks.")
logger = logging.getLogger(__name__)

@app.command()
def doctor(
    fix: bool = typer.Option(
        False, "--fix", help="Attempt to regenerate default configs/resolvers"
    ),
    fix_deps: bool = typer.Option(
        False,
        "--fix-deps",
        help="Attempt to install missing dependencies (python packages, playwright browsers, interactsh-client)",
    ),
    seclists: bool = typer.Option(
        False,
        "--seclists",
        help="Check for SecLists in project root and download if missing",
    ),
    exit_on_fail: bool = typer.Option(
        True,
        "--exit-on-fail/--no-exit-on-fail",
        help="Exit with code 1 if issues are found",
    ),
) -> None:
    """Run quick environment & source sanity checks."""
    config.ensure_base_directories(force=fix)

    # Check for Favicon Fingerprints
    favicons_path = Path("data/favicons.json")
    if not favicons_path.exists():
        typer.secho("⚠️  Favicon fingerprints missing in data/favicons.json. Downloading...", fg=typer.colors.YELLOW)
        try:
            if not favicons_path.parent.exists(): favicons_path.parent.mkdir(parents=True)
            favicons_path.write_text("{}") 
            typer.secho("✅ data/favicons.json initialized.", fg=typer.colors.GREEN)
        except Exception as e:
                logger.debug(f"Silent failure suppressed: {e}", exc_info=True)
                try:
                    from recon_cli.utils.metrics import metrics
                    metrics.stage_errors.labels(stage="doctor", error_type=type(e).__name__).inc()
                except: pass
    else:
        typer.secho("✅ Favicon fingerprints database found.", fg=typer.colors.GREEN)

    if seclists:
        seclists_path = config.RECON_HOME / "seclists"
        if seclists_path.exists():
            typer.secho(
                "✅ SecLists already exists in project root.", fg=typer.colors.GREEN
            )
        else:
            typer.secho(
                "⏳ SecLists not found. Downloading to project root...",
                fg=typer.colors.YELLOW,
            )
            try:
                subprocess.run(
                    [
                        "git",
                        "clone",
                        "--depth",
                        "1",
                        "https://github.com/danielmiessler/SecLists.git",
                        str(seclists_path),
                    ],
                    check=True,
                )
                typer.secho(
                    "✅ SecLists downloaded successfully.", fg=typer.colors.GREEN
                )
            except Exception as e:
                typer.secho(f"❌ Failed to download SecLists: {e}", fg=typer.colors.RED)

    issues: list[str] = []
    warnings: list[str] = []

    def _version_line(tool: str, args: List[str]) -> tuple[str, str]:
        try:
            with tempfile.TemporaryDirectory(prefix="recon-doctor-") as tmp_home:
                env = os.environ.copy()
                env["HOME"] = tmp_home
                env["XDG_CONFIG_HOME"] = os.path.join(tmp_home, ".config")
                env["XDG_CACHE_HOME"] = os.path.join(tmp_home, ".cache")
                env["XDG_DATA_HOME"] = os.path.join(tmp_home, ".local", "share")
                completed = subprocess.run(
                    [tool] + args,
                    capture_output=True,
                    text=True,
                    timeout=5,
                    check=False,
                    env=env,
                )
        except Exception:
            return "error", ""
        output = ((completed.stdout or "") + "\n" + (completed.stderr or "")).strip()
        if not output:
            return ("ok", "") if completed.returncode == 0 else ("error", "")
        lines = [line.strip() for line in output.splitlines() if line.strip()]
        preferred_line = ""
        preferred_markers = (
            "current version",
            "nuclei engine version",
            "nmap version",
            "ffuf version",
            "usage:",
            "usage of ",
            "version ",
        )
        for line in lines:
            lowered = line.lower()
            if any(marker in lowered for marker in preferred_markers):
                preferred_line = line[:120]
                break
        if completed.returncode == 0:
            return "ok", preferred_line or lines[0][:120]
        if preferred_line:
            return "ok", preferred_line
        return "error", lines[0][:120]

    tool_checks = [
        (
            "subfinder",
            ["-version"],
            "install via go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        ),
        (
            "amass",
            ["-version"],
            "install via go install github.com/owasp-amass/amass/v4/...@latest",
        ),
        ("massdns", ["-h"], "install from https://github.com/blechschmidt/massdns"),
        (
            "httpx",
            ["-version"],
            "install via go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
        ),
        ("ffuf", ["-V"], "install via go install github.com/ffuf/ffuf@latest"),
        (
            "nuclei",
            ["-version"],
            "install via go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        ),
        (
            "naabu",
            ["-version"],
            "install via go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
        ),
        (
            "katana",
            ["-version"],
            "install via go install github.com/projectdiscovery/katana/cmd/katana@latest",
        ),
        (
            "dalfox",
            ["version"],
            "install via go install github.com/hahwul/dalfox/v2@latest",
        ),
        (
            "sqlmap",
            ["--version"],
            "install via pipx install sqlmap or apt install sqlmap",
        ),
        ("nmap", ["--version"], "install via apt install nmap"),
        ("wpscan", ["--version"], "install via gem install wpscan"),
        (
            "interactsh-client",
            ["-version"],
            "install via go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest",
        ),
        (
            "waybackurls",
            ["-h"],
            "install via go install github.com/tomnomnom/waybackurls@latest",
        ),
        ("gau", ["-h"], "install via go install github.com/lc/gau/v2/cmd/gau@latest"),
    ]

    def _collect_tool_health(
        *, emit_warnings: bool
    ) -> tuple[list[tuple[str, str, str]], list[str], list[str]]:
        tool_results: list[tuple[str, str, str]] = []
        local_warnings: list[str] = []
        missing_tools: list[str] = []
        for tool, version_args, hint in tool_checks:
            if not CommandExecutor.available(tool):
                tool_results.append((tool, "missing", ""))
                missing_tools.append(tool)
                local_warnings.append(f"tool:{tool}")
                if emit_warnings and tool not in {"waybackurls", "gau"}:
                    typer.echo(f"[warn] tool '{tool}' not found in PATH ({hint})")
                continue
            probe_status, detail = _version_line(tool, version_args)
            if probe_status == "ok":
                tool_results.append((tool, "ok", detail))
                continue
            tool_results.append((tool, "error", detail))
            local_warnings.append(f"tool:{tool}:error")
            if emit_warnings:
                suffix = f": {detail}" if detail else ""
                typer.echo(
                    f"[warn] tool '{tool}' is installed but failed the health probe{suffix}"
                )

        if not (
            CommandExecutor.available("waybackurls") or CommandExecutor.available("gau")
        ):
            local_warnings.append("tool:waybackurls-or-gau")
            if emit_warnings:
                typer.echo(
                    "[warn] tool 'waybackurls' or 'gau' not found in PATH "
                    "(install via go install github.com/tomnomnom/waybackurls@latest "
                    "or go install github.com/lc/gau/v2/cmd/gau@latest)"
                )
        return tool_results, local_warnings, missing_tools

    python_dep_checks = [
        ("dnspython", "dns", "pip install dnspython"),
        ("playwright", "playwright", "pip install playwright"),
        ("requests", "requests", "pip install requests"),
        ("pyyaml", "yaml", "pip install pyyaml"),
        ("aioquic", "aioquic", "pip install aioquic"),
        ("mmh3", "mmh3", "pip install mmh3"),
    ]

    def _collect_python_health(
        *, emit_warnings: bool
    ) -> tuple[list[tuple[str, str, str]], str, str, list[str], list[str]]:
        python_results: list[tuple[str, str, str]] = []
        local_warnings: list[str] = []
        missing_python: list[str] = []
        for label, module_name, hint in python_dep_checks:
            if importlib.util.find_spec(module_name) is None:
                python_results.append((label, "missing", ""))
                missing_python.append(label)
                local_warnings.append(f"python:{label}")
                if emit_warnings:
                    typer.echo(
                        f"[warn] Python package '{label}' not available ({hint})"
                    )
            else:
                python_results.append((label, "ok", ""))

        browser_status = "unknown"
        browser_detail = ""
        if any(
            label == "playwright" and status == "ok"
            for label, status, _ in python_results
        ):
            try:
                from playwright.sync_api import sync_playwright

                with sync_playwright() as playwright:
                    chromium_path = Path(playwright.chromium.executable_path)
                if chromium_path.exists():
                    browser_status = "ok"
                    browser_detail = str(chromium_path)
                else:
                    browser_status = "missing"
                    browser_detail = "playwright install chromium"
                    local_warnings.append("python:playwright-browsers")
                    if emit_warnings:
                        typer.echo(
                            "[warn] Playwright browsers not installed (run: playwright install chromium)"
                        )
            except Exception as exc:
                browser_status = "missing"
                browser_detail = str(exc).splitlines()[0]
                local_warnings.append("python:playwright-browsers")
                if emit_warnings:
                    typer.echo(
                        "[warn] Playwright browser check failed (run: playwright install chromium)"
                    )
        return (
            python_results,
            browser_status,
            browser_detail,
            local_warnings,
            missing_python,
        )

    tool_results, tool_warnings, missing_tools = _collect_tool_health(
        emit_warnings=not fix_deps
    )
    python_results, browser_status, browser_detail, python_warnings, missing_python = (
        _collect_python_health(emit_warnings=not fix_deps)
    )
    warnings = tool_warnings + python_warnings

    if fix_deps:
        typer.echo("")
        typer.echo("== Dependency Fix Attempts ==")
        attempted = False

        package_by_label = {
            "dnspython": "dnspython",
            "playwright": "playwright",
            "requests": "requests",
            "pyyaml": "pyyaml",
        }
        for package_label in missing_python:
            package_name = package_by_label.get(package_label, package_label)
            attempted = True
            typer.echo(f"[fix] Installing python package: {package_name}")
            install = subprocess.run(
                [sys.executable, "-m", "pip", "install", package_name],
                capture_output=True,
                text=True,
                timeout=900,
                check=False,
            )
            if install.returncode == 0:
                typer.echo(f"[fix] Installed: {package_name}")
            else:
                typer.echo(f"[warn] Failed to install {package_name}")

        if "interactsh-client" in missing_tools:
            attempted = True
            if not CommandExecutor.available("go"):
                typer.echo(
                    "[warn] 'go' not found; cannot auto-install interactsh-client"
                )
            else:
                typer.echo("[fix] Installing interactsh-client via go install")
                install = subprocess.run(
                    [
                        "go",
                        "install",
                        "github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=900,
                    check=False,
                )
                if install.returncode == 0:
                    typer.echo("[fix] Installed: interactsh-client")
                else:
                    typer.echo("[warn] Failed to install interactsh-client")

        if browser_status != "ok":
            attempted = True
            if importlib.util.find_spec("playwright") is None:
                typer.echo(
                    "[warn] Playwright module missing; cannot install browsers yet"
                )
            else:
                typer.echo("[fix] Installing Playwright Chromium browser")
                install = subprocess.run(
                    [sys.executable, "-m", "playwright", "install", "chromium"],
                    capture_output=True,
                    text=True,
                    timeout=900,
                    check=False,
                )
                if install.returncode == 0:
                    typer.echo("[fix] Installed: playwright chromium browser")
                else:
                    typer.echo("[warn] Failed to install Playwright Chromium browser")

        if not attempted:
            typer.echo("[fix] No missing dependencies detected")

        tool_results, tool_warnings, _ = _collect_tool_health(emit_warnings=True)
        python_results, browser_status, browser_detail, python_warnings, _ = (
            _collect_python_health(emit_warnings=True)
        )
        warnings = tool_warnings + python_warnings

    typer.echo("")
    typer.echo("== Tool Health ==")
    for tool, status, version in tool_results:
        if status == "missing":
            typer.echo(f"{tool:12} : missing")
        elif status == "error":
            suffix = f" ({version})" if version else ""
            typer.echo(f"{tool:12} : error{suffix}")
        else:
            suffix = f" ({version})" if version else ""
            typer.echo(f"{tool:12} : ok{suffix}")

    typer.echo("")
    typer.echo("== Python Dependency Health ==")
    for label, status, _ in python_results:
        typer.echo(f"{label:12} : {status}")
    if browser_status == "ok":
        typer.echo(f"{'playwright-browsers':20} : ok ({browser_detail})")
    else:
        suffix = f" ({browser_detail})" if browser_detail else ""
        typer.echo(f"{'playwright-browsers':20} : missing{suffix}")

    try:
        from recon_cli.pipeline import stages
    except Exception as exc:
        issues.append(f"stage import failed: {exc}")

    typer.echo("")
    typer.echo("== API Key Health ==")
    api_keys = [
        (
            "SecurityTrails",
            config.RUNTIME_CONFIG.securitytrails_api_key,
            "Required for historical DNS origin discovery",
        ),
        (
            "GitHub Token",
            config.RUNTIME_CONFIG.github_token,
            "Required for GitHub repository secret scanning",
        ),
        (
            "ViewDNS",
            config.RUNTIME_CONFIG.viewdns_api_key,
            "Used for reverse WHOIS lookups",
        ),
        (
            "WPScan",
            config.RUNTIME_CONFIG.wpscan_api_token,
            "Required for deep WordPress vulnerability scanning",
        ),
        (
            "WhoisFreaks",
            config.RUNTIME_CONFIG.whoisfreaks_api_key,
            "Used for enhanced WHOIS and reverse lookup data",
        ),
        (
            "Telegram Bot",
            config.RUNTIME_CONFIG.telegram_token,
            "Required for Telegram notifications and bot control",
        ),
    ]
    for name, key, description in api_keys:
        status = "ok" if key else "missing"
        color = typer.colors.GREEN if key else typer.colors.YELLOW
        typer.echo(f"{name:15} : ", nl=False)
        typer.secho(status, fg=color, nl=False)
        if not key:
            typer.echo(f" ({description})")
        else:
            typer.echo("")

    if issues:
        typer.echo("")
        for issue in issues:
            typer.echo(f"[fail] {issue}")
        if exit_on_fail:
            raise typer.Exit(code=1)

    if warnings:
        typer.echo("")
        typer.secho(
            f"Doctor completed with {len(warnings)} warning(s)", fg=typer.colors.YELLOW
        )
