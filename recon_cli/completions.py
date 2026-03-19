"""
Shell Completion Scripts for ReconnV2 CLI.

Provides auto-completion for:
- Bash
- Zsh
- Fish
- PowerShell

Example:
    # Bash
    $ recon --install-completion bash

    # Zsh
    $ recon --install-completion zsh

    # Fish
    $ recon --install-completion fish
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Callable

__all__ = [
    "Shell",
    "CompletionGenerator",
    "CompletionInstaller",
    "get_shell",
    "install_completion",
    "generate_completion",
]


class Shell(Enum):
    """Supported shell types."""

    BASH = "bash"
    ZSH = "zsh"
    FISH = "fish"
    POWERSHELL = "powershell"


@dataclass
class Command:
    """CLI command definition for completion."""

    name: str
    description: str
    subcommands: List["Command"] = None
    options: List["Option"] = None

    def __post_init__(self):
        self.subcommands = self.subcommands or []
        self.options = self.options or []


@dataclass
class Option:
    """CLI option definition for completion."""

    name: str
    short: Optional[str] = None
    description: str = ""
    takes_value: bool = False
    choices: List[str] = None
    file_completion: bool = False
    directory_completion: bool = False


# ReconnV2 CLI command structure
RECON_COMMANDS = Command(
    name="recon",
    description="ReconnV2 - Automated Reconnaissance Framework",
    subcommands=[
        Command(
            name="scan",
            description="Start a new scan",
            options=[
                Option("-t", "--target", "Target domain or IP", takes_value=True),
                Option(
                    "-p",
                    "--profile",
                    "Scan profile",
                    takes_value=True,
                    choices=["quick", "standard", "deep", "passive"],
                ),
                Option("-c", "--concurrency", "Concurrency level", takes_value=True),
                Option(
                    "-o",
                    "--output",
                    "Output directory",
                    takes_value=True,
                    directory_completion=True,
                ),
                Option(
                    "-f",
                    "--format",
                    "Output format",
                    takes_value=True,
                    choices=["json", "jsonl", "csv", "html"],
                ),
                Option(
                    "--targets-file",
                    description="File with targets",
                    takes_value=True,
                    file_completion=True,
                ),
                Option("--notify", description="Enable notifications"),
                Option("--no-passive", description="Skip passive stages"),
            ],
        ),
        Command(
            name="job",
            description="Job management",
            subcommands=[
                Command("list", "List all jobs"),
                Command(
                    "show",
                    "Show job details",
                    options=[
                        Option("--full", description="Show full details"),
                    ],
                ),
                Command("cancel", "Cancel a running job"),
                Command("resume", "Resume a paused job"),
                Command("retry", "Retry a failed job"),
                Command("delete", "Delete a job"),
                Command(
                    "export",
                    "Export job results",
                    options=[
                        Option(
                            "-f",
                            "--format",
                            "Export format",
                            takes_value=True,
                            choices=["json", "csv", "html", "pdf"],
                        ),
                    ],
                ),
            ],
        ),
        Command(
            name="profile",
            description="Manage scan profiles",
            subcommands=[
                Command("list", "List profiles"),
                Command("show", "Show profile details"),
                Command("create", "Create a new profile"),
                Command("edit", "Edit a profile"),
                Command("delete", "Delete a profile"),
                Command(
                    "import",
                    "Import profiles",
                    options=[
                        Option(
                            "-f",
                            "--file",
                            "Profile file",
                            takes_value=True,
                            file_completion=True,
                        ),
                    ],
                ),
                Command("export", "Export profiles"),
            ],
        ),
        Command(
            name="tools",
            description="Manage external tools",
            subcommands=[
                Command("list", "List available tools"),
                Command("check", "Check tool availability"),
                Command("install", "Install tools"),
                Command("config", "Configure a tool"),
            ],
        ),
        Command(
            name="config",
            description="Configuration management",
            subcommands=[
                Command("show", "Show current config"),
                Command("set", "Set config value"),
                Command("reset", "Reset to defaults"),
                Command("validate", "Validate config"),
            ],
            options=[
                Option("--global", description="Use global config"),
                Option("--local", description="Use local config"),
            ],
        ),
        Command(
            name="schedule",
            description="Manage scheduled scans",
            subcommands=[
                Command("list", "List scheduled jobs"),
                Command("add", "Add scheduled job"),
                Command("remove", "Remove scheduled job"),
                Command("pause", "Pause scheduled job"),
                Command("resume", "Resume scheduled job"),
            ],
        ),
        Command(
            name="api",
            description="API server management",
            subcommands=[
                Command(
                    "start",
                    "Start API server",
                    options=[
                        Option("-p", "--port", "Port number", takes_value=True),
                        Option("-h", "--host", "Host address", takes_value=True),
                        Option("--reload", description="Enable auto-reload"),
                    ],
                ),
                Command("stop", "Stop API server"),
                Command("status", "Show API server status"),
            ],
        ),
        Command(
            name="interactive",
            description="Start interactive mode",
        ),
        Command(
            name="version",
            description="Show version information",
        ),
    ],
    options=[
        Option("-v", "--verbose", "Verbose output"),
        Option("-q", "--quiet", "Quiet mode"),
        Option("--debug", description="Debug mode"),
        Option("--no-color", description="Disable colors"),
        Option(
            "--config",
            description="Config file path",
            takes_value=True,
            file_completion=True,
        ),
    ],
)


class CompletionGenerator:
    """Generate shell completion scripts."""

    def __init__(self, command: Command):
        self.command = command

    def generate(self, shell: Shell) -> str:
        """Generate completion script for specified shell."""
        generators: Dict[Shell, Callable[[], str]] = {
            Shell.BASH: self._generate_bash,
            Shell.ZSH: self._generate_zsh,
            Shell.FISH: self._generate_fish,
            Shell.POWERSHELL: self._generate_powershell,
        }

        generator = generators.get(shell)
        if generator is None:
            raise ValueError(f"Unsupported shell: {shell}")

        return generator()

    def _generate_bash(self) -> str:
        """Generate Bash completion script."""
        script = """#!/bin/bash
# ReconnV2 Bash Completion
# Generated automatically - do not edit

_recon_completions() {
    local cur prev words cword
    _init_completion || return
    
    local commands="scan job profile tools config schedule api interactive version"
    local global_opts="-v --verbose -q --quiet --debug --no-color --config"
    
    case "$prev" in
        recon)
            COMPREPLY=($(compgen -W "$commands $global_opts" -- "$cur"))
            return
            ;;
        scan)
            local scan_opts="-t --target -p --profile -c --concurrency -o --output -f --format --targets-file --notify --no-passive"
            COMPREPLY=($(compgen -W "$scan_opts" -- "$cur"))
            return
            ;;
        --profile|-p)
            COMPREPLY=($(compgen -W "quick standard deep passive" -- "$cur"))
            return
            ;;
        --format|-f)
            COMPREPLY=($(compgen -W "json jsonl csv html pdf" -- "$cur"))
            return
            ;;
        --target|-t|--config)
            COMPREPLY=($(compgen -f -- "$cur"))
            return
            ;;
        --output|-o)
            COMPREPLY=($(compgen -d -- "$cur"))
            return
            ;;
        job)
            COMPREPLY=($(compgen -W "list show cancel resume retry delete export" -- "$cur"))
            return
            ;;
        profile)
            COMPREPLY=($(compgen -W "list show create edit delete import export" -- "$cur"))
            return
            ;;
        tools)
            COMPREPLY=($(compgen -W "list check install config" -- "$cur"))
            return
            ;;
        config)
            COMPREPLY=($(compgen -W "show set reset validate" -- "$cur"))
            return
            ;;
        schedule)
            COMPREPLY=($(compgen -W "list add remove pause resume" -- "$cur"))
            return
            ;;
        api)
            COMPREPLY=($(compgen -W "start stop status" -- "$cur"))
            return
            ;;
    esac
    
    # Default to command completion
    COMPREPLY=($(compgen -W "$commands" -- "$cur"))
}

complete -F _recon_completions recon
"""
        return script

    def _generate_zsh(self) -> str:
        """Generate Zsh completion script."""
        script = """#compdef recon
# ReconnV2 Zsh Completion
# Generated automatically - do not edit

_recon() {
    local curcontext="$curcontext" state line
    typeset -A opt_args
    
    _arguments -C \\
        '-v[Verbose output]' \\
        '--verbose[Verbose output]' \\
        '-q[Quiet mode]' \\
        '--quiet[Quiet mode]' \\
        '--debug[Debug mode]' \\
        '--no-color[Disable colors]' \\
        '--config[Config file]:file:_files' \\
        '1: :->command' \\
        '*: :->args'
    
    case "$state" in
        command)
            local commands=(
                'scan:Start a new scan'
                'job:Job management'
                'profile:Manage scan profiles'
                'tools:Manage external tools'
                'config:Configuration management'
                'schedule:Manage scheduled scans'
                'api:API server management'
                'interactive:Start interactive mode'
                'version:Show version information'
            )
            _describe 'command' commands
            ;;
        args)
            case "${words[2]}" in
                scan)
                    _arguments \\
                        '-t[Target domain or IP]:target:' \\
                        '--target[Target domain or IP]:target:' \\
                        '-p[Scan profile]:profile:(quick standard deep passive)' \\
                        '--profile[Scan profile]:profile:(quick standard deep passive)' \\
                        '-c[Concurrency level]:concurrency:' \\
                        '--concurrency[Concurrency level]:concurrency:' \\
                        '-o[Output directory]:directory:_directories' \\
                        '--output[Output directory]:directory:_directories' \\
                        '-f[Output format]:format:(json jsonl csv html)' \\
                        '--format[Output format]:format:(json jsonl csv html)' \\
                        '--targets-file[File with targets]:file:_files' \\
                        '--notify[Enable notifications]' \\
                        '--no-passive[Skip passive stages]'
                    ;;
                job)
                    local job_cmds=(
                        'list:List all jobs'
                        'show:Show job details'
                        'cancel:Cancel a running job'
                        'resume:Resume a paused job'
                        'retry:Retry a failed job'
                        'delete:Delete a job'
                        'export:Export job results'
                    )
                    _describe 'job command' job_cmds
                    ;;
                profile)
                    local profile_cmds=(
                        'list:List profiles'
                        'show:Show profile details'
                        'create:Create a new profile'
                        'edit:Edit a profile'
                        'delete:Delete a profile'
                        'import:Import profiles'
                        'export:Export profiles'
                    )
                    _describe 'profile command' profile_cmds
                    ;;
                tools)
                    local tools_cmds=(
                        'list:List available tools'
                        'check:Check tool availability'
                        'install:Install tools'
                        'config:Configure a tool'
                    )
                    _describe 'tools command' tools_cmds
                    ;;
                config)
                    local config_cmds=(
                        'show:Show current config'
                        'set:Set config value'
                        'reset:Reset to defaults'
                        'validate:Validate config'
                    )
                    _describe 'config command' config_cmds
                    ;;
                schedule)
                    local schedule_cmds=(
                        'list:List scheduled jobs'
                        'add:Add scheduled job'
                        'remove:Remove scheduled job'
                        'pause:Pause scheduled job'
                        'resume:Resume scheduled job'
                    )
                    _describe 'schedule command' schedule_cmds
                    ;;
                api)
                    local api_cmds=(
                        'start:Start API server'
                        'stop:Stop API server'
                        'status:Show API server status'
                    )
                    _describe 'api command' api_cmds
                    ;;
            esac
            ;;
    esac
}

_recon "$@"
"""
        return script

    def _generate_fish(self) -> str:
        """Generate Fish completion script."""
        script = """# ReconnV2 Fish Completion
# Generated automatically - do not edit

# Disable file completion by default
complete -c recon -f

# Global options
complete -c recon -s v -l verbose -d 'Verbose output'
complete -c recon -s q -l quiet -d 'Quiet mode'
complete -c recon -l debug -d 'Debug mode'
complete -c recon -l no-color -d 'Disable colors'
complete -c recon -l config -r -d 'Config file path'

# Commands
complete -c recon -n '__fish_use_subcommand' -a scan -d 'Start a new scan'
complete -c recon -n '__fish_use_subcommand' -a job -d 'Job management'
complete -c recon -n '__fish_use_subcommand' -a profile -d 'Manage scan profiles'
complete -c recon -n '__fish_use_subcommand' -a tools -d 'Manage external tools'
complete -c recon -n '__fish_use_subcommand' -a config -d 'Configuration management'
complete -c recon -n '__fish_use_subcommand' -a schedule -d 'Manage scheduled scans'
complete -c recon -n '__fish_use_subcommand' -a api -d 'API server management'
complete -c recon -n '__fish_use_subcommand' -a interactive -d 'Start interactive mode'
complete -c recon -n '__fish_use_subcommand' -a version -d 'Show version information'

# Scan options
complete -c recon -n '__fish_seen_subcommand_from scan' -s t -l target -r -d 'Target domain or IP'
complete -c recon -n '__fish_seen_subcommand_from scan' -s p -l profile -r -a 'quick standard deep passive' -d 'Scan profile'
complete -c recon -n '__fish_seen_subcommand_from scan' -s c -l concurrency -r -d 'Concurrency level'
complete -c recon -n '__fish_seen_subcommand_from scan' -s o -l output -r -d 'Output directory'
complete -c recon -n '__fish_seen_subcommand_from scan' -s f -l format -r -a 'json jsonl csv html' -d 'Output format'
complete -c recon -n '__fish_seen_subcommand_from scan' -l targets-file -r -d 'File with targets'
complete -c recon -n '__fish_seen_subcommand_from scan' -l notify -d 'Enable notifications'
complete -c recon -n '__fish_seen_subcommand_from scan' -l no-passive -d 'Skip passive stages'

# Job subcommands
complete -c recon -n '__fish_seen_subcommand_from job' -a list -d 'List all jobs'
complete -c recon -n '__fish_seen_subcommand_from job' -a show -d 'Show job details'
complete -c recon -n '__fish_seen_subcommand_from job' -a cancel -d 'Cancel a running job'
complete -c recon -n '__fish_seen_subcommand_from job' -a resume -d 'Resume a paused job'
complete -c recon -n '__fish_seen_subcommand_from job' -a retry -d 'Retry a failed job'
complete -c recon -n '__fish_seen_subcommand_from job' -a delete -d 'Delete a job'
complete -c recon -n '__fish_seen_subcommand_from job' -a export -d 'Export job results'

# Profile subcommands
complete -c recon -n '__fish_seen_subcommand_from profile' -a list -d 'List profiles'
complete -c recon -n '__fish_seen_subcommand_from profile' -a show -d 'Show profile details'
complete -c recon -n '__fish_seen_subcommand_from profile' -a create -d 'Create a new profile'
complete -c recon -n '__fish_seen_subcommand_from profile' -a edit -d 'Edit a profile'
complete -c recon -n '__fish_seen_subcommand_from profile' -a delete -d 'Delete a profile'
complete -c recon -n '__fish_seen_subcommand_from profile' -a import -d 'Import profiles'
complete -c recon -n '__fish_seen_subcommand_from profile' -a export -d 'Export profiles'

# Tools subcommands
complete -c recon -n '__fish_seen_subcommand_from tools' -a list -d 'List available tools'
complete -c recon -n '__fish_seen_subcommand_from tools' -a check -d 'Check tool availability'
complete -c recon -n '__fish_seen_subcommand_from tools' -a install -d 'Install tools'
complete -c recon -n '__fish_seen_subcommand_from tools' -a config -d 'Configure a tool'

# Config subcommands
complete -c recon -n '__fish_seen_subcommand_from config' -a show -d 'Show current config'
complete -c recon -n '__fish_seen_subcommand_from config' -a set -d 'Set config value'
complete -c recon -n '__fish_seen_subcommand_from config' -a reset -d 'Reset to defaults'
complete -c recon -n '__fish_seen_subcommand_from config' -a validate -d 'Validate config'

# Schedule subcommands
complete -c recon -n '__fish_seen_subcommand_from schedule' -a list -d 'List scheduled jobs'
complete -c recon -n '__fish_seen_subcommand_from schedule' -a add -d 'Add scheduled job'
complete -c recon -n '__fish_seen_subcommand_from schedule' -a remove -d 'Remove scheduled job'
complete -c recon -n '__fish_seen_subcommand_from schedule' -a pause -d 'Pause scheduled job'
complete -c recon -n '__fish_seen_subcommand_from schedule' -a resume -d 'Resume scheduled job'

# API subcommands
complete -c recon -n '__fish_seen_subcommand_from api' -a start -d 'Start API server'
complete -c recon -n '__fish_seen_subcommand_from api' -a stop -d 'Stop API server'
complete -c recon -n '__fish_seen_subcommand_from api' -a status -d 'Show API server status'
"""
        return script

    def _generate_powershell(self) -> str:
        """Generate PowerShell completion script."""
        script = """# ReconnV2 PowerShell Completion
# Generated automatically - do not edit

$ReconCommands = @{
    'recon' = @{
        'commands' = @('scan', 'job', 'profile', 'tools', 'config', 'schedule', 'api', 'interactive', 'version')
        'options' = @('-v', '--verbose', '-q', '--quiet', '--debug', '--no-color', '--config')
    }
    'scan' = @{
        'options' = @('-t', '--target', '-p', '--profile', '-c', '--concurrency', '-o', '--output', '-f', '--format', '--targets-file', '--notify', '--no-passive')
        'profile_values' = @('quick', 'standard', 'deep', 'passive')
        'format_values' = @('json', 'jsonl', 'csv', 'html', 'pdf')
    }
    'job' = @{
        'commands' = @('list', 'show', 'cancel', 'resume', 'retry', 'delete', 'export')
    }
    'profile' = @{
        'commands' = @('list', 'show', 'create', 'edit', 'delete', 'import', 'export')
    }
    'tools' = @{
        'commands' = @('list', 'check', 'install', 'config')
    }
    'config' = @{
        'commands' = @('show', 'set', 'reset', 'validate')
    }
    'schedule' = @{
        'commands' = @('list', 'add', 'remove', 'pause', 'resume')
    }
    'api' = @{
        'commands' = @('start', 'stop', 'status')
    }
}

Register-ArgumentCompleter -Native -CommandName recon -ScriptBlock {
    param($wordToComplete, $commandAst, $cursorPosition)
    
    $words = $commandAst.CommandElements | ForEach-Object { $_.Extent.Text }
    
    if ($words.Count -eq 1) {
        # Complete main commands
        $ReconCommands['recon']['commands'] + $ReconCommands['recon']['options'] |
            Where-Object { $_ -like "$wordToComplete*" } |
            ForEach-Object {
                [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
            }
        return
    }
    
    $command = $words[1]
    $prevWord = $words[-2]
    
    # Handle option value completions
    switch ($prevWord) {
        { $_ -in @('-p', '--profile') } {
            $ReconCommands['scan']['profile_values'] |
                Where-Object { $_ -like "$wordToComplete*" } |
                ForEach-Object {
                    [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
                }
            return
        }
        { $_ -in @('-f', '--format') } {
            $ReconCommands['scan']['format_values'] |
                Where-Object { $_ -like "$wordToComplete*" } |
                ForEach-Object {
                    [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
                }
            return
        }
    }
    
    # Handle subcommand completions
    if ($ReconCommands.ContainsKey($command)) {
        $subCommands = $ReconCommands[$command]
        
        if ($subCommands.ContainsKey('commands') -and $words.Count -eq 2) {
            $subCommands['commands'] |
                Where-Object { $_ -like "$wordToComplete*" } |
                ForEach-Object {
                    [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
                }
            return
        }
        
        if ($subCommands.ContainsKey('options')) {
            $subCommands['options'] |
                Where-Object { $_ -like "$wordToComplete*" } |
                ForEach-Object {
                    [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
                }
            return
        }
    }
}
"""
        return script


class CompletionInstaller:
    """Install shell completion scripts."""

    COMPLETION_PATHS: Dict[Shell, Path] = {
        Shell.BASH: Path.home() / ".bash_completion.d" / "recon.bash",
        Shell.ZSH: Path.home() / ".zsh" / "completions" / "_recon",
        Shell.FISH: Path.home() / ".config" / "fish" / "completions" / "recon.fish",
        Shell.POWERSHELL: Path.home()
        / "Documents"
        / "WindowsPowerShell"
        / "recon_completion.ps1",
    }

    def __init__(self):
        self.generator = CompletionGenerator(RECON_COMMANDS)

    def install(self, shell: Shell) -> Path:
        """Install completion script for specified shell."""
        script = self.generator.generate(shell)
        path = self.COMPLETION_PATHS[shell]

        # Create parent directory if needed
        path.parent.mkdir(parents=True, exist_ok=True)

        # Write script
        path.write_text(script)

        # Make executable (Unix only)
        if os.name != "nt":
            path.chmod(0o755)

        return path

    def uninstall(self, shell: Shell) -> bool:
        """Uninstall completion script."""
        path = self.COMPLETION_PATHS[shell]
        if path.exists():
            path.unlink()
            return True
        return False

    def get_source_command(self, shell: Shell) -> str:
        """Get command to source the completion script."""
        path = self.COMPLETION_PATHS[shell]

        if shell == Shell.BASH:
            return f'source "{path}"  # Add to ~/.bashrc'
        elif shell == Shell.ZSH:
            return "fpath=(~/.zsh/completions $fpath); autoload -Uz compinit && compinit  # Add to ~/.zshrc"
        elif shell == Shell.FISH:
            return f"# Fish loads completions automatically from {path}"
        elif shell == Shell.POWERSHELL:
            return f'. "{path}"  # Add to $PROFILE'

        return ""


def get_shell() -> Optional[Shell]:
    """Detect the current shell."""
    shell_env = os.environ.get("SHELL", "")

    if "bash" in shell_env:
        return Shell.BASH
    elif "zsh" in shell_env:
        return Shell.ZSH
    elif "fish" in shell_env:
        return Shell.FISH
    elif os.name == "nt" or "powershell" in shell_env.lower():
        return Shell.POWERSHELL

    return None


def install_completion(shell: Optional[Shell] = None) -> Optional[Path]:
    """Install completion script for shell."""
    if shell is None:
        shell = get_shell()

    if shell is None:
        print("Could not detect shell. Please specify: bash, zsh, fish, or powershell")
        return None

    installer = CompletionInstaller()
    path = installer.install(shell)

    print(f"✅ Installed completion script to: {path}")
    print("\n📋 To activate, run:")
    print(f"   {installer.get_source_command(shell)}")

    return path


def generate_completion(shell: Shell) -> str:
    """Generate completion script for shell."""
    generator = CompletionGenerator(RECON_COMMANDS)
    return generator.generate(shell)


if __name__ == "__main__":
    # CLI for testing
    import argparse

    parser = argparse.ArgumentParser(description="Shell completion installer")
    parser.add_argument("action", choices=["install", "generate", "uninstall"])
    parser.add_argument("--shell", choices=["bash", "zsh", "fish", "powershell"])

    args = parser.parse_args()
    shell = Shell(args.shell) if args.shell else get_shell()

    if args.action == "install":
        install_completion(shell)
    elif args.action == "generate":
        print(generate_completion(shell))
    elif args.action == "uninstall":
        installer = CompletionInstaller()
        if installer.uninstall(shell):
            print(f"✅ Uninstalled {shell.value} completion")
        else:
            print(f"⚠️ No completion script found for {shell.value}")
