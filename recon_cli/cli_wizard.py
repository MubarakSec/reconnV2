"""
Interactive CLI Wizard for ReconnV2.

Provides step-by-step wizards for common tasks:
- New scan configuration
- Profile creation
- Job management
- Tool configuration

Example:
    >>> from recon_cli.cli_wizard import ScanWizard
    >>> wizard = ScanWizard()
    >>> config = await wizard.run()
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, TypeVar, Generic
from datetime import datetime

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm, IntPrompt
from rich.table import Table
from rich.tree import Tree
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn

__all__ = [
    "WizardStep",
    "WizardResult",
    "BaseWizard",
    "ScanWizard",
    "ProfileWizard",
    "JobWizard",
    "ToolConfigWizard",
    "InteractiveMode",
    "WizardRegistry",
]


console = Console()


class StepType(Enum):
    """Types of wizard steps."""

    TEXT = "text"
    NUMBER = "number"
    CHOICE = "choice"
    MULTI_CHOICE = "multi_choice"
    CONFIRM = "confirm"
    PATH = "path"
    PASSWORD = "password"
    LIST = "list"


@dataclass
class WizardStep:
    """Single step in a wizard flow."""

    key: str
    prompt: str
    step_type: StepType = StepType.TEXT
    choices: List[str] = field(default_factory=list)
    default: Any = None
    required: bool = True
    validator: Optional[Callable[[Any], bool]] = None
    error_message: str = "Invalid input"
    help_text: Optional[str] = None
    depends_on: Optional[str] = None
    depends_value: Any = None


@dataclass
class WizardResult:
    """Result of a completed wizard."""

    data: Dict[str, Any]
    completed: bool
    cancelled: bool = False
    errors: List[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.now)

    def get(self, key: str, default: Any = None) -> Any:
        """Get a value from the result data."""
        return self.data.get(key, default)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "data": self.data,
            "completed": self.completed,
            "cancelled": self.cancelled,
            "errors": self.errors,
            "timestamp": self.timestamp.isoformat(),
        }


T = TypeVar("T")


class BaseWizard(Generic[T]):
    """Base class for interactive wizards."""

    def __init__(
        self,
        title: str = "Wizard",
        description: str = "",
        steps: Optional[List[WizardStep]] = None,
    ):
        self.title = title
        self.description = description
        self.steps: List[WizardStep] = steps or []
        self.console = console
        self.collected: Dict[str, Any] = {}
        self._step_index = 0

    def add_step(self, step: WizardStep) -> "BaseWizard[T]":
        """Add a step to the wizard."""
        self.steps.append(step)
        return self

    def _show_header(self) -> None:
        """Display wizard header."""
        self.console.print()
        self.console.print(
            Panel(
                f"[bold cyan]{self.title}[/bold cyan]\n\n{self.description}",
                title="🧙 Wizard",
                border_style="cyan",
            )
        )
        self.console.print()

    def _show_progress(self, current: int, total: int) -> None:
        """Show wizard progress."""
        progress = f"Step {current}/{total}"
        bar = "█" * current + "░" * (total - current)
        self.console.print(f"[dim]{progress} [{bar}][/dim]\n")

    def _should_skip_step(self, step: WizardStep) -> bool:
        """Check if step should be skipped based on dependencies."""
        if step.depends_on is None:
            return False

        dep_value = self.collected.get(step.depends_on)
        if step.depends_value is not None:
            return dep_value != step.depends_value
        return dep_value is None or dep_value is False

    def _prompt_step(self, step: WizardStep) -> Any:
        """Prompt user for step input."""
        # Show help text if available
        if step.help_text:
            self.console.print(f"[dim]ℹ️  {step.help_text}[/dim]")

        value = None

        if step.step_type == StepType.TEXT:
            value = Prompt.ask(
                f"[cyan]{step.prompt}[/cyan]",
                default=str(step.default) if step.default else None,
            )

        elif step.step_type == StepType.NUMBER:
            value = IntPrompt.ask(  # type: ignore[assignment]
                f"[cyan]{step.prompt}[/cyan]",
                default=step.default if step.default else 0,  # type: ignore[arg-type]
            )

        elif step.step_type == StepType.CONFIRM:
            value = Confirm.ask(  # type: ignore[assignment]
                f"[cyan]{step.prompt}[/cyan]",
                default=step.default if step.default is not None else False,  # type: ignore[arg-type]
            )

        elif step.step_type == StepType.CHOICE:
            self.console.print(f"[cyan]{step.prompt}[/cyan]")
            for i, choice in enumerate(step.choices, 1):
                default_marker = " [default]" if choice == step.default else ""
                self.console.print(f"  {i}. {choice}{default_marker}")

            idx = IntPrompt.ask(
                "Select option",
                default=step.choices.index(step.default) + 1
                if step.default in step.choices
                else 1,
            )
            value = (
                step.choices[idx - 1] if 1 <= idx <= len(step.choices) else step.default
            )

        elif step.step_type == StepType.MULTI_CHOICE:
            self.console.print(f"[cyan]{step.prompt}[/cyan]")
            for i, choice in enumerate(step.choices, 1):
                self.console.print(f"  {i}. {choice}")

            selection = Prompt.ask(
                "Select options (comma-separated numbers)",
                default="1",
            )
            indices = [
                int(x.strip()) for x in selection.split(",") if x.strip().isdigit()
            ]
            value = [  # type: ignore[assignment]
                step.choices[i - 1] for i in indices if 1 <= i <= len(step.choices)
            ]

        elif step.step_type == StepType.PATH:
            path_str = Prompt.ask(
                f"[cyan]{step.prompt}[/cyan]",
                default=str(step.default) if step.default else None,
            )
            value = Path(path_str) if path_str else None  # type: ignore[assignment]

        elif step.step_type == StepType.PASSWORD:
            value = Prompt.ask(
                f"[cyan]{step.prompt}[/cyan]",
                password=True,
            )

        elif step.step_type == StepType.LIST:
            self.console.print(
                f"[cyan]{step.prompt}[/cyan] (one per line, empty to finish)"
            )
            items = []
            while True:
                item = Prompt.ask("  Item", default="")
                if not item:
                    break
                items.append(item)
            value = items  # type: ignore[assignment]

        # Validate if validator provided
        if step.validator and value is not None:
            if not step.validator(value):
                self.console.print(f"[red]❌ {step.error_message}[/red]")
                return self._prompt_step(step)

        # Check required
        if step.required and (value is None or value == ""):
            self.console.print("[red]❌ This field is required[/red]")
            return self._prompt_step(step)

        return value

    async def run(self) -> WizardResult:
        """Run the wizard interactively."""
        self._show_header()
        self.collected = {}
        errors: List[str] = []

        total_steps = len(self.steps)

        for i, step in enumerate(self.steps, 1):
            # Check if should skip
            if self._should_skip_step(step):
                continue

            self._show_progress(i, total_steps)

            try:
                value = self._prompt_step(step)
                self.collected[step.key] = value
                self.console.print()
            except KeyboardInterrupt:
                self.console.print("\n[yellow]⚠️ Wizard cancelled[/yellow]")
                return WizardResult(
                    data=self.collected,
                    completed=False,
                    cancelled=True,
                )
            except Exception as e:
                errors.append(f"Step '{step.key}': {str(e)}")

        # Show summary
        self._show_summary()

        # Confirm
        if not Confirm.ask("\n[cyan]Proceed with these settings?[/cyan]", default=True):
            return WizardResult(
                data=self.collected,
                completed=False,
                cancelled=True,
            )

        return WizardResult(
            data=self.collected,
            completed=True,
            errors=errors,
        )

    def _show_summary(self) -> None:
        """Display collected values summary."""
        table = Table(title="📋 Summary", show_header=True)
        table.add_column("Setting", style="cyan")
        table.add_column("Value", style="green")

        for key, value in self.collected.items():
            display_value = str(value)
            if len(display_value) > 50:
                display_value = display_value[:47] + "..."
            table.add_row(key, display_value)

        self.console.print(table)

    def transform_result(self, result: WizardResult) -> T:
        """Transform wizard result to target type. Override in subclass."""
        return result.data  # type: ignore


class ScanWizard(BaseWizard[Dict[str, Any]]):
    """Wizard for configuring a new scan."""

    def __init__(self):
        super().__init__(
            title="New Scan Configuration",
            description="Configure a new reconnaissance scan step by step.",
        )
        self._setup_steps()

    def _setup_steps(self) -> None:
        """Set up wizard steps."""
        self.add_step(
            WizardStep(
                key="name",
                prompt="Scan name",
                help_text="A descriptive name for this scan",
                default="my-scan",
            )
        )

        self.add_step(
            WizardStep(
                key="targets",
                prompt="Target domains/IPs",
                step_type=StepType.LIST,
                help_text="Enter target domains or IP addresses",
            )
        )

        self.add_step(
            WizardStep(
                key="profile",
                prompt="Scan profile",
                step_type=StepType.CHOICE,
                choices=["quick", "standard", "deep", "passive", "custom"],
                default="standard",
                help_text="Select scan intensity profile",
            )
        )

        self.add_step(
            WizardStep(
                key="custom_stages",
                prompt="Custom stages to include",
                step_type=StepType.MULTI_CHOICE,
                choices=[
                    "dns_enum",
                    "subdomain_enum",
                    "port_scan",
                    "web_discovery",
                    "screenshot",
                    "vulnerability_scan",
                    "secrets_scan",
                    "takeover_check",
                ],
                depends_on="profile",
                depends_value="custom",
            )
        )

        self.add_step(
            WizardStep(
                key="concurrency",
                prompt="Concurrency level (1-100)",
                step_type=StepType.NUMBER,
                default=10,
                validator=lambda x: 1 <= x <= 100,
                error_message="Concurrency must be between 1 and 100",
            )
        )

        self.add_step(
            WizardStep(
                key="timeout",
                prompt="Timeout per target (seconds)",
                step_type=StepType.NUMBER,
                default=300,
            )
        )

        self.add_step(
            WizardStep(
                key="notify",
                prompt="Enable notifications?",
                step_type=StepType.CONFIRM,
                default=True,
            )
        )

        self.add_step(
            WizardStep(
                key="notify_channels",
                prompt="Notification channels",
                step_type=StepType.MULTI_CHOICE,
                choices=["slack", "discord", "telegram", "email", "webhook"],
                depends_on="notify",
                depends_value=True,
            )
        )

        self.add_step(
            WizardStep(
                key="save_artifacts",
                prompt="Save intermediate artifacts?",
                step_type=StepType.CONFIRM,
                default=True,
            )
        )


class ProfileWizard(BaseWizard[Dict[str, Any]]):
    """Wizard for creating scan profiles."""

    def __init__(self):
        super().__init__(
            title="Create Scan Profile",
            description="Create a reusable scan profile with custom settings.",
        )
        self._setup_steps()

    def _setup_steps(self) -> None:
        """Set up wizard steps."""
        self.add_step(
            WizardStep(
                key="name",
                prompt="Profile name",
                validator=lambda x: x.replace("-", "").replace("_", "").isalnum(),
                error_message="Profile name must be alphanumeric (dashes and underscores allowed)",
            )
        )

        self.add_step(
            WizardStep(
                key="description",
                prompt="Description",
            )
        )

        self.add_step(
            WizardStep(
                key="base_profile",
                prompt="Base profile",
                step_type=StepType.CHOICE,
                choices=["none", "quick", "standard", "deep", "passive"],
                default="none",
                help_text="Inherit settings from an existing profile",
            )
        )

        self.add_step(
            WizardStep(
                key="stages",
                prompt="Stages to include",
                step_type=StepType.MULTI_CHOICE,
                choices=[
                    "dns_enum",
                    "subdomain_enum",
                    "port_scan",
                    "web_discovery",
                    "screenshot",
                    "vulnerability_scan",
                    "secrets_scan",
                    "takeover_check",
                    "auth_matrix",
                    "idor_check",
                    "correlation",
                ],
            )
        )

        self.add_step(
            WizardStep(
                key="tools",
                prompt="Tools to use",
                step_type=StepType.MULTI_CHOICE,
                choices=[
                    "amass",
                    "subfinder",
                    "dnsx",
                    "naabu",
                    "httpx",
                    "nuclei",
                    "ffuf",
                    "katana",
                    "gowitness",
                    "dalfox",
                    "sqlmap",
                ],
            )
        )

        self.add_step(
            WizardStep(
                key="rate_limit",
                prompt="Rate limit (requests/second)",
                step_type=StepType.NUMBER,
                default=100,
            )
        )

        self.add_step(
            WizardStep(
                key="max_depth",
                prompt="Maximum crawl depth",
                step_type=StepType.NUMBER,
                default=3,
            )
        )


class JobWizard(BaseWizard[Dict[str, Any]]):
    """Wizard for job management."""

    def __init__(self):
        super().__init__(
            title="Job Management",
            description="Manage reconnaissance jobs.",
        )
        self._setup_steps()

    def _setup_steps(self) -> None:
        """Set up wizard steps."""
        self.add_step(
            WizardStep(
                key="action",
                prompt="What would you like to do?",
                step_type=StepType.CHOICE,
                choices=["create", "resume", "retry", "cancel", "delete", "view"],
                default="create",
            )
        )

        self.add_step(
            WizardStep(
                key="job_id",
                prompt="Job ID",
                depends_on="action",
                depends_value="resume",  # Will be shown for resume/retry/cancel/delete/view
                required=False,
            )
        )

        self.add_step(
            WizardStep(
                key="schedule",
                prompt="Schedule this job?",
                step_type=StepType.CONFIRM,
                default=False,
                depends_on="action",
                depends_value="create",
            )
        )

        self.add_step(
            WizardStep(
                key="cron_expression",
                prompt="Cron expression (e.g., '0 0 * * *' for daily)",
                depends_on="schedule",
                depends_value=True,
                help_text="Format: minute hour day month weekday",
            )
        )


class ToolConfigWizard(BaseWizard[Dict[str, Any]]):
    """Wizard for tool configuration."""

    def __init__(self):
        super().__init__(
            title="Tool Configuration",
            description="Configure external reconnaissance tools.",
        )
        self._setup_steps()

    def _setup_steps(self) -> None:
        """Set up wizard steps."""
        self.add_step(
            WizardStep(
                key="tool",
                prompt="Select tool to configure",
                step_type=StepType.CHOICE,
                choices=[
                    "amass",
                    "subfinder",
                    "dnsx",
                    "naabu",
                    "httpx",
                    "nuclei",
                    "ffuf",
                    "katana",
                    "gowitness",
                    "dalfox",
                    "sqlmap",
                    "uncover",
                ],
            )
        )

        self.add_step(
            WizardStep(
                key="binary_path",
                prompt="Path to tool binary",
                step_type=StepType.PATH,
                help_text="Leave empty to use PATH",
                required=False,
            )
        )

        self.add_step(
            WizardStep(
                key="config_file",
                prompt="Path to tool config file",
                step_type=StepType.PATH,
                required=False,
            )
        )

        self.add_step(
            WizardStep(
                key="extra_args",
                prompt="Extra command-line arguments",
                required=False,
            )
        )

        self.add_step(
            WizardStep(
                key="timeout",
                prompt="Execution timeout (seconds)",
                step_type=StepType.NUMBER,
                default=300,
            )
        )

        self.add_step(
            WizardStep(
                key="verify",
                prompt="Verify tool installation now?",
                step_type=StepType.CONFIRM,
                default=True,
            )
        )


class WizardRegistry:
    """Registry of available wizards."""

    _wizards: Dict[str, type] = {
        "scan": ScanWizard,
        "profile": ProfileWizard,
        "job": JobWizard,
        "tool": ToolConfigWizard,
    }

    @classmethod
    def register(cls, name: str, wizard_class: type) -> None:
        """Register a wizard."""
        cls._wizards[name] = wizard_class

    @classmethod
    def get(cls, name: str) -> Optional[type]:
        """Get a wizard by name."""
        return cls._wizards.get(name)

    @classmethod
    def list_wizards(cls) -> List[str]:
        """List available wizards."""
        return list(cls._wizards.keys())

    @classmethod
    async def run_wizard(cls, name: str) -> Optional[WizardResult]:
        """Run a wizard by name."""
        wizard_class = cls.get(name)
        if wizard_class is None:
            console.print(f"[red]Unknown wizard: {name}[/red]")
            return None

        wizard = wizard_class()
        return await wizard.run()


class InteractiveMode:
    """Interactive CLI mode with command loop."""

    def __init__(self):
        self.console = console
        self.running = True
        self.history: List[str] = []
        self.commands: Dict[str, Callable] = {}
        self._setup_commands()

    def _setup_commands(self) -> None:
        """Set up available commands."""
        self.commands = {
            "help": self._cmd_help,
            "wizard": self._cmd_wizard,
            "scan": self._cmd_scan,
            "jobs": self._cmd_jobs,
            "profile": self._cmd_profile,
            "status": self._cmd_status,
            "clear": self._cmd_clear,
            "history": self._cmd_history,
            "exit": self._cmd_exit,
            "quit": self._cmd_exit,
        }

    async def run(self) -> None:
        """Run interactive mode."""
        self._show_welcome()

        while self.running:
            try:
                command = Prompt.ask("\n[bold cyan]recon[/bold cyan]")
                self.history.append(command)
                await self._process_command(command)
            except KeyboardInterrupt:
                self.console.print("\n[yellow]Use 'exit' to quit[/yellow]")
            except Exception as e:
                self.console.print(f"[red]Error: {e}[/red]")

    def _show_welcome(self) -> None:
        """Show welcome message."""
        welcome = """
╔═══════════════════════════════════════════════════════════════╗
║                    🔍 ReconnV2 Interactive Mode                ║
║                                                                ║
║  Type 'help' for available commands                           ║
║  Type 'wizard <name>' to start a wizard                       ║
║  Type 'exit' to quit                                          ║
╚═══════════════════════════════════════════════════════════════╝
"""
        self.console.print(Text(welcome, style="cyan"))

    async def _process_command(self, command: str) -> None:
        """Process a command."""
        parts = command.strip().split()
        if not parts:
            return

        cmd_name = parts[0].lower()
        args = parts[1:]

        if cmd_name in self.commands:
            await self.commands[cmd_name](args)
        else:
            self.console.print(f"[red]Unknown command: {cmd_name}[/red]")
            self.console.print("[dim]Type 'help' for available commands[/dim]")

    async def _cmd_help(self, args: List[str]) -> None:
        """Show help."""
        table = Table(title="📚 Available Commands", show_header=True)
        table.add_column("Command", style="cyan")
        table.add_column("Description")

        commands_help = [
            ("help", "Show this help message"),
            ("wizard <name>", "Start a wizard (scan, profile, job, tool)"),
            ("scan <target>", "Quick scan a target"),
            ("jobs", "List jobs"),
            ("profile list", "List profiles"),
            ("status", "Show system status"),
            ("clear", "Clear screen"),
            ("history", "Show command history"),
            ("exit", "Exit interactive mode"),
        ]

        for cmd, desc in commands_help:
            table.add_row(cmd, desc)

        self.console.print(table)

    async def _cmd_wizard(self, args: List[str]) -> None:
        """Run a wizard."""
        if not args:
            wizards = WizardRegistry.list_wizards()
            self.console.print(f"[cyan]Available wizards:[/cyan] {', '.join(wizards)}")
            return

        wizard_name = args[0]
        result = await WizardRegistry.run_wizard(wizard_name)

        if result and result.completed:
            self.console.print("[green]✅ Wizard completed successfully![/green]")

    async def _cmd_scan(self, args: List[str]) -> None:
        """Quick scan."""
        if not args:
            self.console.print("[yellow]Usage: scan <target>[/yellow]")
            return

        target = args[0]
        self.console.print(f"[cyan]Starting scan for {target}...[/cyan]")

        # Would integrate with actual scan functionality
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console,
        ) as progress:
            task = progress.add_task("Initializing scan...", total=None)
            await asyncio.sleep(1)
            progress.update(task, description="Scan queued. Use 'jobs' to monitor.")

    async def _cmd_jobs(self, args: List[str]) -> None:
        """List jobs."""
        table = Table(title="📋 Jobs", show_header=True)
        table.add_column("ID", style="cyan")
        table.add_column("Name")
        table.add_column("Status")
        table.add_column("Progress")
        table.add_column("Created")

        # Example data - would integrate with job manager
        table.add_row(
            "abc123", "example.com scan", "[green]running[/green]", "45%", "2 min ago"
        )
        table.add_row(
            "def456", "test.org scan", "[yellow]queued[/yellow]", "-", "5 min ago"
        )

        self.console.print(table)

    async def _cmd_profile(self, args: List[str]) -> None:
        """Manage profiles."""
        if not args or args[0] == "list":
            table = Table(title="📁 Profiles", show_header=True)
            table.add_column("Name", style="cyan")
            table.add_column("Description")
            table.add_column("Stages")

            # Example data
            table.add_row("quick", "Fast scan", "3")
            table.add_row("standard", "Standard scan", "5")
            table.add_row("deep", "Comprehensive scan", "8")

            self.console.print(table)

    async def _cmd_status(self, args: List[str]) -> None:
        """Show system status."""
        tree = Tree("🖥️ [bold cyan]System Status[/bold cyan]")

        # Jobs branch
        jobs = tree.add("📋 Jobs")
        jobs.add("[green]Running: 1[/green]")
        jobs.add("[yellow]Queued: 2[/yellow]")
        jobs.add("[dim]Completed: 15[/dim]")

        # Tools branch
        tools = tree.add("🔧 Tools")
        tools.add("[green]✓ nuclei[/green]")
        tools.add("[green]✓ httpx[/green]")
        tools.add("[red]✗ amass (not found)[/red]")

        # Resources branch
        resources = tree.add("📊 Resources")
        resources.add("CPU: 25%")
        resources.add("Memory: 1.2 GB")
        resources.add("Disk: 50 GB free")

        self.console.print(tree)

    async def _cmd_clear(self, args: List[str]) -> None:
        """Clear screen."""
        self.console.clear()

    async def _cmd_history(self, args: List[str]) -> None:
        """Show command history."""
        for i, cmd in enumerate(self.history[-20:], 1):
            self.console.print(f"[dim]{i:3}[/dim] {cmd}")

    async def _cmd_exit(self, args: List[str]) -> None:
        """Exit interactive mode."""
        self.running = False
        self.console.print("[cyan]Goodbye! 👋[/cyan]")


# Convenience functions
async def run_interactive() -> None:
    """Run interactive mode."""
    mode = InteractiveMode()
    await mode.run()


async def run_scan_wizard() -> WizardResult:
    """Run scan wizard."""
    wizard = ScanWizard()
    return await wizard.run()


async def run_profile_wizard() -> WizardResult:
    """Run profile wizard."""
    wizard = ProfileWizard()
    return await wizard.run()


if __name__ == "__main__":
    asyncio.run(run_interactive())
