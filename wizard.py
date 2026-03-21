#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════╗
║              ReconnV2 - Quick Start Wizard                ║
╚═══════════════════════════════════════════════════════════╝

واجهة سهلة للمستخدمين الجدد
"""

import sys
import subprocess
from pathlib import Path

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.prompt import Prompt, Confirm
    from rich.table import Table
    from rich import print as rprint

    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    print("[!] Installing rich for better UI...")
    subprocess.run([sys.executable, "-m", "pip", "install", "rich", "-q"])
    from rich.console import Console
    from rich.panel import Panel
    from rich.prompt import Prompt, Confirm
    from rich.table import Table
    from rich import print as rprint

console = Console()

PROFILES = {
    "1": ("quick", "فحص سريع", "⚡", "passive"),
    "2": ("passive", "فحص سلبي آمن", "🔍", "passive"),
    "3": ("full", "فحص شامل", "🚀", "full"),
    "4": ("deep", "فحص عميق مكثف", "🔬", "full"),
    "5": ("bugbounty", "Bug Bounty", "🐛", "full"),
    "6": ("stealth", "فحص خفي", "🕵️", "passive"),
    "7": ("api-only", "APIs فقط", "📱", "full"),
    "8": ("wordpress", "WordPress", "🔧", "full"),
}

SCANNERS = {
    "1": ("nuclei", "فحص ثغرات شامل"),
    "2": ("wpscan", "فحص WordPress"),
}

ACTIVE_MODULES = {
    "1": ("js-secrets", "اكتشاف الأسرار في JavaScript"),
    "2": ("backup", "اكتشاف ملفات النسخ الاحتياطي"),
    "3": ("cors", "فحص CORS"),
    "4": ("diff", "مقارنة الاستجابات"),
}


def show_banner():
    console.clear()
    banner = """
[cyan]╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║   ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗            ║
║   ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║            ║
║   ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║            ║
║   ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║            ║
║   ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║            ║
║   ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝ V2        ║
║                                                           ║
║           [white]Advanced Reconnaissance Pipeline[/white]                ║
╚═══════════════════════════════════════════════════════════╝[/cyan]
"""
    rprint(banner)


def show_profile_menu():
    table = Table(title="اختر نوع الفحص", show_header=True, header_style="bold cyan")
    table.add_column("#", style="green", width=3)
    table.add_column("الرمز", width=4)
    table.add_column("الاسم", style="cyan")
    table.add_column("الوصف", style="white")
    table.add_column("النوع", style="yellow")

    for key, (name, desc, icon, base) in PROFILES.items():
        table.add_row(key, icon, name, desc, base)

    console.print(table)
    return Prompt.ask(
        "\n[cyan]اختر رقم الملف الشخصي[/cyan]",
        choices=list(PROFILES.keys()),
        default="2",
    )


def get_target():
    console.print("\n[cyan]═══════════════════════════════════════[/cyan]")
    target = Prompt.ask("[green]أدخل الهدف (مثال: example.com)[/green]")

    if not target:
        console.print("[red][!] الهدف مطلوب[/red]")
        return None

    return target.strip()


def get_targets_file():
    use_file = Confirm.ask(
        "[yellow]هل تريد استخدام ملف أهداف متعددة؟[/yellow]", default=False
    )

    if use_file:
        file_path = Prompt.ask("[cyan]أدخل مسار الملف[/cyan]")
        if file_path and Path(file_path).exists():
            return file_path
        else:
            console.print("[red][!] الملف غير موجود[/red]")

    return None


def get_scanners():
    use_scanner = Confirm.ask(
        "\n[yellow]هل تريد استخدام ماسحات إضافية؟[/yellow]", default=False
    )

    if not use_scanner:
        return []

    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("#", style="green", width=3)
    table.add_column("الماسح", style="cyan")
    table.add_column("الوصف", style="white")

    for key, (name, desc) in SCANNERS.items():
        table.add_row(key, name, desc)

    console.print(table)

    selected = []
    for key, (name, _) in SCANNERS.items():
        if Confirm.ask(f"استخدام {name}?", default=False):
            selected.append(name)

    return selected


def get_active_modules():
    use_modules = Confirm.ask(
        "\n[yellow]هل تريد تفعيل وحدات نشطة؟[/yellow]", default=False
    )

    if not use_modules:
        return []

    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("#", style="green", width=3)
    table.add_column("الوحدة", style="cyan")
    table.add_column("الوصف", style="white")

    for key, (name, desc) in ACTIVE_MODULES.items():
        table.add_row(key, name, desc)

    console.print(table)

    selected = []
    for key, (name, _) in ACTIVE_MODULES.items():
        if Confirm.ask(f"تفعيل {name}?", default=False):
            selected.append(name)

    return selected


def build_command(target, targets_file, profile, scanners, modules):
    cmd = [sys.executable, "-m", "recon_cli", "scan"]

    if targets_file:
        cmd.extend(["--targets-file", targets_file])
    else:
        cmd.append(target)

    cmd.extend(["--profile", profile])

    for scanner in scanners:
        cmd.extend(["--scanner", scanner])

    for module in modules:
        cmd.extend(["--active-module", module])

    cmd.append("--inline")

    return cmd


def run_scan(cmd):
    console.print("\n[cyan]═══════════════════════════════════════[/cyan]")
    console.print(f"[yellow]الأمر: {' '.join(cmd)}[/yellow]")
    console.print("[cyan]═══════════════════════════════════════[/cyan]\n")

    if Confirm.ask("[green]هل تريد بدء الفحص؟[/green]", default=True):
        console.print("\n[bold green]🚀 جاري بدء الفحص...[/bold green]\n")
        subprocess.run(cmd)
        console.print("\n[bold green]✓ انتهى الفحص![/bold green]")
    else:
        console.print("[yellow]تم الإلغاء[/yellow]")


def quick_mode():
    """وضع سريع بدون أسئلة كثيرة"""
    show_banner()
    target = get_target()
    if not target:
        return

    profile_choice = show_profile_menu()
    profile = PROFILES[profile_choice][0]

    cmd = build_command(target, None, profile, [], [])
    run_scan(cmd)


def advanced_mode():
    """وضع متقدم مع كل الخيارات"""
    show_banner()

    # الهدف
    target = get_target()
    if not target:
        return

    # ملف الأهداف
    targets_file = get_targets_file()

    # الملف الشخصي
    profile_choice = show_profile_menu()
    profile = PROFILES[profile_choice][0]

    # الماسحات
    scanners = get_scanners()

    # الوحدات النشطة
    modules = get_active_modules()

    # بناء الأمر
    cmd = build_command(target, targets_file, profile, scanners, modules)

    # التنفيذ
    run_scan(cmd)


def main_menu():
    show_banner()

    console.print(
        Panel.fit(
            "[green][1][/green] 🚀 وضع سريع\n"
            "[green][2][/green] ⚙️  وضع متقدم\n"
            "[green][3][/green] 📋 عرض المهام\n"
            "[green][4][/green] 🔧 فحص النظام\n"
            "[red][0][/red]  ❌ خروج",
            title="القائمة الرئيسية",
            border_style="cyan",
        )
    )

    choice = Prompt.ask(
        "\n[cyan]اختر[/cyan]", choices=["0", "1", "2", "3", "4"], default="1"
    )

    if choice == "1":
        quick_mode()
    elif choice == "2":
        advanced_mode()
    elif choice == "3":
        subprocess.run([sys.executable, "-m", "recon_cli", "list-jobs"])
        input("\nاضغط Enter للمتابعة...")
    elif choice == "4":
        subprocess.run([sys.executable, "-m", "recon_cli", "doctor"])
        input("\nاضغط Enter للمتابعة...")
    elif choice == "0":
        console.print("\n[green]مع السلامة! 👋[/green]\n")
        sys.exit(0)


def main():
    try:
        while True:
            main_menu()
    except KeyboardInterrupt:
        console.print("\n[green]مع السلامة! 👋[/green]\n")
        sys.exit(0)


if __name__ == "__main__":
    main()
