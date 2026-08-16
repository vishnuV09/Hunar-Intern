"""
CLI Interface for Password Strength Checker using Rich formatting.
"""

import sys
import os

# Ensure UTF-8 output on Windows terminal
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt
from rich.text import Text
from password_checker import PasswordAnalyzer

console = Console()


def print_banner():
    banner_text = Text()
    banner_text.append("🔐 PASSWORD STRENGTH ANALYZER\n", style="bold cyan")
    banner_text.append("Evaluate strength, entropy, crack time, and flaws instantly", style="dim white")
    console.print(Panel(banner_text, border_style="cyan", expand=False))


def display_analysis(res: dict):
    # Rating Color Mapping for Rich
    color_map = {
        "Weak": "bold red",
        "Okay": "bold yellow",
        "Strong": "bold green",
        "Very Strong": "bold bright_green"
    }
    rating_style = color_map.get(res["rating"], "white")

    # Score Bar representation
    score = res["score"]
    bar_length = 30
    filled = int((score / 100) * bar_length)
    bar = "█" * filled + "░" * (bar_length - filled)

    console.print()
    console.print(f"Password: [bold cyan]{res['password']}[/bold cyan] (Length: {res['length']})")
    console.print(f"Overall Rating: [{rating_style}]{res['rating'].upper()}[/{rating_style}] ({score}/100)")
    console.print(f"Score Meter:    [{rating_style}][{bar}][/{rating_style}]")
    console.print(f"Entropy:        [magenta]{res['entropy']} bits[/magenta]")
    console.print(f"Est. Crack Time:[yellow]{res['crack_time']}[/yellow]")
    console.print()

    # Checklist Table
    table = Table(title="Security Checklist Criteria", show_header=True, header_style="bold magenta")
    table.add_column("Criterion", style="white")
    table.add_column("Status", justify="center")

    crit = res["criteria"]
    check_item = lambda cond, text: table.add_row(text, "[green]✔ PASS[/green]" if cond else "[red]✘ FAIL[/red]")

    check_item(crit["min_length_8"], "Minimum Length (>= 8 chars)")
    check_item(crit["min_length_12"], "Recommended Length (>= 12 chars)")
    check_item(crit["has_lowercase"], "Contains Lowercase Letters (a-z)")
    check_item(crit["has_uppercase"], "Contains Uppercase Letters (A-Z)")
    check_item(crit["has_digits"], "Contains Numbers (0-9)")
    check_item(crit["has_symbols"], "Contains Special Symbols (!@#$)")
    check_item(crit["no_common_patterns"], "No Common Leaked Patterns")
    check_item(crit["no_repeats"], "No Consecutive Repeated Chars")

    console.print(table)
    console.print()

    # Flaws & Suggestions
    if res["flaws"]:
        console.print("[bold red]⚠ Detected Security Flaws:[/bold red]")
        for flaw in res["flaws"]:
            console.print(f"  • [red]{flaw}[/red]")
        console.print()

    console.print("[bold cyan]💡 Recommendations to Strengthen:[/bold cyan]")
    for sug in res["suggestions"]:
        console.print(f"  • [yellow]{sug}[/yellow]")
    console.print()


def interactive_cli():
    print_banner()
    while True:
        console.print("\n[bold dim]Options: [1] Analyze Password  [2] Generate Strong Password  [3] Exit[/bold dim]")
        choice = Prompt.ask("Select an option", choices=["1", "2", "3"], default="1")

        if choice == "1":
            pwd = Prompt.ask("\nEnter password to analyze", password=True)
            if not pwd:
                console.print("[yellow]Password cannot be empty.[/yellow]")
                continue
            analyzer = PasswordAnalyzer(pwd)
            res = analyzer.analyze()
            display_analysis(res)

        elif choice == "2":
            length_str = Prompt.ask("Desired password length", default="16")
            try:
                length = int(length_str)
            except ValueError:
                length = 16
            generated = PasswordAnalyzer.generate_strong_password(length=length)
            console.print(f"\n✨ Generated Strong Password: [bold green]{generated}[/bold green]")
            res = PasswordAnalyzer(generated).analyze()
            display_analysis(res)

        elif choice == "3":
            console.print("\n[bold green]Stay Safe & Secure! Goodbye![/bold green]")
            break


if __name__ == "__main__":
    if len(sys.argv) > 1:
        # Quick CLI check from arg: python cli.py mypassword
        pwd_arg = sys.argv[1]
        res = PasswordAnalyzer(pwd_arg).analyze()
        display_analysis(res)
    else:
        interactive_cli()
