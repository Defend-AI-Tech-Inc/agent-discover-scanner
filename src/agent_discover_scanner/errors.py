"""
User-friendly error messages and validation.
"""

from pathlib import Path

from rich.console import Console

console = Console()


class ValidationError(Exception):
    """Base class for validation errors."""

    pass


def validate_file_exists(filepath: str, file_description: str) -> Path:
    """
    Validate that a file exists and is readable.

    Args:
        filepath: Path to check
        file_description: User-friendly description for error message

    Returns:
        Path object if valid

    Raises:
        ValidationError with helpful message
    """
    path = Path(filepath)

    if not path.exists():
        console.print(f"[red]❌ Error:[/red] {file_description} not found")
        console.print(f"[dim]Looked for: {path.absolute()}[/dim]")
        console.print("\n[yellow]💡 Tip:[/yellow] Make sure you're in the correct directory")
        raise ValidationError(f"{file_description} not found: {filepath}")

    if not path.is_file():
        console.print(f"[red]❌ Error:[/red] {filepath} is a directory, not a file")
        console.print(f"\n[yellow]💡 Tip:[/yellow] Provide the path to the {file_description}")
        raise ValidationError(f"{filepath} is not a file")

    try:
        # Check if readable
        with open(path, "r") as f:
            f.read(1)
    except PermissionError:
        console.print(f"[red]❌ Error:[/red] No permission to read {filepath}")
        console.print(f"\n[yellow]💡 Fix:[/yellow] Run: chmod +r {filepath}")
        raise ValidationError(f"Cannot read {filepath}")
    except Exception as e:
        console.print(f"[red]❌ Error:[/red] Cannot read {filepath}: {e}")
        raise ValidationError(f"Cannot read {filepath}")

    return path


def validate_directory_exists(dirpath: str, dir_description: str) -> Path:
    """
    Validate that a directory exists and is accessible.

    Args:
        dirpath: Path to check
        dir_description: User-friendly description

    Returns:
        Path object if valid

    Raises:
        ValidationError with helpful message
    """
    path = Path(dirpath)

    if not path.exists():
        console.print(f"[red]❌ Error:[/red] {dir_description} not found")
        console.print(f"[dim]Looked for: {path.absolute()}[/dim]")
        console.print("\n[yellow]💡 Tip:[/yellow] Check the path and try again")
        raise ValidationError(f"{dir_description} not found: {dirpath}")

    if not path.is_dir():
        console.print(f"[red]❌ Error:[/red] {dirpath} is not a directory")
        raise ValidationError(f"{dirpath} is not a directory")

    return path


def show_setup_help():
    """Show helpful setup instructions if environment is broken."""
    console.print("\n[bold red]Environment Issue Detected[/bold red]")
    console.print("\n[cyan]Quick Fix:[/cyan]")
    console.print("  1. Recreate virtual environment:")
    console.print("     [dim]rm -rf .venv && uv sync[/dim]")
    console.print("\n  2. Verify installation:")
    console.print("     [dim]uv run python --version[/dim]")
    console.print("\n[yellow]Still having issues?[/yellow]")
    console.print("  • Check: https://github.com/Defend-AI-Tech-Inc/agent-discover-scanner/issues")
    console.print("  • Or run: [dim]uv sync --verbose[/dim] for detailed output\n")


def show_no_findings_help(scan_type: str):
    """Show helpful message when no findings are detected."""
    console.print(f"\n[yellow]ℹ️  No {scan_type} detected[/yellow]")

    if scan_type == "agents":
        console.print("\n[cyan]This could mean:[/cyan]")
        console.print("  ✓ Your codebase is clean (no AI agents)")
        console.print("  • The agents use frameworks we don't detect yet")
        console.print("  • Agents are in a different directory")
        console.print(
            "\n[yellow]💡 Tip:[/yellow] Try scanning parent directory or check supported frameworks"
        )

    elif scan_type == "dependencies":
        console.print("\n[cyan]This could mean:[/cyan]")
        console.print("  ✓ No requirements.txt or package.json found")
        console.print("  • Dependencies are managed differently (poetry, pipenv, etc.)")
        console.print(
            "\n[yellow]💡 Tip:[/yellow] Make sure you're in a Python or JavaScript project directory"
        )
