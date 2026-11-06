import typer
from pathlib import Path
from rich.console import Console
from rich.table import Table
from deepguard.analyzer import analyze_code

app = typer.Typer(help="DeepGuard: SAST tool for AI-generated code.")
console = Console()

@app.callback()
def callback():
    """
    DeepGuard: SAST tool for AI-generated code.
    """
    pass

@app.command()
def scan(file_path: Path = typer.Argument(..., help="Path to the Python file to analyze")):
    if not file_path.exists():
        console.print(f"[bold red]Error:[/bold red] File {file_path} not found.")
        raise typer.Exit(code=1)

    source_code = file_path.read_text(encoding="utf-8")
    console.print(f"\n[bold cyan]Scanning:[/bold cyan] {file_path}\n")

    findings = analyze_code(source_code)

    if not findings:
        console.print("[bold green]No vulnerabilities found. Code is secure.[/bold green]\n")
        raise typer.Exit(code=0)

    table = Table(title="Security Findings", show_header=True, header_style="bold magenta")
    table.add_column("Line", justify="right")
    table.add_column("Severity")
    table.add_column("Issue")

    for finding in findings:
        severity_color = "red" if finding.severity in ["CRITICAL", "HIGH"] else "yellow"
        table.add_row(str(finding.line), f"[{severity_color}]{finding.severity}[/{severity_color}]", finding.message)

    console.print(table)
    console.print(f"\n[bold red]Total findings: {len(findings)}[/bold red]\n")
    raise typer.Exit(code=1)

if __name__ == "__main__":
    app()