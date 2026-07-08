import asyncio
import sys
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

from src.utils.helpers import validate_target, get_common_ports
from src.core.scanner import run_port_scan
from src.reporter.report_gen import generate_markdown_report

# Initialize the Rich console controller
console = Console()

async def main():
    # 1. Display a clean, stylized brand header
    console.print(
        Panel.fit(
            "[bold cyan]👁️  PORTVISION [/bold cyan]\n[dim]Asynchronous Network Reconnaissance & Vulnerability Engine[/dim]",
            border_style="cyan",
            padding=(1, 4)
        )
    )
    
    # Prompt user safely using Rich's stylized syntax
    user_input = console.input("\n[bold yellow]👉 Enter target IP address or Domain:[/bold yellow] ").strip()
    if not user_input:
        console.print("[red][-] Error: Target cannot be empty.[/red]")
        return
        
    try:
        # 2. Target validation boundary
        target_ip = validate_target(user_input)
        console.print(f"\n[green][+] Target verified successfully.[/green] Target IP resolved to: [bold white]{target_ip}[/bold white]")
        
        ports_list = list(get_common_ports().keys())
        
        # 3. Dynamic Progress Spinner Context
        with Progress(
            SpinnerColumn("dots", speed=1.2),
            TextColumn("[progress.description]{task.description}"),
            transient=True, # Automatically erases the spinner line when done
            console=console
        ) as progress:
            progress.add_task(description=f"[cyan]Scanning {len(ports_list)} ports concurrently via non-blocking sockets...[/cyan]", total=None)
            results = await run_port_scan(target_ip, ports_list)
            
        # 4. Render the Discoveries Grid Table
        table = Table(title=f"\nActive Service Discoveries for {target_ip}", title_style="bold magenta", border_style="dim")
        table.add_column("PORT", justify="left", style="cyan", no_wrap=True)
        table.add_column("STATUS", justify="center")
        table.add_column("SERVICE NAME", justify="left", style="white")
        table.add_column("GATHERED BANNER METADATA", justify="left", style="italic dim")
        table.add_column("SECURITY ALERT", justify="left")

        open_ports_count = 0
        for record in results:
            if record["status"] == "Open":
                open_ports_count += 1
                status_display = "[bold green]OPEN[/bold green]"
                banner_display = record["banner"] if record["banner"] else "No banner responded"
                
                # Check if our vulnerability matching matrix flagged anything
                if record["vulnerability"]:
                    severity = record["vulnerability"]["severity"]
                    color = "red" if severity in ["High", "Critical"] else "yellow"
                    vuln_display = f"[{color}]⚠️ {record['vulnerability']['title']} ({severity})[/{color}]"
                else:
                    vuln_display = "[green]✔ Clean[/green]"
                    
                table.add_row(str(record["port"]), status_display, record["service"], banner_display, vuln_display)
                
        if open_ports_count > 0:
            console.print(table)
            
            # 5. Export Report
            console.print("\n[cyan][*] Compiling audit logs into Markdown report...[/cyan]")
            saved_path = generate_markdown_report(target_ip, results)
            console.print(f"[bold green]✨ Success![/bold green] Local report generated at:\n[bold white]{saved_path}[/bold white]\n")
        else:
            console.print("\n[yellow][!] Scan execution completed. Zero active open ports discovered on target host.[/yellow]")
            
    except ValueError as err:
        console.print(f"\n[bold red][-] Validation Failure:[/bold red] {err}")
    except Exception as err:
        console.print(f"\n[bold red][-] Critical Runtime Exception Error:[/bold red] {err}")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        console.print("\n[yellow]\n[-] Scan process terminated by user closure command. Exiting cleanly.[/yellow]")
        sys.exit(0)