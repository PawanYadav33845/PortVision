import asyncio
import sys
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

from src.utils.helpers import parse_network_range, get_common_ports
from src.core.discovery import run_network_sweep
from src.core.scanner import run_port_scan
from src.reporter.report_gen import generate_markdown_report
from src.reporter.json_export import export_results_to_json

console = Console()

async def main():
    console.print(
        Panel.fit(
            "[bold cyan]👁️  PORTVISION RECON V2 [/bold cyan]\n[dim]Asynchronous Multi-Protocol Discovery & Threat Analysis Suite[/dim]",
            border_style="cyan",
            padding=(1, 4)
        )
    )
    
    # Prompt accepts single IPs, host names, or CIDR blocks
    user_input = console.input("\n[bold yellow]👉 Enter Target Host, IP, or Subnet Range (e.g., 192.168.1.0/24):[/bold yellow] ").strip()
    if not user_input:
        console.print("[red][-] Error: Target parameters cannot be blank.[/red]")
        return
        
    try:
        # 1. Target Expansion Phase
        candidate_ips = parse_network_range(user_input)
        console.print(f"[green][+] Scopes expanded successfully.[/green] Parsed [bold white]{len(candidate_ips)}[/bold white] network target addresses.")
        
        # 2. Asynchronous Network Sweep Context
        alive_hosts = []
        with Progress(
            SpinnerColumn("earth", speed=1.0),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
            console=console
        ) as progress:
            progress.add_task(description=f"[cyan]Executing concurrent ICMP sweeps across network range...[/cyan]", total=None)
            alive_hosts = await run_network_sweep(candidate_ips)
            
        if not alive_hosts:
            console.print("\n[bold red][!] Network Sweep Complete: 0 live hosts responded to ping queries. Terminating process cleanly.[/bold red]")
            return
            
        console.print(f"[bold green][+] Network Discovery Active![/bold green] Found [bold white]{len(alive_hosts)}[/bold white] responding devices on subnet.")
        
        # Setup session block structure for JSON exporting
        session_capture = {
            "session_execution_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "scanned_range": user_input,
            "hosts_discovered_count": len(alive_hosts),
            "network_discoveries": {}
        }
        
        ports_list = list(get_common_ports().keys())
        
        # 3. Micro-Scan Loop over discovered active hosts
        for host_ip in alive_hosts:
            console.print(f"\n[bold magenta]▼ Commencing Active Scanning Loop against Host: {host_ip}[/bold magenta]")
            
            with Progress(
                SpinnerColumn("dots", speed=1.2),
                TextColumn("[progress.description]{task.description}"),
                transient=True,
                console=console
            ) as progress:
                progress.add_task(description=f"[dim cyan]Probing ports for {host_ip}...[/dim cyan]", total=None)
                scan_results = await run_port_scan(host_ip, ports_list)
                
            # Build and fill terminal summary tables
            table = Table(title=f"Service Log for {host_ip}", title_style="bold green", border_style="dim")
            table.add_column("PORT", style="cyan")
            table.add_column("STATUS")
            table.add_column("SERVICE")
            table.add_column("BANNER METADATA", style="italic dim")
            table.add_column("ALERT ANALYSIS")
            
            open_count = 0
            host_json_log = []
            
            for record in scan_results:
                if record["status"] == "Open":
                    open_count += 1
                    vuln_display = "[green]✔ Clean[/green]"
                    
                    if record["vulnerability"]:
                        severity = record["vulnerability"]["severity"]
                        color = "red" if severity in ["High", "Critical"] else "yellow"
                        vuln_display = f"[{color}]⚠️ {record['vulnerability']['title']}[/{color}]"
                        
                    table.add_row(str(record["port"]), "[bold green]OPEN[/bold green]", record["service"], record["banner"] or "None", vuln_display)
                    host_json_log.append(record)
                    
            if open_count > 0:
                console.print(table)
                # Auto-generate markdown reports for any host with open entries
                generate_markdown_report(host_ip, scan_results)
            else:
                console.print(f"[dim yellow][*] Host {host_ip} responded to sweep but hosts zero open targeted ports.[/dim yellow]")
                
            # Document finding arrays to session capture dictionary
            session_capture["network_discoveries"][host_ip] = {
                "open_ports_detected": open_count,
                "findings": host_json_log
            }
            
        # 4. Finalizing Structural Document Pipeline Output
        console.print("\n[cyan][*] Compiling structured system metrics database arrays...[/cyan]")
        json_path = export_results_to_json(session_capture)
        console.print(f"[bold green]✨ Data Pipeline Success![/bold green] Consolidated session log written safely to:\n[bold white]{json_path}[/bold white]\n")
        
    except Exception as err:
        console.print(f"\n[bold red][-] Runtime Crash Exception Error Encountered: {err}")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        console.print("\n[yellow]\n[-] Operation canceled cleanly by user input command request.[/yellow]")
        sys.exit(0)