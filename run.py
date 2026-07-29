import os
import sys
import socket
import argparse
import asyncio
from datetime import datetime

# Enforce UTF-8 encoding on Windows console streams to prevent charmap UnicodeEncodeError
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

from src.utils.helpers import parse_network_range, get_common_ports, get_udp_ports
from src.core.discovery import run_network_sweep
from src.core.scanner import run_port_scan
from src.core.device_profile import classify_device_type, DEVICE_ICONS
from src.core.hostname_resolver import resolve_device_hostname
from src.core.mac_vendor import get_mac_from_arp, lookup_vendor_by_mac
from src.core.subnet_diff import compute_subnet_diff
from src.reporter.report_gen import generate_markdown_report
from src.reporter.html_report import generate_html_executive_report
from src.reporter.json_export import export_results_to_json
from src.reporter.pdf_export import export_session_to_pdf

console = Console()

def find_available_port(default_port: int = 8000) -> int:
    """Checks if a port is in use and returns the next free port."""
    for p in range(default_port, default_port + 20):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if s.connect_ex(("127.0.0.1", p)) != 0:
                return p
    return default_port

def launch_gui_server(host: str = "127.0.0.1", port: int = 8000):
    """Launches the Uvicorn ASGI server hosting the PortVision Web GUI."""
    target_port = find_available_port(port)
    console.print(Panel.fit(
        f"[bold cyan]🌐 Launching PortVision Web GUI Server[/bold cyan]\n"
        f"[green]Dashboard URL:[/green] [bold white]http://{host}:{target_port}[/bold white]\n"
        f"[dim]Press Ctrl+C in terminal to stop server[/dim]",
        border_style="cyan"
    ))
    import uvicorn
    uvicorn.run("src.gui.app:app", host=host, port=target_port, reload=False)

async def run_cli_scan(user_input: str, scan_mode: str, profile: str, lookup_cves: bool):
    try:
        # 1. Target Expansion
        candidate_ips = parse_network_range(user_input)
        console.print(f"[green][+] Scopes expanded successfully.[/green] Target addresses: [bold white]{len(candidate_ips)}[/bold white]")

        # 2. ICMP Ping Sweep & MAC Resolution
        alive_hosts = []
        with Progress(
            SpinnerColumn("earth", speed=1.0),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
            console=console
        ) as progress:
            progress.add_task(description="[cyan]Executing ICMP discovery sweeps & MAC resolution...[/cyan]", total=None)
            alive_hosts = await run_network_sweep(candidate_ips)

        if not alive_hosts:
            console.print("\n[bold red][!] Sweep Complete: 0 live hosts responded. Process complete.[/bold red]")
            return

        console.print(f"[bold green][+] Network Sweep Active![/bold green] Found [bold white]{len(alive_hosts)}[/bold white] live responding hosts.")

        session_capture = {
            "session_execution_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "scanned_range": user_input,
            "hosts_discovered_count": len(alive_hosts),
            "network_discoveries": {}
        }

        # 3. Active Scanning Loop
        for host_ip in alive_hosts:
            console.print(f"\n[bold magenta]▼ Scanning Host: {host_ip} ({scan_mode} mode, profile={profile})[/bold magenta]")

            with Progress(
                SpinnerColumn("dots", speed=1.2),
                TextColumn("[progress.description]{task.description}"),
                transient=True,
                console=console
            ) as progress:
                progress.add_task(description=f"[dim cyan]Probing ports on {host_ip}...[/dim cyan]", total=None)
                scan_results = await run_port_scan(
                    host_ip, 
                    ports_to_scan=[], 
                    scan_mode=scan_mode, 
                    lookup_cves=lookup_cves,
                    profile=profile
                )

            open_count = 0
            host_json_log = []
            open_ports_list = []
            all_banners = []
            web_title = None

            for record in scan_results:
                status = record.get("status", "Closed")
                if "Open" in status:
                    open_count += 1
                    open_ports_list.append(record["port"])
                    if record.get("banner"):
                        all_banners.append(record["banner"])
                    if record.get("web_audit") and record["web_audit"].get("title"):
                        web_title = record["web_audit"]["title"]
                    host_json_log.append(record)

            hostname = await resolve_device_hostname(host_ip, web_title=web_title)
            mac_addr = get_mac_from_arp(host_ip)
            vendor_name = lookup_vendor_by_mac(mac_addr)
            classified_type = classify_device_type(open_ports_list, " ".join(all_banners))
            dev_badge = DEVICE_ICONS.get(classified_type, classified_type)

            mac_str = f" | MAC: {mac_addr} ({vendor_name})" if mac_addr else ""

            # Build Terminal Summary Table
            table = Table(title=f"Service Findings for {host_ip} ({hostname}){mac_str} [{dev_badge}]", title_style="bold green", border_style="dim")
            table.add_column("PORT", style="cyan")
            table.add_column("PROTO", style="blue")
            table.add_column("STATUS")
            table.add_column("SERVICE")
            table.add_column("CATEGORY", style="dim")
            table.add_column("BANNER / METADATA", style="italic dim")
            table.add_column("SECURITY ANALYSIS")

            for record in host_json_log:
                vuln_display = "[green]✔ Clean[/green]"
                vuln = record.get("vulnerability")
                if vuln:
                    sev = vuln.get("severity", "Medium")
                    color = "red" if sev in ["High", "Critical"] else "yellow"
                    cve_tag = f"[{vuln.get('cve_id')}] " if vuln.get("cve_id") else ""
                    vuln_display = f"[{color}]⚠️ {cve_tag}{vuln['title']}[/{color}]"

                table.add_row(
                    str(record["port"]),
                    record.get("protocol", "TCP"),
                    f"[bold green]{record.get('status', 'OPEN').upper()}[/bold green]",
                    record.get("service", "Unknown"),
                    record.get("category", "General"),
                    record.get("banner") or "None",
                    vuln_display
                )

            if open_count > 0:
                console.print(table)
                generate_markdown_report(host_ip, scan_results)
            else:
                console.print(f"[dim yellow][*] Host {host_ip} ({hostname}) responded to ping but hosts 0 open ports for profile '{profile}'.[/dim yellow]")

            session_capture["network_discoveries"][host_ip] = {
                "device_name": hostname,
                "device_classification": classified_type,
                "device_badge": dev_badge,
                "mac_address": mac_addr or "N/A",
                "hardware_vendor": vendor_name,
                "open_ports_detected": open_count,
                "findings": host_json_log
            }

        # Subnet Diff
        subnet_diff = compute_subnet_diff(session_capture)
        session_capture["subnet_diff"] = subnet_diff
        if subnet_diff.get("new_hosts") or subnet_diff.get("newly_opened_ports"):
            console.print("\n[bold yellow]🔄 Subnet Diff Alert:[/bold yellow]")
            if subnet_diff["new_hosts"]:
                console.print(f"  [yellow]• New Hosts Joined:[/yellow] {', '.join(subnet_diff['new_hosts'])}")
            if subnet_diff["newly_opened_ports"]:
                console.print(f"  [yellow]• Newly Opened Ports:[/yellow] {subnet_diff['newly_opened_ports']}")

        # 4. Generate Reports
        console.print("\n[cyan][*] Compiling structured executive reports...[/cyan]")
        json_path = export_results_to_json(session_capture)
        html_path = generate_html_executive_report(session_capture)
        pdf_path = export_session_to_pdf(session_capture)
        
        console.print(f"[bold green]✨ Reports Generated Successfully![/bold green]")
        console.print(f" 📄 Executive HTML Dashboard: [bold white]{html_path}[/bold white]")
        console.print(f" 📑 PDF Executive Document: [bold white]{pdf_path}[/bold white]")
        console.print(f" 📊 JSON Session Data: [bold white]{json_path}[/bold white]\n")

    except Exception as err:
        console.print(f"\n[bold red][-] Exception Error Encountered: {err}[/bold red]")

def main():
    parser = argparse.ArgumentParser(description="PortVision Multi-Protocol Reconnaissance & Device Profiling Suite")
    parser.add_argument("--gui", action="store_true", help="Launch the Web GUI interface")
    parser.add_argument("--target", type=str, help="Target host, IP, or CIDR range (e.g. 192.168.1.0/24)")
    parser.add_argument("--mode", type=str, choices=["TCP", "UDP", "SYN", "COMBINED"], default="TCP", help="Scanning protocol mode")
    parser.add_argument("--profile", type=str, choices=["ALL", "AUTO", "ROUTER", "PRINTER", "IOT", "NAS", "DATABASE", "WEB", "WORKSTATION"], default="ALL", help="Target device scan profile")
    parser.add_argument("--no-cve", action="store_true", help="Disable live online CVE API lookups")
    args = parser.parse_args()

    if args.gui:
        launch_gui_server()
        return

    console.print(
        Panel.fit(
            "[bold cyan]👁️ PORTVISION v3.5 [/bold cyan]\n"
            "[dim]Multi-Protocol Recon, MAC Vendor OUI, Subnet Diffing & PDF Suite[/dim]",
            border_style="cyan",
            padding=(1, 4)
        )
    )

    user_input = args.target
    if not user_input:
        user_input = console.input("\n[bold yellow]👉 Enter Target Host, IP, or Subnet Range (e.g. 192.168.1.0/24):[/bold yellow] ").strip()
        if not user_input:
            console.print("[red][-] Error: Target parameter cannot be blank.[/red]")
            return

    scan_mode = args.mode
    profile = args.profile

    if not args.target:
        console.print("\n[bold cyan]Select Protocol Scanning Mode:[/bold cyan]")
        console.print("  [white]1.[/white] TCP Connect Scan (Default)")
        console.print("  [white]2.[/white] Non-blocking UDP Probing (DNS, NTP, SNMP, SSDP)")
        console.print("  [white]3.[/white] Raw Socket SYN Stealth Scan")
        console.print("  [white]4.[/white] Combined Dual Sweep (TCP + UDP)")
        console.print("  [white]5.[/white] Launch Web GUI Interface")
        
        mode_choice = console.input("\n[yellow]Choice [1-5] (default 1): [/yellow]").strip()
        if mode_choice == "2":
            scan_mode = "UDP"
        elif mode_choice == "3":
            scan_mode = "SYN"
        elif mode_choice == "4":
            scan_mode = "COMBINED"
        elif mode_choice == "5":
            launch_gui_server()
            return
        else:
            scan_mode = "TCP"

    lookup_cves = not args.no_cve
    asyncio.run(run_cli_scan(user_input, scan_mode, profile, lookup_cves))

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[yellow]\n[-] Scan canceled cleanly by user.[/yellow]")
        sys.exit(0)