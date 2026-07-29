import asyncio
import logging
from datetime import datetime
from src.utils.helpers import parse_network_range
from src.core.discovery import run_network_sweep
from src.core.scanner import run_port_scan
from src.core.subnet_diff import compute_subnet_diff
from src.utils.alerts import send_webhook_alert
from src.reporter.json_export import export_results_to_json

async def run_scheduled_audit_loop(
    target_input: str, 
    interval_seconds: int = 3600, 
    webhook_url: str = None, 
    scan_mode: str = "TCP"
):
    """
    Background scheduler loop that performs periodic subnet audits.
    Sends Webhook alerts when new hosts, new open ports, or vulnerabilities appear.
    """
    logging.info(f"Starting scheduled subnet monitoring for target '{target_input}' every {interval_seconds}s...")
    
    while True:
        try:
            candidate_ips = parse_network_range(target_input)
            alive_hosts = await run_network_sweep(candidate_ips)

            session_capture = {
                "session_execution_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "scanned_range": target_input,
                "hosts_discovered_count": len(alive_hosts),
                "network_discoveries": {}
            }

            for host_ip in alive_hosts:
                scan_results = await run_port_scan(host_ip, scan_mode=scan_mode, lookup_cves=False)
                open_findings = [r for r in scan_results if "Open" in r.get("status", "")]
                session_capture["network_discoveries"][host_ip] = {
                    "open_ports_detected": len(open_findings),
                    "findings": open_findings
                }

            # Calculate Subnet Diff
            diff = compute_subnet_diff(session_capture)
            export_results_to_json(session_capture)

            # Trigger Webhook Alert if changes detected
            if webhook_url and (diff["new_hosts"] or diff["newly_opened_ports"]):
                send_webhook_alert(webhook_url, session_capture)

        except Exception as err:
            logging.error(f"Scheduled audit loop error: {err}")

        await asyncio.sleep(interval_seconds)
