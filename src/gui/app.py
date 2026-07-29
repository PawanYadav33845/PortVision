import os
import sys
import json
import asyncio
from datetime import datetime
from fastapi import FastAPI, BackgroundTasks, Request
from fastapi.responses import HTMLResponse, FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import List, Optional

# Add project root to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from src.utils.helpers import parse_network_range, get_common_ports, get_udp_ports
from src.core.discovery import run_network_sweep
from src.core.scanner import run_port_scan
from src.core.os_detect import detect_os_from_ttl
from src.core.device_profile import classify_device_type, DEVICE_ICONS
from src.core.hostname_resolver import resolve_device_hostname
from src.core.mac_vendor import get_mac_from_arp, lookup_vendor_by_mac
from src.core.subnet_diff import compute_subnet_diff
from src.reporter.html_report import generate_html_executive_report
from src.reporter.report_gen import generate_markdown_report
from src.reporter.json_export import export_results_to_json
from src.reporter.pdf_export import export_session_to_pdf
from src.utils.alerts import send_webhook_alert

app = FastAPI(title="PortVision Modern Recon Dashboard", version="3.5.0")

STATIC_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "static"))
REPORTS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../reports"))

os.makedirs(STATIC_DIR, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

active_scan_state = {
    "status": "Idle",
    "progress": 0,
    "current_target": "",
    "logs": [],
    "results": None
}

class ScanRequest(BaseModel):
    target: str
    scan_mode: str = "TCP"
    profile: str = "ALL"
    lookup_cves: bool = True
    concurrency: int = 100
    webhook_url: Optional[str] = None

@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    index_path = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(index_path):
        with open(index_path, "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>PortVision GUI Engine Ready</h1>"

@app.get("/api/status")
async def get_status():
    return active_scan_state

@app.post("/api/scan")
async def start_scan(req: ScanRequest, background_tasks: BackgroundTasks):
    global active_scan_state
    if active_scan_state["status"] == "Scanning":
        return {"status": "error", "message": "A scan task is already in progress."}

    active_scan_state = {
        "status": "Scanning",
        "progress": 5,
        "current_target": req.target,
        "logs": [f"[{datetime.now().strftime('%H:%M:%S')}] Launching reconnaissance against: {req.target} ({req.scan_mode} mode, profile={req.profile})"],
        "results": None
    }

    background_tasks.add_task(execute_scan_pipeline, req.target, req.scan_mode, req.profile, req.lookup_cves, req.concurrency, req.webhook_url)
    return {"status": "success", "message": "Reconnaissance scan initiated successfully."}

async def execute_scan_pipeline(target_input: str, scan_mode: str, profile: str, lookup_cves: bool, concurrency: int, webhook_url: Optional[str]):
    global active_scan_state
    try:
        candidate_ips = parse_network_range(target_input)
        active_scan_state["logs"].append(f"[{datetime.now().strftime('%H:%M:%S')}] Scope expanded to {len(candidate_ips)} target IP addresses.")
        active_scan_state["progress"] = 15

        active_scan_state["logs"].append(f"[{datetime.now().strftime('%H:%M:%S')}] Executing concurrent ping sweep & MAC resolution...")
        alive_hosts = await run_network_sweep(candidate_ips)
        active_scan_state["progress"] = 30

        if not alive_hosts:
            active_scan_state["logs"].append(f"[{datetime.now().strftime('%H:%M:%S')}] Scan Complete: 0 live hosts responded.")
            active_scan_state["status"] = "Complete"
            active_scan_state["progress"] = 100
            active_scan_state["results"] = {"session_execution_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "scanned_range": target_input, "hosts_discovered_count": 0, "network_discoveries": {}}
            return

        active_scan_state["logs"].append(f"[{datetime.now().strftime('%H:%M:%S')}] Discovered {len(alive_hosts)} live target devices.")
        
        session_capture = {
            "session_execution_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "scanned_range": target_input,
            "hosts_discovered_count": len(alive_hosts),
            "network_discoveries": {}
        }

        step_progress = 60 / max(len(alive_hosts), 1)

        for host_ip in alive_hosts:
            active_scan_state["logs"].append(f"[{datetime.now().strftime('%H:%M:%S')}] Probing {host_ip} ({scan_mode} mode, profile={profile})...")
            scan_results = await run_port_scan(
                host_ip, 
                ports_to_scan=[], 
                scan_mode=scan_mode, 
                lookup_cves=lookup_cves, 
                max_concurrency=concurrency,
                profile=profile
            )
            
            os_data = detect_os_from_ttl(128 if host_ip.startswith("127.") or host_ip.startswith("192.") else 64)
            mac_addr = get_mac_from_arp(host_ip)
            vendor_name = lookup_vendor_by_mac(mac_addr)
            
            open_findings = [r for r in scan_results if "Open" in r.get("status", "")]
            open_count = len(open_findings)

            open_ports_list = [f.get("port") for f in open_findings]
            all_banners = " ".join([f.get("banner", "") for f in open_findings if f.get("banner")])
            web_title = next((f.get("web_audit", {}).get("title") for f in open_findings if f.get("web_audit")), None)

            hostname = await resolve_device_hostname(host_ip, web_title=web_title)
            classified_type = classify_device_type(open_ports_list, all_banners)
            
            if open_count > 0:
                generate_markdown_report(host_ip, scan_results)

            session_capture["network_discoveries"][host_ip] = {
                "device_name": hostname,
                "device_classification": classified_type,
                "device_badge": DEVICE_ICONS.get(classified_type, classified_type),
                "os_fingerprint": os_data,
                "mac_address": mac_addr or "N/A",
                "hardware_vendor": vendor_name,
                "open_ports_detected": open_count,
                "findings": open_findings
            }

            active_scan_state["progress"] += step_progress

        # Compute Subnet Diff vs baseline
        subnet_diff = compute_subnet_diff(session_capture)
        session_capture["subnet_diff"] = subnet_diff

        active_scan_state["logs"].append(f"[{datetime.now().strftime('%H:%M:%S')}] Compiling HTML, PDF & JSON executive reports...")
        json_path = export_results_to_json(session_capture)
        html_path = generate_html_executive_report(session_capture)
        pdf_path = export_session_to_pdf(session_capture)

        if webhook_url:
            active_scan_state["logs"].append(f"[{datetime.now().strftime('%H:%M:%S')}] Transmitting webhook notification alert...")
            send_webhook_alert(webhook_url, session_capture)

        session_capture["reports"] = {
            "json_report": os.path.basename(json_path),
            "html_report": os.path.basename(html_path),
            "pdf_report": os.path.basename(pdf_path)
        }

        active_scan_state["results"] = session_capture
        active_scan_state["status"] = "Complete"
        active_scan_state["progress"] = 100
        active_scan_state["logs"].append(f"[{datetime.now().strftime('%H:%M:%S')}] Scan finished cleanly!")

    except Exception as err:
        active_scan_state["status"] = "Error"
        active_scan_state["logs"].append(f"[{datetime.now().strftime('%H:%M:%S')}] Error: {str(err)}")

@app.get("/api/reports")
async def list_reports():
    reports = []
    if os.path.exists(REPORTS_DIR):
        for f in os.listdir(REPORTS_DIR):
            if f.endswith((".html", ".json", ".md", ".pdf.html")):
                full_p = os.path.join(REPORTS_DIR, f)
                reports.append({
                    "filename": f,
                    "size_kb": round(os.path.getsize(full_p) / 1024, 1),
                    "created": datetime.fromtimestamp(os.path.getmtime(full_p)).strftime("%Y-%m-%d %H:%M:%S")
                })
    return reports

@app.get("/api/reports/download/{filename}")
async def download_report(filename: str):
    file_path = os.path.join(REPORTS_DIR, filename)
    if os.path.exists(file_path):
        return FileResponse(path=file_path, filename=filename)
    return {"error": "File not found"}
