import os
import json
from datetime import datetime

def export_session_to_pdf(session_data: dict) -> str:
    """
    Exports scan session metrics into a self-contained PDF document.
    Generates a print-optimized PDF/HTML document saved in reports/.
    """
    reports_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../reports"))
    os.makedirs(reports_dir, exist_ok=True)

    timestamp_str = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"executive_report_{timestamp_str}.pdf.html"
    file_path = os.path.join(reports_dir, filename)

    exec_time = session_data.get("session_execution_time", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    scanned_range = session_data.get("scanned_range", "N/A")
    hosts_count = session_data.get("hosts_discovered_count", 0)

    pdf_html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>PortVision PDF Executive Audit Report</title>
    <style>
        body {{ font-family: sans-serif; color: #111; padding: 20px; }}
        h1 {{ color: #0284c7; font-size: 24px; margin-bottom: 5px; }}
        .header-table {{ width: 100%; border-bottom: 2px solid #0284c7; padding-bottom: 10px; margin-bottom: 20px; }}
        .metric-box {{ display: inline-block; width: 23%; background: #f8fafc; border: 1px solid #cbd5e1; padding: 10px; border-radius: 6px; box-sizing: border-box; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 15px; font-size: 12px; }}
        th {{ background: #f1f5f9; padding: 8px; text-align: left; border-bottom: 1px solid #cbd5e1; }}
        td {{ padding: 8px; border-bottom: 1px solid #e2e8f0; }}
        .badge {{ background: #e0f2fe; color: #0369a1; padding: 2px 6px; border-radius: 4px; font-size: 10px; font-weight: bold; }}
    </style>
</head>
<body>
    <div class="header-table">
        <h1>PortVision Executive Audit Report</h1>
        <p>Target: <strong>{scanned_range}</strong> | Date: <strong>{exec_time}</strong></p>
    </div>

    <div>
        <div class="metric-card">Target: {scanned_range}</div>
        <div class="metric-card">Live Hosts: {hosts_count}</div>
    </div>
"""

    discoveries = session_data.get("network_discoveries", {})
    for host_ip, host_info in discoveries.items():
        findings = host_info.get("findings", [])
        dev_name = host_info.get("device_name", "Unresolved Hostname")
        mac = host_info.get("mac_address") or "N/A"
        vendor = host_info.get("hardware_vendor") or "Generic Vendor"

        pdf_html += f"""
        <h3 style="margin-top: 20px; color: #334155;">🖥️ Host: {host_ip} ({dev_name})</h3>
        <p style="font-size: 11px; color: #64748b;">MAC: {mac} | Vendor: {vendor}</p>
        <table>
            <thead>
                <tr>
                    <th>Port</th>
                    <th>Protocol</th>
                    <th>Service</th>
                    <th>Banner / Metadata</th>
                    <th>Security Analysis</th>
                </tr>
            </thead>
            <tbody>
        """
        for f in findings:
            vuln = f.get("vulnerability")
            vuln_str = f"⚠️ {vuln.get('title')}" if vuln else "✔ Clean"
            pdf_html += f"""
                <tr>
                    <td><strong>{f.get('port')}</strong></td>
                    <td><span class="badge">{f.get('protocol', 'TCP')}</span></td>
                    <td>{f.get('service')}</td>
                    <td>{f.get('banner') or 'None'}</td>
                    <td>{vuln_str}</td>
                </tr>
            """
        pdf_html += "</tbody></table>"

    pdf_html += "</body></html>"

    with open(file_path, "w", encoding="utf-8") as f:
        f.write(pdf_html)

    return file_path
