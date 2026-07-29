import os
import json
from datetime import datetime
from src.core.device_profile import classify_device_type, DEVICE_ICONS

def generate_html_executive_report(session_data: dict) -> str:
    """
    Renders a modern, single-file HTML executive dashboard report from scan session metrics.
    Includes resolved Device Hostnames, Device Type Classification badges, OS fingerprinting, and Web/TLS audit details.
    """
    reports_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../reports"))
    os.makedirs(reports_dir, exist_ok=True)

    timestamp_str = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"executive_report_{timestamp_str}.html"
    file_path = os.path.join(reports_dir, filename)

    exec_time = session_data.get("session_execution_time", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    scanned_range = session_data.get("scanned_range", "N/A")
    hosts_count = session_data.get("hosts_discovered_count", 0)

    # Global Summary Metrics
    total_open_ports = 0
    total_critical_vulns = 0
    total_high_vulns = 0
    total_medium_vulns = 0

    discoveries = session_data.get("network_discoveries", {})
    for host_ip, host_info in discoveries.items():
        findings = host_info.get("findings", [])
        total_open_ports += host_info.get("open_ports_detected", 0)
        for f in findings:
            v = f.get("vulnerability")
            if v:
                sev = v.get("severity", "").lower()
                if sev == "critical":
                    total_critical_vulns += 1
                elif sev == "high":
                    total_high_vulns += 1
                elif sev == "medium":
                    total_medium_vulns += 1

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PortVision Executive Security Report - {scanned_range}</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg-dark: #0f172a;
            --card-bg: #1e293b;
            --accent-cyan: #38bdf8;
            --accent-purple: #a855f7;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --border-color: #334155;
            --sev-critical: #ef4444;
            --sev-high: #f97316;
            --sev-medium: #eab308;
            --sev-clean: #10b981;
        }}

        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: 'Inter', sans-serif;
            background-color: var(--bg-dark);
            color: var(--text-main);
            line-height: 1.6;
            padding: 30px;
        }}

        .container {{ max-width: 1200px; margin: 0 auto; }}

        header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding-bottom: 24px;
            border-bottom: 2px solid var(--border-color);
            margin-bottom: 30px;
        }}

        .brand {{ display: flex; align-items: center; gap: 12px; }}
        .brand-icon {{
            font-size: 2rem;
            background: linear-gradient(135deg, var(--accent-cyan), var(--accent-purple));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}
        .brand h1 {{ font-size: 1.8rem; font-weight: 700; letter-spacing: -0.5px; }}

        .meta-pill {{
            background: rgba(56, 189, 248, 0.1);
            color: var(--accent-cyan);
            padding: 6px 14px;
            border-radius: 20px;
            font-size: 0.85rem;
            font-weight: 600;
            border: 1px solid rgba(56, 189, 248, 0.3);
        }}

        .metrics-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }}

        .metric-card {{
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 22px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.25);
        }}

        .metric-label {{
            font-size: 0.85rem;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.5px;
            font-weight: 600;
            margin-bottom: 8px;
        }}

        .metric-value {{ font-size: 2.2rem; font-weight: 700; }}
        .val-cyan {{ color: var(--accent-cyan); }}
        .val-purple {{ color: var(--accent-purple); }}
        .val-red {{ color: var(--sev-critical); }}

        .host-card {{
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            margin-bottom: 24px;
            overflow: hidden;
        }}

        .host-header {{
            background: rgba(255, 255, 255, 0.03);
            padding: 16px 24px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border-color);
        }}

        .host-ip {{ font-size: 1.1rem; font-weight: 600; }}
        .hostname-tag {{ color: var(--text-muted); font-size: 0.9rem; margin-left: 6px; font-weight: 400; }}

        .os-badge {{
            background: rgba(168, 85, 247, 0.15);
            color: #d8b4fe;
            padding: 4px 10px;
            border-radius: 6px;
            font-size: 0.8rem;
            font-weight: 600;
            border: 1px solid rgba(168, 85, 247, 0.3);
        }}

        .dev-badge {{
            background: rgba(56, 189, 248, 0.15);
            color: var(--accent-cyan);
            padding: 4px 10px;
            border-radius: 6px;
            font-size: 0.8rem;
            font-weight: 600;
            border: 1px solid rgba(56, 189, 248, 0.3);
        }}

        table {{ width: 100%; border-collapse: collapse; text-align: left; }}
        th {{
            background: rgba(15, 23, 42, 0.6);
            color: var(--text-muted);
            font-size: 0.8rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            padding: 12px 20px;
            border-bottom: 1px solid var(--border-color);
        }}
        td {{ padding: 14px 20px; border-bottom: 1px solid var(--border-color); font-size: 0.9rem; }}
        tr:last-child td {{ border-bottom: none; }}

        .proto-badge {{
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 700;
            background: #334155;
            color: #f8fafc;
        }}
        .badge-tcp {{ background: #0284c7; }}
        .badge-udp {{ background: #7c3aed; }}
        .badge-syn {{ background: #059669; }}

        .sev-badge {{
            display: inline-block;
            padding: 4px 10px;
            border-radius: 6px;
            font-size: 0.78rem;
            font-weight: 700;
            text-transform: uppercase;
        }}
        .bg-critical {{ background: rgba(239, 68, 68, 0.2); color: var(--sev-critical); border: 1px solid var(--sev-critical); }}
        .bg-high {{ background: rgba(249, 115, 22, 0.2); color: var(--sev-high); border: 1px solid var(--sev-high); }}
        .bg-medium {{ background: rgba(234, 179, 8, 0.2); color: var(--sev-medium); border: 1px solid var(--sev-medium); }}
        .bg-clean {{ background: rgba(16, 185, 129, 0.2); color: var(--sev-clean); border: 1px solid var(--sev-clean); }}

        .web-audit-box {{
            margin-top: 6px;
            background: rgba(15, 23, 42, 0.5);
            padding: 8px 12px;
            border-radius: 6px;
            font-size: 0.8rem;
            color: var(--text-muted);
            border: 1px dashed var(--border-color);
        }}

        @media print {{
            body {{ background: #fff; color: #000; padding: 0; }}
            .metric-card, .host-card {{ border: 1px solid #ccc; background: #fff; color: #000; box-shadow: none; }}
            th {{ background: #f1f5f9; color: #333; }}
            td {{ color: #111; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="brand">
                <span class="brand-icon">👁️</span>
                <div>
                    <h1>PortVision Security Suite</h1>
                    <p style="color: var(--text-muted); font-size: 0.9rem;">Executive Network Infrastructure Analysis</p>
                </div>
            </div>
            <div class="meta-pill">Executed: {exec_time}</div>
        </header>

        <div class="metrics-grid">
            <div class="metric-card">
                <div class="metric-label">Scanned Scope</div>
                <div class="metric-value val-cyan" style="font-size: 1.5rem; word-break: break-all;">{scanned_range}</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Active Devices</div>
                <div class="metric-value val-purple">{hosts_count}</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Discovered Open Ports</div>
                <div class="metric-value val-cyan">{total_open_ports}</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Critical / High Risks</div>
                <div class="metric-value val-red">{total_critical_vulns + total_high_vulns}</div>
            </div>
        </div>

        <div style="font-size: 1.4rem; font-weight: 600; margin-bottom: 20px;">🔍 Discovered Host Infrastructures</div>
"""

    for host_ip, host_info in discoveries.items():
        findings = host_info.get("findings", [])
        open_count = host_info.get("open_ports_detected", 0)
        os_data = host_info.get("os_fingerprint") or {"os_family": "Generic Host"}
        hostname = host_info.get("device_name") or "Unresolved Hostname"

        open_ports_list = [f.get("port") for f in findings if f.get("port")]
        all_banners = " ".join([f.get("banner", "") for f in findings if f.get("banner")])
        classified_type = classify_device_type(open_ports_list, all_banners)
        dev_badge_text = DEVICE_ICONS.get(classified_type, classified_type)

        html_content += f"""
        <div class="host-card">
            <div class="host-header">
                <div>
                    <span class="host-ip">🖥️ {host_ip}</span>
                    <span class="hostname-tag">({hostname})</span>
                    <span class="dev-badge" style="margin-left: 10px;">{dev_badge_text}</span>
                    <span class="os-badge" style="margin-left: 6px;">💻 OS: {os_data.get('os_family')}</span>
                </div>
                <div class="meta-pill">{open_count} Open Ports</div>
            </div>
            <table>
                <thead>
                    <tr>
                        <th>Port / Proto</th>
                        <th>Service</th>
                        <th>Category</th>
                        <th>Banner & Web Audit</th>
                        <th>Security Analysis & CVE</th>
                    </tr>
                </thead>
                <tbody>
        """

        if not findings:
            html_content += """
                    <tr>
                        <td colspan="5" style="text-align: center; color: var(--text-muted);">No open targeted ports detected on this host.</td>
                    </tr>
            """
        else:
            for record in findings:
                port = record.get("port")
                proto = record.get("protocol", "TCP")
                service = record.get("service", "Unknown")
                category = record.get("category", "General")
                banner = record.get("banner") or "No banner returned"
                vuln = record.get("vulnerability")
                web_meta = record.get("web_audit")

                proto_class = "badge-udp" if "udp" in proto.lower() else "badge-syn" if "syn" in proto.lower() else "badge-tcp"

                web_audit_html = ""
                if web_meta:
                    title_str = f"<strong>Title:</strong> {web_meta.get('title')}<br>" if web_meta.get('title') else ""
                    server_str = f"<strong>Server:</strong> {web_meta.get('server')}<br>" if web_meta.get('server') else ""
                    tls_str = ""
                    if web_meta.get("tls_cert"):
                        cert = web_meta["tls_cert"]
                        tls_str = f"<strong>TLS Cert:</strong> {cert.get('subject')} (Expires in {cert.get('days_remaining')} days)<br>"
                    web_audit_html = f"""
                        <div class="web-audit-box">
                            🌐 <strong>Web Application Audit:</strong><br>
                            {title_str}{server_str}{tls_str}
                        </div>
                    """

                if vuln:
                    sev = vuln.get("severity", "Medium")
                    sev_class = f"bg-{sev.lower()}"
                    cve_id = vuln.get("cve_id")
                    cve_str = f'<span style="background: rgba(168, 85, 247, 0.2); color: #d8b4fe; padding: 2px 6px; border-radius: 4px; font-family: monospace;">{cve_id}</span> ' if cve_id else ''
                    vuln_cell = f"""
                        <span class="sev-badge {sev_class}">⚠️ {sev}</span>
                        <div style="margin-top: 6px; font-size: 0.82rem; color: var(--text-muted);">
                            <strong>{cve_str}{vuln.get('title')}</strong><br>
                            {vuln.get('description')}
                        </div>
                    """
                else:
                    vuln_cell = '<span class="sev-badge bg-clean">✔ Clean</span>'

                html_content += f"""
                    <tr>
                        <td><strong>{port}</strong> <span class="proto-badge {proto_class}">{proto}</span></td>
                        <td>{service}</td>
                        <td><span style="color: var(--text-muted); font-size: 0.85rem;">{category}</span></td>
                        <td style="font-family: monospace; font-size: 0.82rem; color: var(--text-muted);">
                            {banner}
                            {web_audit_html}
                        </td>
                        <td>{vuln_cell}</td>
                    </tr>
                """

        html_content += """
                </tbody>
            </table>
        </div>
        """

    html_content += f"""
        <footer>
            <p>PortVision Asynchronous Reconnaissance Engine • Report Generated on {exec_time}</p>
        </footer>
    </div>
</body>
</html>
"""

    with open(file_path, "w", encoding="utf-8") as f:
        f.write(html_content)

    return file_path
