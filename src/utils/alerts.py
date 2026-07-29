import json
import urllib.request
from typing import Optional

def send_webhook_alert(webhook_url: str, session_data: dict) -> bool:
    """
    Transmits scan summary & threat alert payload to Slack, Discord, or generic Webhooks.
    """
    if not webhook_url:
        return False

    scanned_range = session_data.get("scanned_range", "Unknown Target")
    exec_time = session_data.get("session_execution_time", "")
    hosts_count = session_data.get("hosts_discovered_count", 0)

    total_ports = 0
    vulns_flagged = []

    discoveries = session_data.get("network_discoveries", {})
    for host_ip, host_info in discoveries.items():
        findings = host_info.get("findings", [])
        total_ports += host_info.get("open_ports_detected", 0)
        for f in findings:
            if f.get("vulnerability"):
                v = f["vulnerability"]
                vulns_flagged.append(f"{host_ip}:{f['port']} - {v.get('title')} ({v.get('severity')})")

    # Discord / Slack formatted JSON payload
    payload = {
        "content": f"🚨 **PortVision Recon Summary Alert**",
        "embeds": [
            {
                "title": f"Scan Summary for {scanned_range}",
                "color": 15158332 if vulns_flagged else 3066993,
                "fields": [
                    {"name": "Execution Time", "value": str(exec_time), "inline": True},
                    {"name": "Live Hosts", "value": str(hosts_count), "inline": True},
                    {"name": "Open Ports", "value": str(total_ports), "inline": True},
                    {"name": "Vulnerabilities Flagged", "value": str(len(vulns_flagged)), "inline": False}
                ],
                "footer": {"text": "PortVision Security Recon Suite"}
            }
        ]
    }

    try:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(webhook_url, data=data, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            return resp.status in (200, 204)
    except Exception:
        return False
