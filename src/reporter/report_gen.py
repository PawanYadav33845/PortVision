import os
from datetime import datetime

def generate_markdown_report(target: str, scan_results: list) -> str:
    """
    Compiles multi-protocol scan results and live/offline CVE findings into a structured Markdown report.
    """
    current_time = datetime.now()
    timestamp_str = current_time.strftime("%Y-%m-%d_%H-%M-%S")
    display_time = current_time.strftime("%Y-%m-%d %H:%M:%S")

    reports_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../reports"))
    os.makedirs(reports_dir, exist_ok=True)
    
    filename = f"scan_{target.replace('.', '_')}_{timestamp_str}.md"
    file_path = os.path.join(reports_dir, filename)

    md_content = f"""# PortVision Recon Report
    
## 📋 Execution Context
* **Target Host / Scope:** `{target}`
* **Scan Timestamp:** `{display_time}`
* **Status:** Complete

---

## 🔍 Discovered Infrastructure Ports & Services
| Port | Protocol | Status | Service | Category | Banner Metadata |
| :--- | :--- | :--- | :--- | :--- | :--- |
"""

    vulnerabilities_found = []
    for record in scan_results:
        status = record.get("status", "Closed")
        if "Open" in status:
            banner = record.get("banner") if record.get("banner") else "No banner responded"
            proto = record.get("protocol", "TCP")
            category = record.get("category", "General")
            
            md_content += f"| **{record['port']}** | `{proto}` | `OPEN` | {record['service']} | {category} | *{banner}* |\n"
            
            if record.get("vulnerability"):
                vulnerabilities_found.append(record["vulnerability"])

    if vulnerabilities_found:
        md_content += "\n---\n\n## 🚨 Threat & CVE Vulnerability Findings\n\n"
        
        for vuln in vulnerabilities_found:
            sev = vuln.get("severity", "Medium")
            severity_badge = f"`CRITICAL`" if sev == "Critical" else f"`HIGH`" if sev == "High" else f"`MEDIUM`"
            cve_id = vuln.get("cve_id")
            cve_str = f" [{cve_id}]" if cve_id else ""
            
            md_content += f"### ⚠️ {vuln['title']}{cve_str} ({severity_badge})\n"
            md_content += f"* **Risk Summary:** {vuln.get('description')}\n"
            md_content += f"* **Remediation Action:** {vuln.get('remediation')}\n\n"
    else:
        md_content += "\n---\n\n## ✅ Security Analysis\n"
        md_content += "*Zero high-risk vulnerability signatures or exposed unauthenticated protocols matched the active ports.*"

    md_content += "\n\n---\n*Compiled automatically by PortVision Security Recon Engine.*"

    with open(file_path, "w", encoding="utf-8") as file:
        file.write(md_content)

    return file_path