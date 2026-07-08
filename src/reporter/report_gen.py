import os
from datetime import datetime

def generate_markdown_report(target: str, scan_results: list) -> str:
    """
    Compiles scan results and any flagged vulnerabilities into a structured Markdown report.
    """
    current_time = datetime.now()
    timestamp_str = current_time.strftime("%Y-%m-%d_%H-%M-%S")
    display_time = current_time.strftime("%Y-%m-%d %H:%M:%S")

    reports_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../reports"))
    os.makedirs(reports_dir, exist_ok=True)
    
    filename = f"scan_{target.replace('.', '_')}_{timestamp_str}.md"
    file_path = os.path.join(reports_dir, filename)

    # Base Layout Structure
    md_content = f"""# PortVision Scan Report
    
## 📋 Scan Summary
* **Target Host / IP:** `{target}`
* **Scan Execution Time:** `{display_time}`
* **Status:** Complete

---

## 🔍 Discovered Services and Ports
| Port | Status | Service Name | Banner / Version Metadata |
| :--- | :--- | :--- | :--- |
"""

    # 1. Build the active ports table
    vulnerabilities_found = []
    for record in scan_results:
        if record["status"] == "Open":
            banner = record["banner"] if record["banner"] else "No banner responded"
            md_content += f"| **{record['port']}** | `OPEN` | {record['service']} | *{banner}* |\n"
            
            # Keep track of flagged vulnerabilities for our next section
            if record["vulnerability"]:
                vulnerabilities_found.append(record["vulnerability"])

    # 2. Append the Vulnerability Assessment Section if any threats matched
    if vulnerabilities_found:
        md_content += "\n---\n\n## 🚨 Security Vulnerability Analysis\n"
        md_content += "The following critical protocol-level or version-specific risks were detected on the target:\n\n"
        
        for vuln in vulnerabilities_found:
            severity_badge = f"`CRITICAL`" if vuln["severity"] == "Critical" else f"`HIGH`" if vuln["severity"] == "High" else f"`MEDIUM`"
            
            md_content += f"### ⚠️ {vuln['title']} ({severity_badge})\n"
            md_content += f"* **Risk Description:** {vuln['description']}\n"
            md_content += f"* **Remediation Plan:** {vuln['remediation']}\n\n"
    else:
        md_content += "\n---\n\n## ✅ Security Vulnerability Analysis\n"
        md_content += "*No known vulnerability signatures or high-risk unencrypted protocols matched the active open ports.*"

    md_content += "\n\n---\n*Report automatically compiled by PortVision Recon Engine.*"

    with open(file_path, "w", encoding="utf-8") as file:
        file.write(md_content)

    return file_path