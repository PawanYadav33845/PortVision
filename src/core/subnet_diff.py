import os
import json
from typing import Optional, Dict

REPORTS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../reports"))

def get_latest_previous_session() -> Optional[dict]:
    """
    Finds and loads the most recent JSON session file in reports/ directory.
    """
    if not os.path.exists(REPORTS_DIR):
        return None

    json_files = [
        os.path.join(REPORTS_DIR, f) for f in os.listdir(REPORTS_DIR)
        if f.startswith("session_capture_") and f.endswith(".json")
    ]

    if not json_files:
        return None

    # Sort by modification timestamp (newest first)
    json_files.sort(key=lambda x: os.path.getmtime(x), reverse=True)
    
    # Return the second newest if available, or newest if only one exists
    target_file = json_files[0]
    
    try:
        with open(target_file, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None

def compute_subnet_diff(current_session: dict, baseline_session: Optional[dict] = None) -> dict:
    """
    Compares current scan session against previous baseline scan session.
    Returns delta metrics: new hosts, offline hosts, new open ports, remediated ports.
    """
    if not baseline_session:
        baseline_session = get_latest_previous_session()

    diff_res = {
        "baseline_timestamp": baseline_session.get("session_execution_time", "None") if baseline_session else "N/A",
        "new_hosts": [],
        "offline_hosts": [],
        "newly_opened_ports": [],
        "remediated_ports": []
    }

    if not baseline_session or "network_discoveries" not in baseline_session:
        return diff_res

    curr_discoveries = current_session.get("network_discoveries", {})
    base_discoveries = baseline_session.get("network_discoveries", {})

    curr_ips = set(curr_discoveries.keys())
    base_ips = set(base_discoveries.keys())

    diff_res["new_hosts"] = list(curr_ips - base_ips)
    diff_res["offline_hosts"] = list(base_ips - curr_ips)

    # Compare open ports for common hosts
    for ip in curr_ips.intersection(base_ips):
        curr_findings = curr_discoveries[ip].get("findings", [])
        base_findings = base_discoveries[ip].get("findings", [])

        curr_ports = {f["port"] for f in curr_findings if "Open" in f.get("status", "")}
        base_ports = {f["port"] for f in base_findings if "Open" in f.get("status", "")}

        new_p = curr_ports - base_ports
        rem_p = base_ports - curr_ports

        for p in new_p:
            diff_res["newly_opened_ports"].append({"ip": ip, "port": p})
        for p in rem_p:
            diff_res["remediated_ports"].append({"ip": ip, "port": p})

    return diff_res
