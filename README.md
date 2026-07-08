# 👁️ PortVision

PortVision is a high-performance, asynchronous network reconnaissance, multi-protocol host discovery, and vulnerability triage engine built in Python. By leveraging non-blocking network sockets and subprocess execution via `asyncio`, PortVision can map out active devices across entire network subnets, probe open ports concurrently, perform banner metadata extraction, and export structured audit pipelines.

## 🚀 Core Features
* **Multi-Protocol Network Discovery:** Implements concurrent, non-blocking ICMP ping sweeps to filter out dead space and identify active hosts across full CIDR blocks (e.g., `192.168.1.0/24`).
* **Asynchronous TCP Engine:** Probes target ports simultaneously using `asyncio.open_connection`, completing massive scans in seconds.
* **Vulnerability Reference Matrix:** Cross-references open ports and banner metadata to categorize risks (Low, Medium, High, Critical) with explicit remediation steps.
* **Real-time Session Exporting:** Automatically serializes scan configurations, timelines, discovery metrics, and vulnerabilities into highly structured, schema-compliant JSON files (`/reports`).
* **Automated Markdown Reporter:** Formats findings into high-visibility engineering tables and security summaries for human auditors.
---

## 🛠️ System Architecture

```text
portvision/
│
├── src/
│   ├── core/
│   │   ├── scanner.py          # Asynchronous port loop aggregation engine
│   │   └── banner_grab.py      # Dual-stage software banner fetching utility
│   │
│   ├── utils/
│   │   ├── helpers.py          # Target validation & default port maps
│   │   └── vulns_db.py         # Signature rules & remediation database
│   │
│   └── reporter/
│       └── report_gen.py       # Automated Markdown documentation compiler
│
├── tests/
│   └── test_scanner.py         # Mock-isolated automated validation tests
│
├── reports/                    # Auto-generated timestamped audit logs
├── run.py                      # Application terminal UI orchestrator EntryPoint
└── requirements.txt            # Dependency tracker configuration file

Setup & Execution
1. Initialize Virtual Environment
Ensure your configurations are isolated properly:
    python -m venv venv
    .\venv\Scripts\Activate.ps1
2. Install Project Dependencies
Install the styling and reporting dependencies:
    pip install rich jinja2
3. Launch the Scanner Dashboard
    python run.py
4. Execute the Test Suite
Validate the mocked network layers instantly:
    python tests/test_scanner.py