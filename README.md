# 👁️ PortVision

PortVision is a high-performance, asynchronous network reconnaissance and vulnerability detection engine built using Python. By utilizing non-blocking network sockets via `asyncio`, PortVision concurrently probes target networks for active service entry points, performs dual-stage banner grabbing, and cross-references discoveries against a local signature matrix to flag immediate protocol-level security risks.

## 🚀 Core Features
* **Asynchronous TCP Engine:** Fires concurrent connection requests via `asyncio.open_connection`, dropping total scan windows down to seconds.
* **Dual-Stage Banner Grabbing:** Implements both passive listening and active newline carriage injections (`\r\n`) to force unannounced software signatures from quiet target systems.
* **Vulnerability & Severity Triage:** Evaluates active ports and banner versions against a signature reference matrix to categorize threats (Low, Medium, High, Critical).
* **Rich Terminal UI Dashboard:** Renders clean, color-coded interactive tabular outputs using the `Rich` framework directly in the terminal interface.
* **Automated Audit Reports:** Automatically writes distinct, timestamped Markdown documentation summaries straight to a localized storage directory (`/reports`).
* **Test-Driven Design:** Built alongside an isolated unit test suite leveraging `unittest.mock` to guarantee deterministic networking code execution.

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