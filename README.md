# 👁️ PortVision Security Suite

[![Python Version](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Build Status](https://img.shields.io/badge/tests-12%20passed-brightgreen.svg)]()
[![FastAPI GUI](https://img.shields.io/badge/GUI-FastAPI%20%2B%20Glassmorphism-purple.svg)]()

**PortVision** is a high-performance, asynchronous multi-protocol network discovery, port scanning, OS fingerprinting, and vulnerability triage engine built in Python.

By leveraging `asyncio` non-blocking sockets, raw TCP SYN stealth capabilities, non-blocking UDP payload probes, live online CVE API lookups, and a FastAPI-powered Web GUI with dynamic port fallback, PortVision enables rapid network mapping, service auditing, and executive reporting.

---

## ✨ Key Features

* **📡 Multi-Protocol Port Scanning**:
  * **TCP Connect Scan**: Fast asynchronous TCP port connection engine.
  * **Non-blocking UDP Probing**: Custom protocol payloads for DNS (53), NTP (123), SNMP (161), SSDP (1900), mDNS (5353), and NetBIOS (137).
  * **TCP SYN Stealth Scan**: Low-profile raw TCP SYN scanning with automatic privilege detection and graceful TCP fallback.
  * **Combined Dual Sweep**: Runs concurrent TCP and UDP discovery sweeps simultaneously.

* **💻 OS Fingerprinting Engine**:
  * Analyzes IP TTL (Time To Live) response values and TCP window parameters to classify operating systems (*Microsoft Windows*, *Linux/macOS*, *Cisco IOS / Network Routers*) and calculate network hop distance.

* **🔍 Live CVE & Vulnerability Triage**:
  * **Live Online CVE Lookups**: Regex product/version banner extractor that queries live vulnerability APIs (CIRCL CVE Search / NIST NVD) with caching.
  * **Offline Signature Matrix**: Built-in detection rules for exposed Redis, Memcached, MongoDB, Docker/K8s APIs, Etcd, Hadoop YARN, RDP BlueKeep, Tomcat Ghostcat, Telnet, FTP, and SMB.

* **🌐 Web Application & TLS Certificate Audit**:
  * Extracts page `<title>`, `Server`, and `X-Powered-By` HTTP headers.
  * Checks HTTP Security Headers (`Strict-Transport-Security`, `X-Frame-Options`, `CSP`).
  * Audits SSL/TLS certificates on HTTPS ports (Issuer, Expiry date, Days remaining, Self-Signed warning).

* **📢 Webhook Notification Engine**:
  * Formats scan execution summaries and flagged Critical/High severity threats for automated transmission to Slack, Discord, or Telegram webhooks.

* **⚡ Rate Limiting & Concurrency Controls**:
  * Integrated `asyncio.Semaphore` rate-limiting control across concurrent port probes (`--concurrency 100`).

* **📄 Executive HTML & Markdown Dashboard Reports**:
  * Generates self-contained, print-to-PDF ready HTML executive dashboard reports (`reports/executive_report_*.html`).
  * Serializes structured audit findings into schema-compliant JSON files (`reports/session_capture_*.json`).

* **🌐 Modern Glassmorphism Web GUI**:
  * Web interface powered by FastAPI & Uvicorn (`http://127.0.0.1:8000`).
  * Automatic free-port fallback if port 8000 is occupied by another process.
  * Features real-time scan progress monitoring, live console feeds, host cards, and 1-click report downloads.

---

## 🛠️ Project Structure

```text
PortVision/
│
├── src/
│   ├── core/
│   │   ├── scanner.py          # Asynchronous multi-protocol scan manager & rate limiter
│   │   ├── udp_scanner.py      # Non-blocking UDP probe engine (DNS, NTP, SNMP, SSDP)
│   │   ├── syn_scanner.py      # Raw socket TCP SYN stealth scanner with fallback
│   │   ├── discovery.py        # Asynchronous ICMP ping sweep module
│   │   ├── banner_grab.py      # Service banner retrieval module
│   │   ├── cve_lookup.py       # Live CIRCL CVE & NVD API lookup engine with caching
│   │   ├── os_detect.py        # IP TTL response OS fingerprinting heuristics
│   │   └── web_audit.py        # HTTP title/header & SSL/TLS certificate audit module
│   │
│   ├── gui/
│   │   ├── app.py              # FastAPI Web GUI backend server
│   │   └── static/             # Glassmorphism frontend UI (HTML, CSS, JS)
│   │
│   ├── utils/
│   │   ├── helpers.py          # Target parser & 150+ TCP/UDP port mapping
│   │   ├── vulns_db.py         # Offline vulnerability signature matrix
│   │   └── alerts.py           # Webhook notification engine (Slack/Discord/Telegram)
│   │
│   └── reporter/
│       ├── html_report.py      # Executive HTML dashboard report generator
│       ├── report_gen.py       # Markdown report documentation generator
│       └── json_export.py      # JSON session metrics serializer
│
├── tests/
│   └── test_scanner.py         # Unit test suite (12 tests)
│
├── reports/                    # Auto-generated audit reports directory
├── run.py                      # Core CLI & GUI entry point launcher
├── requirements.txt            # Dependency manifest
├── README.md                   # Documentation
└── .gitignore                  # Git tracking rules
```

---

## ⚙️ Installation & Quick Start

### 1. Clone the Repository
```bash
git clone https://github.com/PawanYadav33845/PortVision.git
cd PortVision
```

### 2. Create Virtual Environment & Install Dependencies
```bash
python -m venv venv

# On Windows:
.\venv\Scripts\Activate.ps1

# On Linux / macOS:
source venv/bin/activate

pip install -r requirements.txt
```

---

## 🚀 Usage

### 🌐 Option A: Launch the Web GUI Dashboard
```bash
python run.py --gui
```
Open your browser at **`http://127.0.0.1:8000`** (or the assigned fallback port displayed in the console) to access the interactive web interface.

---

### 🖥️ Option B: Command Line Interface (CLI)

#### 1. Standard TCP Connect Scan
```bash
python run.py --target 127.0.0.1
```

#### 2. Scan an Entire Subnet (CIDR Block)
```bash
python run.py --target 192.168.1.0/24
```

#### 3. Non-blocking UDP Probing
```bash
python run.py --target 192.168.1.1 --mode UDP
```

#### 4. Raw TCP SYN Stealth Scan *(Requires Admin/Root)*
```bash
python run.py --target 192.168.1.1 --mode SYN
```

#### 5. Dual Sweep (TCP + UDP Combined)
```bash
python run.py --target 192.168.1.1 --mode COMBINED
```

#### 6. Interactive CLI Mode
```bash
python run.py
```

---

## 🧪 Running Unit Tests

Run the test suite to verify network parsers, scanners, and report generators:

```bash
python -m unittest discover -s tests
```

---

## 📝 License

Distributed under the MIT License. See `LICENSE` for more information.

---

## ⚠️ Disclaimer

PortVision is designed for legitimate security auditing, network administration, and authorized penetration testing. Always obtain explicit authorization before scanning networks or targets you do not own.