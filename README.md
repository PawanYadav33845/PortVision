# 👁️ PortVision v3.5.0

> **Multi-Protocol Reconnaissance, MAC Vendor OUI Resolution, Device Profiling & Subnet Diffing Suite**

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![Version](https://img.shields.io/badge/version-3.5.0-cyan.svg)]()
[![FastAPI](https://img.shields.io/badge/FastAPI-v0.100%2B-009688.svg)](https://fastapi.tiangolo.com/)
[![GitHub Package](https://img.shields.io/badge/GHCR-Docker%20Container-blue?logo=docker)](https://github.com/PawanYadav33845/PortVision/pkgs/container/portvision)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## 🌐 Live Demo & Deployment

- 🐳 **GitHub Container Registry (GHCR)**:
  ```bash
  docker run -d -p 8000:8000 ghcr.io/pawanyadav33845/portvision:latest
  ```
- 🔗 **GitHub Repository**: [https://github.com/PawanYadav33845/PortVision](https://github.com/PawanYadav33845/PortVision)
- 🚀 **Live Web App Demo**: Launch locally via `python run.py --gui` or host on Render / Cloud using the provided Docker container!

---

## ✨ Key Features

- **⚡ Multi-Protocol Scanning Engine**: Supports asynchronous TCP Connect, non-blocking UDP payload probing (DNS, NTP, SNMP, SSDP, NetBIOS), and raw TCP SYN stealth reconnaissance.
- **🏷️ Multi-Tier Hostname Resolver**: Resolves hostnames via Reverse DNS PTR, NetBIOS node status queries (UDP 137), mDNS queries (UDP 5353), and HTTP Web Title fallbacks.
- **🛜 MAC Address & Vendor OUI Lookup**: Queries local OS ARP tables to extract physical MAC addresses and matches OUI prefixes against an offline database (*Apple, Cisco, Raspberry Pi, VMware, Intel, HP, Dell, TP-Link*).
- **🎯 Device Profiling & Classification (`--profile`)**: Automatically classifies targets into device types (*Router*, *Printer*, *IoT*, *NAS Storage*, *Database Server*, *Workstation*, *Web Server*) or uses `AUTO` mode to auto-target device-specific ports.
- **🔄 Subnet Diffing & Change Tracking**: Compares active scans against historical session baselines to detect new hosts, offline hosts, newly opened ports, and remediated vulnerabilities.
- **🌐 Glassmorphic Web GUI**: Built with FastAPI & Server-Sent Events (SSE) featuring real-time console streaming, visual device cards, and dynamic free-port fallback to avoid socket conflicts (`WinError 10048`).
- **📑 Executive PDF & HTML Reporting**: Generates interactive HTML dashboards with `@media print` PDF styles and 1-click PDF download capabilities.
- **🔔 Webhook Notification Alerts**: Sends instant threat alerts to Slack, Discord, or Telegram webhooks.

---

## 🚀 Quick Start

### 1. Installation
Clone the repository and install dependencies:
```bash
git clone https://github.com/PawanYadav33845/PortVision.git
cd PortVision
pip install -r requirements.txt
```

### 2. Launch Web GUI
Start the interactive Web Dashboard:
```bash
python run.py --gui
```
Navigate to **`http://127.0.0.1:8000`** in your web browser.

### 3. Run CLI Scans

- **Standard Subnet Scan**:
  ```bash
  python run.py --target 192.168.1.0/24
  ```

- **Smart Auto Device Profiling Scan**:
  ```bash
  python run.py --target 192.168.1.1 --profile AUTO
  ```

- **Targeted Router/Gateway Scan**:
  ```bash
  python run.py --target 192.168.1.1 --profile ROUTER
  ```

- **Raw SYN Stealth Scan** *(Requires OS Admin Privileges)*:
  ```bash
  python run.py --target 192.168.1.100 --mode SYN
  ```

- **UDP Payload Probe Sweep**:
  ```bash
  python run.py --target 192.168.1.1 --mode UDP
  ```

---

## 🛠️ Architecture & Project Structure

```text
PortVision/
├── run.py                      # Main entry point launcher (CLI & Web GUI)
├── Dockerfile                  # Container build specification
├── .github/workflows/deploy.yml# Automated GHCR CI/CD build pipeline
├── requirements.txt            # Python package dependencies
├── .gitignore                  # Git ignore rules for reports & caches
├── src/
│   ├── core/
│   │   ├── scanner.py          # Asynchronous scan manager & semaphore pool
│   │   ├── discovery.py        # ICMP ping sweep engine
│   │   ├── udp_scanner.py      # Non-blocking UDP payload probing
│   │   ├── syn_scanner.py      # Raw TCP SYN stealth scanner
│   │   ├── hostname_resolver.py# Reverse DNS, NetBIOS & mDNS name resolver
│   │   ├── mac_vendor.py       # ARP table parser & IEEE OUI vendor database
│   │   ├── device_profile.py   # Device classification & profile port maps
│   │   ├── os_detect.py        # IP TTL OS fingerprinting heuristics
│   │   ├── web_audit.py        # HTTP headers & SSL/TLS certificate auditor
│   │   ├── cve_lookup.py       # Live CIRCL CVE & NIST NVD lookup engine
│   │   └── subnet_diff.py      # Historical scan session delta comparator
│   ├── reporter/
│   │   ├── html_report.py      # Executive HTML dashboard generator
│   │   ├── pdf_export.py       # Printable PDF report generator
│   │   ├── json_export.py      # JSON session capture exporter
│   │   └── report_gen.py       # Markdown report generator
│   ├── gui/
│   │   ├── app.py              # FastAPI Web GUI backend server
│   │   └── static/             # Glassmorphic frontend assets (HTML, CSS, JS)
│   └── utils/
│       ├── helpers.py          # 150+ port matrix & IP range parsers
│       ├── vulns_db.py         # Offline vulnerability signature matrix
│       └── alerts.py           # Webhook notification engine
└── tests/
    └── test_scanner.py         # Automated unit test suite
```

---

## 📖 CLI Argument Reference

| Flag | Option | Description |
| :--- | :--- | :--- |
| `--gui` | Flag | Launches the FastAPI Web Dashboard interface. |
| `--target` | String | Target IP address, hostname, or CIDR block (e.g. `192.168.1.0/24`). |
| `--mode` | `TCP` / `UDP` / `SYN` / `COMBINED` | Protocol scanning mode (Default: `TCP`). |
| `--profile` | `ALL` / `AUTO` / `ROUTER` / `PRINTER` / `IOT` / `NAS` / `DATABASE` / `WEB` / `WORKSTATION` | Targeted device port profile (Default: `ALL`). |
| `--no-cve` | Flag | Disables live online CVE API lookups for offline environments. |

---

## 🧪 Running Automated Unit Tests

Execute the 11-test suite to verify core engines:
```bash
python -m unittest discover -s tests
```

---

## 📜 License & Legal Disclaimer

This tool is released under the **MIT License**.

> **Disclaimer**: PortVision is intended exclusively for authorized network inventory, security auditing, and defensive infrastructure management. Users must ensure compliance with all applicable laws and obtain proper authorization before scanning remote targets.