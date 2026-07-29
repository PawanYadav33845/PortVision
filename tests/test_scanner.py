import unittest
from unittest.mock import patch, AsyncMock
import asyncio

from src.utils.helpers import validate_target, parse_network_range, get_common_ports, get_udp_ports, get_port_category
from src.core.scanner import scan_single_tcp_port
from src.core.udp_scanner import scan_single_udp_port
from src.core.syn_scanner import scan_single_syn_port
from src.core.cve_lookup import parse_banner_product_version
from src.core.os_detect import detect_os_from_ttl
from src.core.web_audit import audit_tls_certificate, audit_web_service
from src.core.device_profile import classify_device_type, get_ports_for_profile
from src.utils.vulns_db import check_vulnerabilities
from src.reporter.html_report import generate_html_executive_report

class TestPortVisionExpanded(unittest.TestCase):

    # 1. Target Validation & Network Range Parsing
    def test_validate_valid_ipv4(self):
        self.assertEqual(validate_target("  127.0.0.1  "), "127.0.0.1")

    def test_validate_invalid_ipv4_octets(self):
        with self.assertRaises(ValueError):
            validate_target("256.100.10.1")

    @patch("socket.gethostbyname")
    def test_validate_domain_resolution(self, mock_gethostbyname):
        mock_gethostbyname.return_value = "93.184.216.34"
        self.assertEqual(validate_target("example.com"), "93.184.216.34")

    def test_parse_cidr_network_range(self):
        ips = parse_network_range("192.168.1.0/30")
        self.assertIn("192.168.1.1", ips)
        self.assertIn("192.168.1.2", ips)

    # 2. Device Profiling & Classification
    def test_device_classification_printer(self):
        dev = classify_device_type([9100, 80], "HP LaserJet Printer")
        self.assertEqual(dev, "Printer / Multi-Function Device")

    def test_device_classification_router(self):
        dev = classify_device_type([53, 80, 1900], "")
        self.assertEqual(dev, "Router / Network Gateway")

    def test_device_classification_database(self):
        dev = classify_device_type([3306], "MySQL Community Server")
        self.assertEqual(dev, "Database Server")

    def test_get_ports_for_profile(self):
        router_ports = get_ports_for_profile("router")
        self.assertIn(53, router_ports)
        self.assertIn(1900, router_ports)

        printer_ports = get_ports_for_profile("printer")
        self.assertIn(9100, printer_ports)

    # 3. Port Categorization & Helpers
    def test_port_categories(self):
        self.assertEqual(get_port_category(80), "Web Service")
        self.assertEqual(get_port_category(3306), "Database Service")
        self.assertEqual(get_port_category(22), "Remote Access")

    # 4. OS Fingerprinting Heuristics
    def test_os_detection_ttl_windows(self):
        res = detect_os_from_ttl(128)
        self.assertEqual(res["os_family"], "Microsoft Windows")

    def test_os_detection_ttl_linux(self):
        res = detect_os_from_ttl(64)
        self.assertEqual(res["os_family"], "Linux / Unix / macOS")

    # 5. Offline Vulnerability Signature Engine
    def test_vulnerability_signatures(self):
        vsftpd = check_vulnerabilities(21, "vsftpd 2.3.4")
        self.assertIsNotNone(vsftpd)
        self.assertEqual(vsftpd["severity"], "Critical")

    # 6. Async Single TCP Port Scanner
    @patch("asyncio.open_connection")
    @patch("src.core.scanner.grab_banner", new_callable=AsyncMock)
    def test_scan_single_port_open(self, mock_grab_banner, mock_open_connection):
        mock_reader = AsyncMock()
        mock_writer = AsyncMock()
        mock_writer.wait_closed = AsyncMock()
        mock_open_connection.return_value = (mock_reader, mock_writer)
        mock_grab_banner.return_value = "Mocked Service Banner v1.0"

        result = asyncio.run(scan_single_tcp_port("127.0.0.1", 80, timeout=0.1, lookup_cves=False))

        self.assertEqual(result["status"], "Open")
        self.assertEqual(result["port"], 80)

    # 7. HTML Executive Report Generator
    def test_html_report_generation(self):
        mock_session = {
            "session_execution_time": "2026-07-29 22:00:00",
            "scanned_range": "127.0.0.1",
            "hosts_discovered_count": 1,
            "network_discoveries": {
                "127.0.0.1": {
                    "os_fingerprint": {"os_family": "Microsoft Windows"},
                    "open_ports_detected": 1,
                    "findings": [
                        {
                            "port": 80,
                            "protocol": "TCP",
                            "service": "HTTP",
                            "category": "Web Service",
                            "banner": "Apache/2.4.41",
                            "vulnerability": None
                        }
                    ]
                }
            }
        }
        file_path = generate_html_executive_report(mock_session)
        self.assertTrue(file_path.endswith(".html"))

if __name__ == "__main__":
    unittest.main()