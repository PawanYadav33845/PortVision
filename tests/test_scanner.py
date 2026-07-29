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

    # 2. Port Categorization & Helpers
    def test_port_categories(self):
        self.assertEqual(get_port_category(80), "Web Service")
        self.assertEqual(get_port_category(3306), "Database Service")
        self.assertEqual(get_port_category(22), "Remote Access")
        self.assertEqual(get_port_category(53), "Infrastructure & Network")

    # 3. OS Fingerprinting Heuristics
    def test_os_detection_ttl_windows(self):
        res = detect_os_from_ttl(128)
        self.assertEqual(res["os_family"], "Microsoft Windows")

    def test_os_detection_ttl_linux(self):
        res = detect_os_from_ttl(64)
        self.assertEqual(res["os_family"], "Linux / Unix / macOS")

    def test_os_detection_ttl_router(self):
        res = detect_os_from_ttl(255)
        self.assertEqual(res["os_family"], "Cisco IOS / Network Device / Solaris")

    # 4. Banner Product/Version Parser
    def test_parse_banner_product_version(self):
        pv = parse_banner_product_version("OpenSSH_7.2p1 Ubuntu-4")
        self.assertIsNotNone(pv)
        self.assertEqual(pv["product"], "openssh")
        self.assertEqual(pv["version"], "7.2p1")

        pv2 = parse_banner_product_version("Apache/2.4.41 (Unix)")
        self.assertIsNotNone(pv2)
        self.assertEqual(pv2["product"], "apache")
        self.assertEqual(pv2["version"], "2.4.41")

    # 5. Offline Vulnerability Signature Engine
    def test_vulnerability_signatures(self):
        vsftpd = check_vulnerabilities(21, "vsftpd 2.3.4")
        self.assertIsNotNone(vsftpd)
        self.assertEqual(vsftpd["severity"], "Critical")
        self.assertEqual(vsftpd["cve_id"], "CVE-2011-2523")

        redis = check_vulnerabilities(6379, "")
        self.assertIsNotNone(redis)
        self.assertEqual(redis["severity"], "Critical")

        telnet = check_vulnerabilities(23, "")
        self.assertIsNotNone(telnet)
        self.assertEqual(telnet["severity"], "High")

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
        self.assertEqual(result["banner"], "Mocked Service Banner v1.0")

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