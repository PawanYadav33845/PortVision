import os
import unittest
from unittest.mock import patch, AsyncMock
import asyncio

from src.utils.helpers import validate_target, parse_network_range, get_common_ports, get_udp_ports, get_port_category
from src.core.scanner import scan_single_tcp_port
from src.core.cve_lookup import parse_banner_product_version
from src.core.os_detect import detect_os_from_ttl
from src.core.device_profile import classify_device_type, get_ports_for_profile
from src.core.mac_vendor import get_mac_from_arp, lookup_vendor_by_mac
from src.core.subnet_diff import compute_subnet_diff
from src.reporter.pdf_export import export_session_to_pdf
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

    # 3. MAC & Vendor Resolution
    def test_lookup_vendor_by_mac(self):
        self.assertEqual(lookup_vendor_by_mac("00:05:69:11:22:33"), "VMware, Inc.")
        self.assertEqual(lookup_vendor_by_mac("B8:27:EB:AA:BB:CC"), "Raspberry Pi Foundation")

    # 4. Subnet Diffing
    def test_compute_subnet_diff(self):
        base = {
            "session_execution_time": "2026-07-29 20:00:00",
            "network_discoveries": {"192.168.1.1": {"findings": [{"port": 80, "status": "Open"}]}}
        }
        curr = {
            "session_execution_time": "2026-07-29 21:00:00",
            "network_discoveries": {
                "192.168.1.1": {"findings": [{"port": 80, "status": "Open"}, {"port": 443, "status": "Open"}]},
                "192.168.1.50": {"findings": [{"port": 22, "status": "Open"}]}
            }
        }
        diff = compute_subnet_diff(curr, base)
        self.assertIn("192.168.1.50", diff["new_hosts"])
        self.assertEqual(len(diff["newly_opened_ports"]), 1)
        self.assertEqual(diff["newly_opened_ports"][0]["port"], 443)

    # 5. PDF Export Generation
    def test_pdf_export_generation(self):
        mock_session = {
            "session_execution_time": "2026-07-29 22:00:00",
            "scanned_range": "127.0.0.1",
            "hosts_discovered_count": 1,
            "network_discoveries": {
                "127.0.0.1": {
                    "device_name": "localhost",
                    "mac_address": "00:00:00:00:00:00",
                    "hardware_vendor": "Local Host",
                    "findings": [{"port": 80, "protocol": "TCP", "service": "HTTP", "banner": "Apache"}]
                }
            }
        }
        pdf_path = export_session_to_pdf(mock_session)
        self.assertTrue(os.path.exists(pdf_path))

if __name__ == "__main__":
    unittest.main()