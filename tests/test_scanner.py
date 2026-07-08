import unittest
from unittest.mock import patch, AsyncMock
import asyncio

# Import the functions we want to test
from src.utils.helpers import validate_target
from src.core.scanner import scan_single_port

class TestPortVisionCore(unittest.TestCase):

    # ---------------------------------------------------------
    # 1. TESTING INPUT VALIDATION (src/utils/helpers.py)
    # ---------------------------------------------------------
    def test_validate_valid_ipv4(self):
        """Should return the clean IP string if a valid IPv4 is provided."""
        result = validate_target("  127.0.0.1  ")
        self.assertEqual(result, "127.0.0.1")

    def test_validate_invalid_ipv4_octets(self):
        """Should raise ValueError if IP octets exceed 255."""
        with self.assertRaises(ValueError):
            validate_target("256.100.10.1")

    @patch("socket.gethostbyname")
    def test_validate_domain_resolution(self, mock_gethostbyname):
        """Should dynamically resolve a domain name to an IP address string."""
        # Mocking DNS resolution so it doesn't actually hit the internet
        mock_gethostbyname.return_value = "93.184.216.34"
        
        result = validate_target("example.com")
        self.assertEqual(result, "93.184.216.34")
        mock_gethostbyname.assert_called_once_with("example.com")

    # ---------------------------------------------------------
    # 2. TESTING ASYNC SCANNER ENGINE (src/core/scanner.py)
    # ---------------------------------------------------------
    @patch("asyncio.open_connection")
    @patch("src.core.scanner.grab_banner", new_callable=AsyncMock)
    def test_scan_single_port_open(self, mock_grab_banner, mock_open_connection):
        """Should correctly mark port status as 'Open' when a connection succeeds."""
        # Setup mocks for stream reader and writer
        mock_reader = AsyncMock()
        mock_writer = AsyncMock()
        mock_open_connection.return_value = (mock_reader, mock_writer)
        mock_grab_banner.return_value = "Mocked Service Banner v1.0"

        # Execute the async function using the event loop
        loop = asyncio.get_event_loop()
        result = loop.run_until_complete(scan_single_port("127.0.0.1", 80, timeout=0.1))

        # Assertions
        self.assertEqual(result["status"], "Open")
        self.assertEqual(result["port"], 80)
        self.assertEqual(result["banner"], "Mocked Service Banner v1.0")
        mock_writer.close.assert_called_once()

    @patch("asyncio.open_connection", side_effect=ConnectionRefusedError)
    def test_scan_single_port_closed(self, mock_open_connection):
        """Should correctly flag port status as 'Closed' when network connection is rejected."""
        loop = asyncio.get_event_loop()
        result = loop.run_until_complete(scan_single_port("127.0.0.1", 80, timeout=0.1))

        self.assertEqual(result["status"], "Closed")
        self.assertIsNone(result["banner"])

if __name__ == "__main__":
    unittest.main()