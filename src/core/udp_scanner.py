import asyncio
import socket
from src.utils.helpers import get_udp_ports, get_port_category
from src.utils.vulns_db import check_vulnerabilities

# Protocol-Specific UDP Probes
UDP_PROBES = {
    53: b"\x00\x1e\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07google\x03com\x00\x00\x01\x00\x01",  # DNS Query A google.com
    123: b"\x1b" + b"\x00" * 47,  # NTP Client Request (Mode 3)
    161: b"\x30\x1d\x02\x01\x00\x04\x06public\xa1\x10\x02\x04\x70\x02\x04\x01\x02\x01\x00\x30\x00",  # SNMPv1 GetNext
    1900: b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n",  # SSDP
    137: b"\x80\x94\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x20\x43\x4b\x41\x41\x43\x4b\x41\x41\x43\x4b\x41\x41\x43\x4b\x41\x41\x43\x4b\x41\x41\x43\x4b\x41\x41\x43\x4b\x41\x41\x00\x00\x21\x00\x01"  # NetBIOS
}

class UDPClientProtocol(asyncio.DatagramProtocol):
    def __init__(self, message, on_response):
        self.message = message
        self.on_response = on_response
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport
        self.transport.sendto(self.message)

    def datagram_received(self, data, addr):
        if not self.on_response.done():
            self.on_response.set_result(data)
        if self.transport:
            self.transport.close()

    def error_received(self, exc):
        if not self.on_response.done():
            self.on_response.set_exception(exc)
        if self.transport:
            self.transport.close()

    def connection_lost(self, exc):
        if not self.on_response.done():
            self.on_response.set_result(None)

async def scan_single_udp_port(target_ip: str, port: int, timeout: float = 2.0) -> dict:
    """
    Sends a non-blocking UDP probe to a target IP and port.
    Returns scan record with status Open, Open|Filtered, or Closed.
    """
    udp_map = get_udp_ports()
    service_name = udp_map.get(port, f"UDP-Service-{port}")
    category = get_port_category(port)
    
    result = {
        "port": port,
        "protocol": "UDP",
        "status": "Closed",
        "service": service_name,
        "category": category,
        "banner": None,
        "vulnerability": None,
        "cve_details": None
    }

    probe_payload = UDP_PROBES.get(port, b"\x00\x00\x00\x00\x00\x00\x00\x00")
    loop = asyncio.get_running_loop()
    on_response = loop.create_future()

    try:
        transport, protocol = await asyncio.wait_for(
            loop.create_datagram_endpoint(
                lambda: UDPClientProtocol(probe_payload, on_response),
                remote_addr=(target_ip, port)
            ),
            timeout=timeout
        )

        try:
            response_data = await asyncio.wait_for(on_response, timeout=timeout)
            if response_data:
                result["status"] = "Open"
                try:
                    banner_str = response_data.decode("utf-8", errors="ignore").strip()
                    result["banner"] = banner_str if banner_str else f"Raw Binary Payload ({len(response_data)} bytes)"
                except Exception:
                    result["banner"] = f"Raw UDP Data Response ({len(response_data)} bytes)"
            else:
                result["status"] = "Open|Filtered"
        except (asyncio.TimeoutError, Exception):
            result["status"] = "Open|Filtered"
        finally:
            transport.close()

    except (ConnectionRefusedError, socket.error):
        result["status"] = "Closed"
    except Exception:
        result["status"] = "Closed"

    # Attach offline vulnerability rules if marked Open
    if result["status"] == "Open":
        vuln = check_vulnerabilities(port, result["banner"], protocol="udp")
        if vuln:
            result["vulnerability"] = vuln

    return result

async def run_udp_port_scan(target_ip: str, ports_to_scan: list, timeout: float = 2.0) -> list:
    """
    Runs concurrent non-blocking UDP scans across a list of UDP ports.
    """
    tasks = [scan_single_udp_port(target_ip, port, timeout=timeout) for port in ports_to_scan]
    return await asyncio.gather(*tasks)
