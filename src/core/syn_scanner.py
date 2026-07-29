import os
import sys
import socket
import struct
import random
import asyncio
import platform
from src.utils.helpers import get_common_ports, get_port_category
from src.utils.vulns_db import check_vulnerabilities

def is_admin() -> bool:
    """Checks if the current process has administrative/root privileges."""
    try:
        if platform.system().lower() == "windows":
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.geteuid() == 0
    except Exception:
        return False

def can_use_syn_scan() -> bool:
    """Determines whether raw TCP SYN scanning is available on this system."""
    if not is_admin():
        return False
    try:
        # Check if raw socket creation succeeds
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        s.close()
        return True
    except Exception:
        return False

def calculate_checksum(msg: bytes) -> int:
    """Calculates standard Internet Checksum for raw IP/TCP headers."""
    s = 0
    for i in range(0, len(msg), 2):
        if i + 1 < len(msg):
            w = (msg[i] << 8) + (msg[i+1])
        else:
            w = (msg[i] << 8)
        s = s + w
    s = (s >> 16) + (s & 0xffff)
    s = s + (s >> 16)
    s = ~s & 0xffff
    return s

async def raw_syn_probe(target_ip: str, port: int, timeout: float = 1.5) -> str:
    """
    Constructs and transmits a raw TCP SYN packet to target port.
    Evaluates response for SYN-ACK (Open), RST (Closed), or Timeout (Filtered).
    """
    try:
        # Create raw TCP socket
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        raw_sock.settimeout(timeout)
        
        source_port = random.randint(1024, 65535)
        seq_num = random.randint(0, 4294967295)
        ack_num = 0
        doff = 5  # 5 * 4 = 20 bytes TCP header length
        
        # TCP Flags: FIN=0, SYN=1, RST=0, PSH=0, ACK=0, URG=0
        flags = 0x02
        window = socket.htons(5840)
        checksum = 0
        urg_ptr = 0
        
        offset_res = (doff << 4) + 0
        tcp_header = struct.pack('!HHLLBBHHH', source_port, port, seq_num, ack_num, offset_res, flags, window, checksum, urg_ptr)
        
        # Pseudo header for checksum calculation
        try:
            source_ip = socket.gethostbyname(socket.gethostname())
        except Exception:
            source_ip = "127.0.0.1"
            
        src_addr = socket.inet_aton(source_ip)
        dst_addr = socket.inet_aton(target_ip)
        placeholder = 0
        protocol = socket.IPPROTO_TCP
        tcp_len = len(tcp_header)
        
        psh = struct.pack('!4s4sBBH', src_addr, dst_addr, placeholder, protocol, tcp_len)
        psh = psh + tcp_header
        
        tcp_checksum = calculate_checksum(psh)
        tcp_header = struct.pack('!HHLLBBH', source_port, port, seq_num, ack_num, offset_res, flags, window) + struct.pack('H', tcp_checksum) + struct.pack('!H', urg_ptr)
        
        loop = asyncio.get_running_loop()
        
        def _send_recv():
            raw_sock.sendto(tcp_header, (target_ip, port))
            response_pkt, addr = raw_sock.recvfrom(1024)
            return response_pkt

        response_pkt = await loop.run_in_executor(None, _send_recv)
        raw_sock.close()

        if response_pkt:
            # Parse TCP Flags from IP payload offset
            tcp_flags = response_pkt[33] if len(response_pkt) >= 34 else 0
            if tcp_flags & 0x12 == 0x12:  # SYN + ACK
                return "Open"
            elif tcp_flags & 0x04:  # RST
                return "Closed"

        return "Filtered"
    except (socket.timeout, asyncio.TimeoutError):
        return "Filtered"
    except Exception:
        return "FallbackRequired"

async def scan_single_syn_port(target_ip: str, port: int, timeout: float = 1.5) -> dict:
    """
    Performs SYN stealth scan on a port with automatic fallback to TCP Connect.
    """
    port_map = get_common_ports()
    service_name = port_map.get(port, "Unknown Service")
    category = get_port_category(port)

    result = {
        "port": port,
        "protocol": "TCP-SYN",
        "status": "Closed",
        "service": service_name,
        "category": category,
        "banner": None,
        "vulnerability": None,
        "cve_details": None
    }

    if can_use_syn_scan():
        syn_status = await raw_syn_probe(target_ip, port, timeout=timeout)
        if syn_status != "FallbackRequired":
            result["status"] = syn_status
            if result["status"] == "Open":
                result["vulnerability"] = check_vulnerabilities(port, None, protocol="tcp")
            return result

    # Fallback to TCP Connect Probe
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(target_ip, port),
            timeout=timeout
        )
        result["status"] = "Open"
        result["protocol"] = "TCP-Connect (Fallback)"
        writer.close()
        await writer.wait_closed()
        result["vulnerability"] = check_vulnerabilities(port, None, protocol="tcp")
    except Exception:
        result["status"] = "Closed"

    return result

async def run_syn_port_scan(target_ip: str, ports_to_scan: list, timeout: float = 1.5) -> list:
    """
    Executes SYN stealth port scanning across a list of target ports.
    """
    tasks = [scan_single_syn_port(target_ip, port, timeout=timeout) for port in ports_to_scan]
    return await asyncio.gather(*tasks)
