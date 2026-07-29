import re
import socket
import struct
import asyncio
from typing import Optional

def resolve_reverse_dns(ip: str) -> Optional[str]:
    """Resolves standard Reverse DNS PTR record for an IP address."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        if hostname and hostname != ip:
            return hostname
    except Exception:
        pass
    return None

def resolve_netbios_name(ip: str, timeout: float = 1.0) -> Optional[str]:
    """
    Sends a NetBIOS Node Status Query over UDP 137 to resolve Windows/SAMBA NetBIOS Hostname.
    """
    packet = (
        b"\x80\x94\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        b"\x20\x43\x4b\x41\x41\x43\x4b\x41\x41\x43\x4b\x41\x41\x43\x4b\x41\x41"
        b"\x43\x4b\x41\x41\x43\x4b\x41\x41\x43\x4b\x41\x41\x43\x4b\x41\x41\x00"
        b"\x00\x21\x00\x01"
    )
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(packet, (ip, 137))
            data, _ = sock.recvfrom(1024)
            
            if len(data) > 57:
                num_names = data[56]
                if num_names > 0:
                    netbios_name = data[57:72].decode("latin-1", errors="ignore").strip()
                    if netbios_name and not netbios_name.startswith("IS~"):
                        return netbios_name
    except Exception:
        pass
    return None

def resolve_mdns_name(ip: str, timeout: float = 1.0) -> Optional[str]:
    """
    Sends an mDNS Reverse Query over UDP 5353 to resolve mDNS .local hostname.
    """
    try:
        octets = ip.split(".")
        rev_ip = ".".join(reversed(octets)) + ".in-addr.arpa"
        
        hdr = b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        qname = b"".join([bytes([len(part)]) + part.encode() for part in rev_ip.split(".")]) + b"\x00"
        qtype_qclass = b"\x00\x0c\x00\x01"
        pkt = hdr + qname + qtype_qclass

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(pkt, (ip, 5353))
            data, _ = sock.recvfrom(1024)
            if data and len(data) > 12:
                matches = re.findall(rb"([a-zA-Z0-9\-]+\.local)", data)
                if matches:
                    return matches[0].decode("utf-8", errors="ignore")
    except Exception:
        pass
    return None

async def resolve_device_hostname(ip: str, web_title: Optional[str] = None) -> str:
    """
    Multi-protocol hostname resolver:
    1. Reverse DNS Lookup
    2. NetBIOS Computer Name Query (UDP 137)
    3. mDNS (.local) Name Query (UDP 5353)
    4. Web Title Fallback
    """
    loop = asyncio.get_running_loop()

    # 1. Reverse DNS
    dns_name = await loop.run_in_executor(None, resolve_reverse_dns, ip)
    if dns_name:
        return dns_name

    # 2. NetBIOS Name
    netbios_name = await loop.run_in_executor(None, resolve_netbios_name, ip, 0.8)
    if netbios_name:
        return f"{netbios_name} (NetBIOS)"

    # 3. mDNS Name
    mdns_name = await loop.run_in_executor(None, resolve_mdns_name, ip, 0.8)
    if mdns_name:
        return mdns_name

    # 4. Web Title fallback
    if web_title and len(web_title) > 2:
        clean_title = web_title.replace("\n", " ").strip()
        return f"[{clean_title[:30]}]"

    return "Unresolved Hostname"
