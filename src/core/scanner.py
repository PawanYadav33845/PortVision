import asyncio
import socket
from src.utils.helpers import get_common_ports
from src.core.banner_grab import grab_banner
from src.utils.vulns_db import check_vulnerabilities  # Import our new vuln db

async def scan_single_port(target_ip: str, port: int, timeout: float = 1.0) -> dict:
    """
    Attempts an asynchronous TCP connection to a specific port on the target IP.
    If open, fetches its service banner and checks for known vulnerabilities.
    """
    port_map = get_common_ports()
    service_name = port_map.get(port, "Unknown Service")
    
    result = {
        "port": port,
        "status": "Closed",
        "service": service_name,
        "banner": None,
        "vulnerability": None  # Placeholder for vulnerability data
    }

    try:
        # Check if port is open
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(target_ip, port),
            timeout=timeout
        )
        
        result["status"] = "Open"
        
        # Clean up initial connection probe
        writer.close()
        await writer.wait_closed()
        
        # Port is open -> grab banner
        fetched_banner = await grab_banner(target_ip, port, timeout=2.0)
        result["banner"] = fetched_banner
        
        # Check for matching vulnerability signatures
        vuln_data = check_vulnerabilities(port, fetched_banner)
        if vuln_data:
            result["vulnerability"] = vuln_data
        
    except (asyncio.TimeoutError, ConnectionRefusedError, socket.error):
        pass

    return result

async def run_port_scan(target_ip: str, ports_to_scan: list) -> list:
    """
    Aggregates concurrent scanning, banner grabbing, and vuln checks across ports.
    """
    tasks = []
    for port in ports_to_scan:
        tasks.append(scan_single_port(target_ip, port))
        
    scan_results = await asyncio.gather(*tasks)
    return scan_results