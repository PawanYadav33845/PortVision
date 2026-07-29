import asyncio
import socket
import inspect
from src.utils.helpers import get_common_ports, get_udp_ports, get_port_category
from src.core.banner_grab import grab_banner
from src.utils.vulns_db import check_vulnerabilities
from src.core.udp_scanner import run_udp_port_scan
from src.core.syn_scanner import run_syn_port_scan
from src.core.cve_lookup import lookup_cve_for_banner
from src.core.os_detect import detect_os_from_ttl
from src.core.web_audit import audit_web_service
from src.core.device_profile import get_ports_for_profile, classify_device_type

async def scan_single_tcp_port(target_ip: str, port: int, timeout: float = 1.0, lookup_cves: bool = True, semaphore: asyncio.Semaphore = None) -> dict:
    """
    Attempts an asynchronous TCP connection to a specific port on target_ip.
    Supports concurrency semaphores, OS fingerprinting, and web/TLS audits.
    """
    async def _do_scan():
        port_map = get_common_ports()
        service_name = port_map.get(port, "Unknown Service")
        category = get_port_category(port)
        
        result = {
            "port": port,
            "protocol": "TCP",
            "status": "Closed",
            "service": service_name,
            "category": category,
            "banner": None,
            "vulnerability": None,
            "cve_details": None,
            "web_audit": None
        }

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target_ip, port),
                timeout=timeout
            )
            
            result["status"] = "Open"
            
            close_res = writer.close()
            if inspect.isawaitable(close_res):
                await close_res
            if hasattr(writer, "wait_closed"):
                wait_res = writer.wait_closed()
                if inspect.isawaitable(wait_res):
                    await wait_res
            
            # Grab Banner
            fetched_banner = await grab_banner(target_ip, port, timeout=2.0)
            result["banner"] = fetched_banner
            
            # Offline vulnerability signature check
            vuln_data = check_vulnerabilities(port, fetched_banner, protocol="tcp")
            if vuln_data:
                result["vulnerability"] = vuln_data

            # Live online CVE lookup
            if lookup_cves and fetched_banner and "No banner returned" not in fetched_banner:
                live_cve = await lookup_cve_for_banner(fetched_banner)
                if live_cve:
                    result["cve_details"] = live_cve
                    if not result["vulnerability"]:
                        result["vulnerability"] = live_cve

            # Web Application & TLS Certificate Audit
            if port in {80, 81, 443, 3000, 5000, 8000, 8080, 8081, 8443, 8888, 9090}:
                loop = asyncio.get_running_loop()
                web_meta = await loop.run_in_executor(None, audit_web_service, target_ip, port, 3.0)
                if web_meta:
                    result["web_audit"] = web_meta

        except (asyncio.TimeoutError, ConnectionRefusedError, socket.error):
            pass

        return result

    if semaphore:
        async with semaphore:
            return await _do_scan()
    else:
        return await _do_scan()

async def run_port_scan(
    target_ip: str, 
    ports_to_scan: list = None, 
    scan_mode: str = "TCP", 
    lookup_cves: bool = True, 
    max_concurrency: int = 100,
    profile: str = "ALL"
) -> list:
    """
    Unified entry point for multi-protocol scanning with device profiling & concurrency limits.
    """
    mode = scan_mode.upper()
    semaphore = asyncio.Semaphore(max_concurrency)

    # Determine target ports based on device profile selection
    target_ports = ports_to_scan
    if not target_ports or len(target_ports) == 0:
        prof_clean = profile.lower().strip()
        if prof_clean in ["router", "printer", "iot", "nas", "database", "web", "workstation"]:
            target_ports = get_ports_for_profile(prof_clean)
        elif prof_clean == "auto":
            # Auto-detect device profile by quick probe of key profile ports
            quick_ports = [80, 443, 445, 3306, 9100, 1883, 1900, 3389]
            quick_res = await asyncio.gather(*[scan_single_tcp_port(target_ip, p, timeout=0.8, lookup_cves=False, semaphore=semaphore) for p in quick_ports])
            open_p = [r["port"] for r in quick_res if "Open" in r["status"]]
            detected_dev = classify_device_type(open_p)
            
            # Map detected device type to profile ports
            dev_map = {
                "Printer / Multi-Function Device": "printer",
                "Router / Network Gateway": "router",
                "NAS / Storage Server": "nas",
                "Database Server": "database",
                "IoT / Smart Device": "iot",
                "Workstation / PC": "workstation",
                "Web Server / Application Host": "web"
            }
            assigned_prof = dev_map.get(detected_dev, "web")
            target_ports = get_ports_for_profile(assigned_prof)
        else:
            target_ports = list(get_common_ports().keys())

    if mode == "UDP":
        udp_ports = target_ports if ports_to_scan else list(get_udp_ports().keys())
        return await run_udp_port_scan(target_ip, udp_ports)
        
    elif mode == "SYN":
        return await run_syn_port_scan(target_ip, target_ports)

    elif mode == "COMBINED":
        udp_ports = list(get_udp_ports().keys())
        tcp_task = asyncio.gather(*[scan_single_tcp_port(target_ip, p, lookup_cves=lookup_cves, semaphore=semaphore) for p in target_ports])
        udp_task = run_udp_port_scan(target_ip, udp_ports)
        
        tcp_res, udp_res = await asyncio.gather(tcp_task, udp_task)
        return list(tcp_res) + list(udp_res)

    else:  # Default TCP Connect Scan
        tasks = [scan_single_tcp_port(target_ip, p, lookup_cves=lookup_cves, semaphore=semaphore) for p in target_ports]
        return await asyncio.gather(*tasks)