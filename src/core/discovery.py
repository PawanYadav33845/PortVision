import asyncio
import sys
import platform

async def ping_host(ip: str) -> str or None:
    """
    Sends a single asynchronous ICMP ping echo request to an IP address.
    Returns the IP if alive, or None if the host drops the packet request.
    """
    # Determine OS platform flag for ping command syntax configurations
    current_os = platform.system().lower()
    if current_os == "windows":
        cmd = ["ping", "-n", "1", "-w", "500", ip]
    else:
        cmd = ["ping", "-c", "1", "-W", "1", ip]
        
    try:
        # Launch non-blocking background system process shell
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        # Await connection timeout or completion
        await process.communicate()
        
        # Return IP if returncode is 0 (Success response received)
        if process.returncode == 0:
            return ip
    except Exception:
        pass
        
    return None

async def run_network_sweep(ip_list: list) -> list:
    """
    Aggregates concurrent non-blocking system pings across a full list of target IPs.
    """
    tasks = [ping_host(ip) for ip in ip_list]
    results = await asyncio.gather(*tasks)
    
    # Filter out None entries, returning only alive target IP strings
    return [ip for ip in results if ip is not None]