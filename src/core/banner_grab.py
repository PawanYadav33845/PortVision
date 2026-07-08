import asyncio
import socket

async def grab_banner(target_ip: str, port: int, timeout: float = 2.0) -> str:
    """
    Connects to an open port and attempts to read its initial service banner string.
    """
    try:
        # Open a fresh connection stream specifically to receive data
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(target_ip, port),
            timeout=timeout
        )
        
        # Some services (like SSH, FTP, SMTP) send a banner immediately upon connection
        try:
            data = await asyncio.wait_for(reader.read(1024), timeout=1.5)
            banner = data.decode('utf-8', errors='ignore').strip()
            
            if banner:
                return banner
        except asyncio.TimeoutError:
            # If the service expects the client to speak first (like HTTP), sending a blank line can trigger a response
            writer.write(b"\r\n")
            await writer.drain()
            data = await asyncio.wait_for(reader.read(1024), timeout=1.5)
            banner = data.decode('utf-8', errors='ignore').strip()
            if banner:
                return banner
                
        # Clean up resources safely
        writer.close()
        await writer.wait_closed()
        
    except Exception:
        # If any socket connection failure occurs, return none
        pass
        
    return "No banner returned (Service requires explicit payload)"