import platform

def detect_os_from_ttl(ttl: int) -> dict:
    """
    Fingerprints operating system based on IP TTL (Time To Live) response values.
      TTL 64  -> Linux / Unix / macOS / Android
      TTL 128 -> Windows 10/11 / Windows Server
      TTL 255 -> Cisco IOS / Solaris / Network Router
    """
    if ttl is None:
        return {"os_family": "Unknown", "confidence": "Low", "details": "No TTL response received"}

    ttl = int(ttl)
    if ttl <= 64:
        # Distance calculation assuming initial TTL of 64
        hops = 64 - ttl
        return {
            "os_family": "Linux / Unix / macOS",
            "confidence": "High" if hops <= 5 else "Medium",
            "estimated_ttl": 64,
            "network_hops": hops,
            "details": f"TTL={ttl} (Estimated {hops} network hops away from initial TTL 64)"
        }
    elif ttl <= 128:
        hops = 128 - ttl
        return {
            "os_family": "Microsoft Windows",
            "confidence": "High" if hops <= 5 else "Medium",
            "estimated_ttl": 128,
            "network_hops": hops,
            "details": f"TTL={ttl} (Estimated {hops} network hops away from initial TTL 128)"
        }
    elif ttl <= 255:
        hops = 255 - ttl
        return {
            "os_family": "Cisco IOS / Network Device / Solaris",
            "confidence": "Medium",
            "estimated_ttl": 255,
            "network_hops": hops,
            "details": f"TTL={ttl} (Estimated {hops} network hops away from initial TTL 255)"
        }
    
    return {"os_family": "Unknown", "confidence": "Low", "details": f"Unrecognized TTL value: {ttl}"}
