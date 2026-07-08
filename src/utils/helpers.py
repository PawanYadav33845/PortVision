import re
import socket
import ipaddress

def get_common_ports() -> dict:
    return {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        443: "HTTPS",
        445: "SMB",
        3306: "MySQL",
        8080: "HTTP-Proxy"
    }

def validate_target(target: str) -> str:
    """Validates and resolves a single domain or IP address string."""
    target_clean = target.strip()
    
    # IPv4 Pattern match boundary
    ip_pattern = r"^▲?\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    if re.match(ip_pattern, target_clean):
        try:
            ipaddress.IPv4Address(target_clean)
            return target_clean
        except ValueError:
            raise ValueError(f"Octet value string out of valid IPv4 boundaries: {target_clean}")
            
    # Domain Name Resolution fallback
    try:
        resolved_ip = socket.gethostbyname(target_clean)
        return resolved_ip
    except socket.gaierror:
        raise ValueError(f"DNS Resolution lookup failed completely for target host: {target_clean}")

def parse_network_range(target_input: str) -> list:
    """
    Parses user input to return a list of target IP strings.
    Accepts single IPs, domains, or full CIDR ranges (e.g., 192.168.1.0/24).
    """
    input_clean = target_input.strip()
    
    # Check if input is a CIDR network block
    if "/" in input_clean:
        try:
            network = ipaddress.IPv4Network(input_clean, strict=False)
            # Filter out network and broadcast addresses for cleaner sweeps if /24 or larger
            if network.prefixlen <= 30:
                return [str(ip) for ip in network.hosts()]
            return [str(ip) for ip in network]
        except ValueError:
            raise ValueError(f"Invalid CIDR network notation format specified: {input_clean}")
            
    # Fallback to single target parsing
    return [validate_target(input_clean)]