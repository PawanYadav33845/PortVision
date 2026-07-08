import socket
import re

def validate_target(target: str) -> str:
    """
    Validates if the target input is a valid IPv4 address or domain name.
    If it's a domain, it resolves it to its corresponding IP address.
    Returns the clean IP address string, or raises a ValueError if invalid.
    """
    target = target.strip()

    # 1. Check if it's a valid IPv4 format using regex
    ip_pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    if ip_pattern.match(target):
        # Double-check that octets are between 0 and 255
        try:
            socket.inet_aton(target)
            return target
        except socket.error:
            raise ValueError(f"Invalid IP address format: {target}")

    # 2. If it's not a raw IP, assume it's a domain name and try to resolve it
    try:
        resolved_ip = socket.gethostbyname(target)
        return resolved_ip
    except socket.gaierror:
        raise ValueError(f"Could not resolve host or domain: '{target}'")

def get_common_ports() -> dict:
    """
    Returns a dictionary of standard TCP ports and their associated service names
    to use for mapping and baseline scanning.
    """
    return {
        21: "FTP (File Transfer Protocol)",
        22: "SSH (Secure Shell)",
        23: "Telnet (Unencrypted Text)",
        25: "SMTP (Simple Mail Transfer)",
        53: "DNS (Domain Name System)",
        80: "HTTP (Hypertext Transfer Protocol)",
        110: "POP3 (Post Office Protocol)",
        443: "HTTPS (Secure HTTP)",
        445: "SMB (Server Message Block)",
        3306: "MySQL Database",
        8080: "HTTP Alternate / Tomcat"
    }