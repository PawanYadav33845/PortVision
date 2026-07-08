def check_vulnerabilities(port: int, banner: str) -> dict:
    """
    Analyzes a port number and its gathered banner metadata against a local 
    vulnerability reference matrix. Returns threat details if flagged.
    """
    banner_clean = banner.lower() if banner else ""

    # 1. Check by Port Default Vulnerabilities (Protocol-based risks)
    if port == 23:
        return {
            "title": "Unencrypted Telnet Protocol Active",
            "severity": "High",
            "description": "Telnet transmits all login credentials and commands in cleartext over the wire, allowing attackers to sniff passwords easily.",
            "remediation": "Disable the Telnet service immediately and migrate to SSH (Port 22) for secure, encrypted remote administration."
        }
        
    if port == 445:
        return {
            "title": "Exposed SMB (Server Message Block) Service",
            "severity": "Medium",
            "description": "Exposing SMB directly to network edges presents a wide attack surface. Historically targeted by critical exploits like EternalBlue (CVE-2017-0143).",
            "remediation": "Ensure SMB is strictly firewalled, restrict access to authorized internal IPs only, and enforce SMBv3 signing."
        }

    # 2. Check by Version Banner Matching (Simulating a mini-CVE search)
    if "openssh_7.2" in banner_clean:
        return {
            "title": "Outdated OpenSSH Version Discovered (v7.2)",
            "severity": "High",
            "description": "This specific version of OpenSSH is vulnerable to user enumeration flaws (CVE-2018-15473) and potential remote code execution under specific configurations.",
            "remediation": "Upgrade the underlying OpenSSH package to the latest stable release via your system's package manager."
        }
        
    if "vsftpd_2.3.4" in banner_clean:
        return {
            "title": "Critical VSFTPD Backdoor Version (v2.3.4)",
            "severity": "Critical",
            "description": "The downloaded source archive for vsftpd-2.3.4 historically contained a malicious backdoor triggered by a smiley face user input, giving instant root shell access.",
            "remediation": "Purge this package immediately from the host machine and install a verified, untainted version of FTP or switch to SFTP."
        }

    # If no signatures match, return None
    return None