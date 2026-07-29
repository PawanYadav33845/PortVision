def check_vulnerabilities(port: int, banner: str, protocol: str = "tcp") -> dict:
    """
    Analyzes a port number, protocol, and gathered banner metadata against 
    an expanded offline threat matrix. Returns risk analysis dictionary if flagged.
    """
    banner_clean = banner.lower() if banner else ""

    # Protocol-Specific UDP Risks
    if protocol.lower() == "udp":
        if port == 53:
            return {
                "title": "Exposed UDP DNS Server (Open Resolver Risk)",
                "severity": "Medium",
                "cve_id": "CWE-400",
                "description": "Publicly exposed UDP DNS resolvers can be weaponized in DNS amplification DDoS attacks.",
                "remediation": "Restrict DNS recursion to trusted internal IP ranges only."
            }
        if port == 123:
            return {
                "title": "NTP UDP Monlist / Amplification Risk",
                "severity": "Medium",
                "cve_id": "CVE-2013-5211",
                "description": "NTP servers executing monlist command enable high-factor UDP amplification DDoS attacks.",
                "remediation": "Disable `monlist` query support in ntp.conf (`noquery`)."
            }
        if port == 161:
            return {
                "title": "Exposed SNMP UDP Service (Default Community Strings)",
                "severity": "High",
                "cve_id": "CWE-200",
                "description": "SNMP over UDP exposes critical system health and network topology metrics if default 'public' community strings are enabled.",
                "remediation": "Change default SNMP community strings and switch to SNMPv3 with authNoPriv/authPriv."
            }
        if port == 1900:
            return {
                "title": "SSDP / UPnP Amplification Vulnerability",
                "severity": "Low",
                "cve_id": "CWE-200",
                "description": "SSDP services on port 1900 reveal local UPnP network metadata and can participate in UDP reflection attacks.",
                "remediation": "Disable UPnP on WAN interfaces."
            }
        if port == 5353:
            return {
                "title": "Exposed mDNS (Multicast DNS) Service",
                "severity": "Low",
                "cve_id": "CWE-200",
                "description": "Multicast DNS leaks internal device hostnames and network services across local subnets.",
                "remediation": "Filter port 5353 UDP at subnet network boundaries."
            }

    # Protocol-Specific TCP Port & Service Risks
    if port == 23:
        return {
            "title": "Unencrypted Telnet Protocol Active",
            "severity": "High",
            "cve_id": "CWE-319",
            "description": "Telnet transmits all login credentials and commands in cleartext over the network.",
            "remediation": "Disable Telnet service and migrate to SSH (Port 22)."
        }
        
    if port == 21:
        if "vsftpd 2.3.4" in banner_clean or "vsftpd_2.3.4" in banner_clean:
            return {
                "title": "VSFTPD v2.3.4 Malicious Backdoor Command Execution",
                "severity": "Critical",
                "cve_id": "CVE-2011-2523",
                "description": "VSFTPD 2.3.4 source distribution contains a malicious backdoor triggered by specific username sequences.",
                "remediation": "Purge vsftpd 2.3.4 immediately and install a safe release or SFTP."
            }
        return {
            "title": "Cleartext FTP Authentication",
            "severity": "Medium",
            "cve_id": "CWE-319",
            "description": "FTP sends username and password credentials unencrypted unless TLS (FTPS) is enforced.",
            "remediation": "Enforce FTPS (Explicit TLS) or migrate to SFTP (Port 22)."
        }

    if port == 445 or port == 139:
        return {
            "title": "Exposed SMB (Server Message Block) Service",
            "severity": "High",
            "cve_id": "CVE-2017-0143",
            "description": "Exposed SMB services present a wide attack surface historically targeted by exploits like EternalBlue.",
            "remediation": "Firewall port 445/139 from public internet, enforce SMBv3 signing, and disable SMBv1."
        }

    if port == 1883:
        return {
            "title": "Unencrypted MQTT Broker Exposed",
            "severity": "Medium",
            "cve_id": "CWE-319",
            "description": "Unencrypted MQTT brokers expose IoT device telemetry, sensor data, and control topics to network sniffing.",
            "remediation": "Enforce MQTT over TLS (Port 8883) with client certificate authentication."
        }

    if port == 2375:
        return {
            "title": "Unencrypted Docker Remote REST Daemon",
            "severity": "Critical",
            "cve_id": "CWE-306",
            "description": "Docker daemon listening on unencrypted port 2375 grants immediate root container/host takeover privileges.",
            "remediation": "Never expose port 2375 to networks; use SSH socket forwarding or port 2376 with TLS client certificates."
        }

    if port == 2379:
        return {
            "title": "Exposed Etcd API Endpoint",
            "severity": "Critical",
            "cve_id": "CWE-306",
            "description": "Unauthenticated etcd endpoints expose Kubernetes cluster secrets, configuration data, and encryption keys.",
            "remediation": "Enable mutual TLS authentication (`--client-cert-auth`) for etcd access."
        }

    if port == 3389:
        return {
            "title": "Exposed RDP (Remote Desktop Protocol)",
            "severity": "High",
            "cve_id": "CVE-2019-0708",
            "description": "Directly exposing RDP to public networks makes hosts vulnerable to brute-force attacks and RCE exploits like BlueKeep.",
            "remediation": "Place RDP behind a VPN or Remote Desktop Gateway, enforce NLA (Network Level Authentication), and enable 2FA."
        }

    if port == 5900 or port == 5901:
        return {
            "title": "Exposed Unencrypted VNC Desktop",
            "severity": "High",
            "cve_id": "CWE-306",
            "description": "VNC remote desktop servers exposed without strong passwords allow unauthorized graphical remote access.",
            "remediation": "Tunnel VNC sessions over SSH or VPN, and enforce strong authentication."
        }

    if port == 6379:
        return {
            "title": "Exposed Redis In-Memory Data Store",
            "severity": "Critical",
            "cve_id": "CWE-306",
            "description": "Redis instances exposed without authentication allow unauthenticated remote command execution and data exfiltration.",
            "remediation": "Enable `requirepass` authentication, bind to 127.0.0.1, or place behind a firewall."
        }

    if port == 6443:
        return {
            "title": "Exposed Kubernetes API Server",
            "severity": "High",
            "cve_id": "CWE-284",
            "description": "Publicly reachable Kubernetes API servers can lead to cluster compromise if anonymous auth is misconfigured.",
            "remediation": "Ensure `--anonymous-auth=false` is enforced and restrict IP access via network policies."
        }

    if port == 8009:
        return {
            "title": "Exposed Apache Tomcat AJP Connector (Ghostcat Risk)",
            "severity": "High",
            "cve_id": "CVE-2020-1938",
            "description": "AJP13 protocol connector on port 8009 allows remote file reading and potential RCE via Ghostcat exploit.",
            "remediation": "Upgrade Apache Tomcat or disable AJP connector if unused."
        }

    if port == 8088:
        return {
            "title": "Exposed Hadoop YARN Resource Manager",
            "severity": "High",
            "cve_id": "CWE-306",
            "description": "Unauthenticated Hadoop YARN APIs allow remote attackers to submit arbitrary batch execution jobs.",
            "remediation": "Enforce Kerberos authentication for Hadoop cluster services."
        }

    if port == 9000:
        return {
            "title": "Exposed PHP-FPM / MinIO Admin Console",
            "severity": "High",
            "cve_id": "CVE-2019-11043",
            "description": "Exposed FastCGI / MinIO interfaces can lead to remote command execution under misconfigured NGINX setups.",
            "remediation": "Restrict port 9000 to local unix sockets or internal loopback interfaces."
        }

    if port == 9200:
        return {
            "title": "Exposed Elasticsearch REST API",
            "severity": "High",
            "cve_id": "CWE-306",
            "description": "Elasticsearch REST APIs exposed without Shield/X-Pack authentication allow direct database indexing and deletion.",
            "remediation": "Enable Elastic Stack Security authentication and disable public API access."
        }

    if port == 11211:
        return {
            "title": "Exposed Unauthenticated Memcached Server",
            "severity": "Critical",
            "cve_id": "CVE-2018-1000115",
            "description": "Unauthenticated Memcached servers can be abused for massive UDP reflection attacks and data tampering.",
            "remediation": "Bind Memcached exclusively to local interfaces (`-l 127.0.0.1`) and disable UDP if unused."
        }

    if port == 27017:
        return {
            "title": "Exposed Unauthenticated MongoDB Instance",
            "severity": "Critical",
            "cve_id": "CWE-306",
            "description": "MongoDB databases exposed without access control allow remote attackers to read, drop, or ransom databases.",
            "remediation": "Enable `security.authorization: enabled` in mongod.conf."
        }

    # Version Banner Matches
    if "openssh_7.2" in banner_clean or "openssh 7.2" in banner_clean:
        return {
            "title": "Outdated OpenSSH Version Discovered (v7.2)",
            "severity": "High",
            "cve_id": "CVE-2018-15473",
            "description": "OpenSSH 7.2 is vulnerable to username enumeration via crafted auth requests.",
            "remediation": "Upgrade OpenSSH to the latest stable release."
        }

    if "apache/2.4.49" in banner_clean or "apache/2.4.50" in banner_clean:
        return {
            "title": "Apache HTTP Server Path Traversal & RCE",
            "severity": "Critical",
            "cve_id": "CVE-2021-41773",
            "description": "Flaw in path normalization allows unauthenticated remote attackers to map files outside document root and execute code.",
            "remediation": "Upgrade Apache HTTP Server immediately to 2.4.51 or higher."
        }

    if "log4j" in banner_clean or "log4shell" in banner_clean:
        return {
            "title": "Apache Log4j Remote Code Execution (Log4Shell)",
            "severity": "Critical",
            "cve_id": "CVE-2021-44228",
            "description": "JNDI lookup vulnerability in Log4j allows remote unauthenticated code execution via HTTP headers or inputs.",
            "remediation": "Update log4j core dependency to 2.17.1+."
        }

    return None