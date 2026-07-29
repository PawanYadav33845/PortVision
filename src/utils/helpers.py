import re
import socket
import ipaddress

def get_common_ports() -> dict:
    """
    Returns an expanded dictionary of common TCP services (150+ ports).
    """
    return {
        21: "FTP (File Transfer Protocol)",
        22: "SSH (Secure Shell)",
        23: "Telnet (Unencrypted Remote Console)",
        25: "SMTP (Simple Mail Transfer)",
        53: "DNS (Domain Name System)",
        67: "DHCP Server",
        68: "DHCP Client",
        69: "TFTP (Trivial File Transfer)",
        80: "HTTP (Hypertext Transfer Protocol)",
        81: "HTTP Alternate / NGINX Proxy Manager",
        88: "Kerberos Authentication",
        110: "POP3 (Post Office Protocol v3)",
        111: "RPCbind / Portmapper",
        123: "NTP (Network Time Protocol)",
        135: "MS RPC Endpoint Mapper",
        137: "NetBIOS Name Service",
        138: "NetBIOS Datagram Service",
        139: "NetBIOS Session Service",
        143: "IMAP (Internet Message Access Protocol)",
        161: "SNMP (Simple Network Management)",
        162: "SNMP Trap",
        179: "BGP (Border Gateway Protocol)",
        389: "LDAP (Lightweight Directory Access Protocol)",
        443: "HTTPS (HTTP Secure)",
        445: "SMB (Server Message Block)",
        465: "SMTPS (SMTP over SSL)",
        500: "ISAKMP / IKE (IPsec Key Exchange)",
        514: "Syslog",
        515: "LPD (Line Printer Daemon)",
        587: "SMTP Submission (TLS)",
        636: "LDAPS (LDAP over SSL)",
        853: "DNS over TLS",
        873: "Rsync File Synchronization",
        993: "IMAPS (IMAP over SSL)",
        995: "POP3S (POP3 over SSL)",
        1025: "Microsoft RPC Network Service",
        1080: "SOCKS Proxy",
        1194: "OpenVPN",
        1433: "Microsoft SQL Server",
        1434: "MS SQL Monitor",
        1521: "Oracle Database TNS Listener",
        1701: "L2TP VPN",
        1723: "PPTP VPN",
        1812: "RADIUS Authentication",
        1813: "RADIUS Accounting",
        1883: "MQTT (Message Queuing Telemetry Transport)",
        1900: "SSDP / UPnP Discovery",
        2049: "NFS (Network File System)",
        2082: "cPanel Control Panel",
        2083: "cPanel Secure",
        2086: "WHM (WebHost Manager)",
        2087: "WHM Secure",
        2181: "Apache ZooKeeper",
        2222: "Custom SSH / DirectAdmin",
        2375: "Docker REST API (Unencrypted)",
        2376: "Docker REST API (TLS)",
        2379: "Etcd Client API",
        2380: "Etcd Peer Server",
        3000: "Grafana / Node.js Web App",
        3128: "Squid HTTP Proxy",
        3306: "MySQL Database",
        3389: "RDP (Remote Desktop Protocol)",
        4500: "IPsec NAT Traversal",
        5000: "UPnP / Docker Registry / Flask App",
        5000: "Flask / Docker Registry",
        5432: "PostgreSQL Database",
        5601: "Kibana Dashboard",
        5672: "RabbitMQ AMQP",
        5900: "VNC Remote Desktop",
        5901: "VNC Display :1",
        5985: "WinRM (HTTP)",
        5986: "WinRM (HTTPS)",
        6379: "Redis In-Memory Data Store",
        6443: "Kubernetes API Server",
        7000: "Cassandra Inter-Node",
        7001: "Oracle WebLogic Server",
        8000: "HTTP Alt / Django / FastAPI",
        8009: "Apache AJP13 Connector",
        8080: "HTTP Proxy / Jenkins / Apache Tomcat",
        8081: "HTTP Alt Service / Nexus",
        8088: "Hadoop YARN Resource Manager",
        8443: "HTTPS Alt / Admin Console",
        8500: "Consul Service Mesh",
        8883: "MQTT over TLS",
        8888: "Jupyter Notebook / HTTP Alt",
        9000: "MinIO / SonarQube / PHP-FPM",
        9042: "Apache Cassandra Native Protocol",
        9090: "Prometheus Monitoring Server",
        9092: "Apache Kafka",
        9200: "Elasticsearch REST API",
        9300: "Elasticsearch Cluster Comm",
        10000: "Webmin Control Panel",
        11211: "Memcached In-Memory Cache",
        15672: "RabbitMQ Management Console",
        27017: "MongoDB Database",
        27018: "MongoDB Shard Server",
        28017: "MongoDB Web Admin",
        50000: "SAP NetWeaver / Jenkins Slave",
        50070: "Hadoop HDFS NameNode Web UI"
    }

def get_udp_ports() -> dict:
    """
    Returns an expanded dictionary of common UDP ports with service descriptions.
    """
    return {
        53: "DNS (Domain Name System)",
        67: "DHCP Server",
        68: "DHCP Client",
        69: "TFTP (Trivial File Transfer)",
        88: "Kerberos KDC",
        111: "RPCbind / Portmapper",
        123: "NTP (Network Time Protocol)",
        135: "MS RPC",
        137: "NetBIOS Name Service",
        138: "NetBIOS Datagram Service",
        161: "SNMP (Simple Network Management Protocol)",
        162: "SNMP Trap",
        500: "IKE / IPsec VPN",
        514: "Syslog Server",
        520: "RIP (Routing Information Protocol)",
        623: "IPMI Remote Management",
        1194: "OpenVPN",
        1434: "MS SQL Server Monitor",
        1812: "RADIUS Auth",
        1813: "RADIUS Accounting",
        1900: "SSDP / UPnP",
        4500: "IPsec NAT-T",
        5353: "mDNS (Multicast DNS)",
        5683: "CoAP (Constrained Application Protocol)",
        11211: "Memcached UDP",
        16122: "Ubiquiti Discovery Protocol",
        51820: "WireGuard VPN"
    }

def get_port_category(port: int) -> str:
    """Returns the service category for a port number."""
    web_ports = {80, 81, 443, 3000, 5000, 5601, 8000, 8080, 8081, 8088, 8443, 8500, 8888, 9000, 9090, 10000, 15672, 50070}
    db_ports = {1433, 1521, 2379, 3306, 5432, 6379, 7000, 9042, 9200, 11211, 27017, 27018}
    remote_ports = {22, 23, 2222, 3389, 5900, 5901, 5985, 5986}
    mail_ports = {25, 110, 143, 465, 587, 993, 995}
    infra_ports = {53, 67, 68, 123, 137, 138, 139, 161, 389, 445, 1883, 1900, 514, 2181, 2375, 6443, 9092}
    
    if port in web_ports:
        return "Web Service"
    elif port in db_ports:
        return "Database Service"
    elif port in remote_ports:
        return "Remote Access"
    elif port in mail_ports:
        return "Mail Service"
    elif port in infra_ports:
        return "Infrastructure & Network"
    else:
        return "General Service"

def validate_target(target: str) -> str:
    """Validates and resolves a single domain or IP address string."""
    target_clean = target.strip()
    
    ip_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    if re.match(ip_pattern, target_clean):
        try:
            ipaddress.IPv4Address(target_clean)
            return target_clean
        except ValueError:
            raise ValueError(f"Octet value string out of valid IPv4 boundaries: {target_clean}")
            
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
    
    if "/" in input_clean:
        try:
            network = ipaddress.IPv4Network(input_clean, strict=False)
            if network.prefixlen <= 30:
                return [str(ip) for ip in network.hosts()]
            return [str(ip) for ip in network]
        except ValueError:
            raise ValueError(f"Invalid CIDR network notation format specified: {input_clean}")
            
    return [validate_target(input_clean)]