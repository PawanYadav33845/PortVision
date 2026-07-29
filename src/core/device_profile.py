from typing import List, Dict

DEVICE_PORT_PROFILES: Dict[str, List[int]] = {
    "router": [22, 23, 53, 80, 161, 443, 623, 1900, 5353, 8080, 8443],
    "printer": [80, 161, 443, 515, 631, 8080, 9100],
    "iot": [80, 443, 1883, 1900, 5353, 5683, 8008, 8009, 8443, 8883],
    "nas": [139, 445, 548, 873, 2049, 8080, 8443],
    "database": [1433, 1521, 2379, 3306, 5432, 6379, 7000, 9042, 9200, 11211, 27017],
    "web": [80, 81, 443, 3000, 5000, 8000, 8080, 8081, 8088, 8443, 8500, 8888, 9000, 9090, 15672],
    "workstation": [135, 139, 445, 3389, 5900, 5901, 5985, 5986]
}

DEVICE_ICONS: Dict[str, str] = {
    "Router / Network Gateway": "🛜 Router / Gateway",
    "Printer / Multi-Function Device": "📠 Printer",
    "IoT / Smart Device": "📱 IoT Device",
    "NAS / Storage Server": "💾 NAS Storage",
    "Database Server": "🗄️ Database Server",
    "Workstation / PC": "💻 Workstation PC",
    "Web Server / Application Host": "🌐 Web Server",
    "Generic Network Device": "🖥️ Generic Device"
}

def get_ports_for_profile(profile_name: str) -> List[int]:
    """Returns list of ports targeted for a specific device profile."""
    prof = profile_name.lower().strip()
    return DEVICE_PORT_PROFILES.get(prof, [])

def classify_device_type(open_ports: List[int], banner_text: str = "") -> str:
    """
    Classifies a device type based on open port patterns and banner signatures.
    """
    port_set = set(open_ports)
    banner_clean = banner_text.lower() if banner_text else ""

    # 1. Printer Check
    if 9100 in port_set or 631 in port_set or 515 in port_set or "printer" in banner_clean or "jetdirect" in banner_clean:
        return "Printer / Multi-Function Device"

    # 2. Router / Network Appliance Check
    if (53 in port_set or 1900 in port_set) and (80 in port_set or 443 in port_set or 161 in port_set):
        return "Router / Network Gateway"

    # 3. NAS / Network Storage Server
    if (445 in port_set or 139 in port_set or 2049 in port_set or 548 in port_set) and (8080 in port_set or 8443 in port_set or 873 in port_set):
        return "NAS / Storage Server"

    # 4. Database Server
    if port_set.intersection({3306, 5432, 1433, 1521, 6379, 27017, 9200, 11211}):
        return "Database Server"

    # 5. IoT / Smart Device
    if 1883 in port_set or 8883 in port_set or 5683 in port_set or 8008 in port_set:
        return "IoT / Smart Device"

    # 6. Workstation / Windows Desktop
    if 3389 in port_set or 135 in port_set or 5985 in port_set or 5900 in port_set:
        return "Workstation / PC"

    # 7. Web Server
    if port_set.intersection({80, 443, 8080, 8443, 3000, 5000, 9000}):
        return "Web Server / Application Host"

    return "Generic Network Device"
