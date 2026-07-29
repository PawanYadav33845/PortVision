import re
import os
import sys
import subprocess
from typing import Optional, Dict

OUI_VENDOR_DATABASE: Dict[str, str] = {
    "00:05:69": "VMware, Inc.",
    "00:0C:29": "VMware, Inc.",
    "00:50:56": "VMware, Inc.",
    "00:1C:42": "Parallels, Inc.",
    "08:00:27": "Oracle VirtualBox",
    "52:54:00": "QEMU / KVM Virtual Interface",
    "00:1A:2B": "Cisco Systems",
    "00:1E:13": "Cisco Systems",
    "00:26:0B": "Cisco Systems",
    "00:11:32": "Synology Inc. (NAS)",
    "00:08:9B": "QNAP Systems, Inc. (NAS)",
    "B8:27:EB": "Raspberry Pi Foundation",
    "DC:A6:32": "Raspberry Pi Foundation",
    "E4:5F:01": "Raspberry Pi Foundation",
    "3C:22:FB": "Apple, Inc.",
    "AC:bc:32": "Apple, Inc.",
    "70:85:C2": "HP Inc. / Hewlett-Packard",
    "30:8D:99": "Hewlett Packard Enterprise",
    "00:14:22": "Dell Inc.",
    "F4:CE:46": "Dell Inc.",
    "00:1F:C6": "ASUSTeK Computer Inc.",
    "D8:3B:BF": "TP-Link Corporation",
    "00:27:22": "Ubiquiti Networks",
    "78:8A:20": "Ubiquiti Networks",
    "18:FE:34": "Espressif Systems (IoT)",
    "24:0A:C4": "Espressif Systems (IoT)",
    "60:01:94": "Espressif Systems (IoT)",
    "A4:CF:12": "Xiaomi Communications",
    "7C:49:EB": "Intel Corporation"
}

def get_mac_from_arp(ip: str) -> Optional[str]:
    """
    Parses the local operating system ARP table to find the MAC address for a given IP.
    """
    if ip.startswith("127."):
        return "00:00:00:00:00:00"

    try:
        if sys.platform == "win32":
            cmd = ["arp", "-a", ip]
            output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=2).decode("latin-1", errors="ignore")
            # Match MAC pattern e.g. 00-1a-2b-3c-4d-5e
            match = re.search(r"([0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2})", output)
            if match:
                return match.group(1).replace("-", ":").upper()
        else:
            cmd = ["arp", "-n", ip]
            output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=2).decode("utf-8", errors="ignore")
            match = re.search(r"([0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2})", output)
            if match:
                return match.group(1).upper()
    except Exception:
        pass
    return None

def lookup_vendor_by_mac(mac: str) -> str:
    """
    Resolves hardware manufacturer vendor name from MAC address OUI prefix.
    """
    if not mac or mac == "00:00:00:00:00:00":
        return "Local Host / Loopback"

    mac_clean = mac.upper().replace("-", ":")
    prefix = ":".join(mac_clean.split(":")[:3])

    if prefix in OUI_VENDOR_DATABASE:
        return OUI_VENDOR_DATABASE[prefix]

    # Check case-insensitive prefix match
    for oui, vendor in OUI_VENDOR_DATABASE.items():
        if oui.upper() == prefix:
            return vendor

    return "Generic Hardware Vendor"
