import os
import re
import json
import asyncio
import urllib.request
import urllib.error
from typing import Optional, Dict, List

# Try importing aiohttp, fallback gracefully if not installed
try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False

CACHE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../reports"))
CACHE_FILE = os.path.join(CACHE_DIR, "cve_cache.json")

def load_cve_cache() -> dict:
    """Loads cached CVE lookup results from disk."""
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def save_cve_cache(cache: dict):
    """Saves updated CVE lookup cache to disk."""
    try:
        os.makedirs(CACHE_DIR, exist_ok=True)
        with open(CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(cache, f, indent=4, ensure_ascii=False)
    except Exception:
        pass

def parse_banner_product_version(banner: str) -> Optional[dict]:
    """
    Parses banner text to extract product software name and version number.
    """
    if not banner:
        return None

    banner_clean = banner.strip()
    
    patterns = [
        r"([a-zA-Z0-9_\-]+)[/\s_](\d+\.\d+(?:\.\d+)?(?:p\d+)?)",
        r"([a-zA-Z0-9_\-]+)\s+v?(\d+\.\d+(?:\.\d+)?)"
    ]

    for pat in patterns:
        match = re.search(pat, banner_clean)
        if match:
            product = match.group(1).lower()
            version = match.group(2).lower()
            
            if product in ["http", "https", "tcp", "udp", "server", "ssh", "ftp"]:
                if product == "ssh":
                    product = "openssh"
                elif product == "ftp":
                    product = "vsftpd"
                elif product in ["http", "https"]:
                    product = "apache"
                    
            return {
                "product": product,
                "version": version,
                "query_string": f"{product}:{version}"
            }
            
    return None

def _sync_fetch_circl_cve(product: str, timeout: float = 4.0) -> List[dict]:
    """Fallback synchronous urllib HTTP fetch for CIRCL CVE API."""
    api_url = f"https://cve.circl.lu/api/search/{product}"
    cve_list = []
    try:
        req = urllib.request.Request(api_url, headers={'User-Agent': 'PortVision/2.0'})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status == 200:
                data = json.loads(resp.read().decode('utf-8'))
                results = data if isinstance(data, list) else data.get("results", [])
                for item in results:
                    summary = item.get("summary", "")
                    cve_id = item.get("id", "")
                    cvss = float(item.get("cvss", 0.0) or 0.0)
                    severity = "Critical" if cvss >= 9.0 else "High" if cvss >= 7.0 else "Medium" if cvss >= 4.0 else "Low"
                    cve_list.append({
                        "cve_id": cve_id,
                        "cvss": cvss,
                        "severity": severity,
                        "summary": summary[:250] + "..." if len(summary) > 250 else summary,
                        "references": item.get("references", [])[:2]
                    })
                    if len(cve_list) >= 3:
                        break
    except Exception:
        pass
    return cve_list

async def query_circl_cve_api(product: str, version: str, timeout: float = 4.0) -> List[dict]:
    """
    Queries CIRCL CVE Search API for vulnerabilities matching product/version.
    Uses aiohttp if available, or urllib threadpool executor fallback.
    """
    if HAS_AIOHTTP:
        api_url = f"https://cve.circl.lu/api/search/{product}"
        cve_list = []
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(api_url, timeout=timeout) as response:
                    if response.status == 200:
                        data = await response.json()
                        results = data if isinstance(data, list) else data.get("results", [])
                        for item in results:
                            summary = item.get("summary", "")
                            cve_id = item.get("id", "")
                            cvss = float(item.get("cvss", 0.0) or 0.0)
                            if version in summary.lower() or version in str(item.get("vulnerable_configuration", "")).lower():
                                severity = "Critical" if cvss >= 9.0 else "High" if cvss >= 7.0 else "Medium" if cvss >= 4.0 else "Low"
                                cve_list.append({
                                    "cve_id": cve_id,
                                    "cvss": cvss,
                                    "severity": severity,
                                    "summary": summary[:250] + "..." if len(summary) > 250 else summary,
                                    "references": item.get("references", [])[:2]
                                })
                                if len(cve_list) >= 3:
                                    break
        except Exception:
            pass
        return cve_list
    else:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, _sync_fetch_circl_cve, product, timeout)

async def lookup_cve_for_banner(banner: str) -> Optional[dict]:
    """
    Extracts software product & version from banner, checks local cache,
    and performs live vulnerability lookup if needed.
    """
    pv = parse_banner_product_version(banner)
    if not pv:
        return None

    query_key = pv["query_string"]
    cache = load_cve_cache()

    if query_key in cache:
        return cache[query_key]

    cves = await query_circl_cve_api(pv["product"], pv["version"])
    
    if cves:
        top_cve = cves[0]
        vuln_data = {
            "title": f"Live CVE Match: {top_cve['cve_id']} ({pv['product'].capitalize()} v{pv['version']})",
            "severity": top_cve["severity"],
            "cve_id": top_cve["cve_id"],
            "cvss": top_cve["cvss"],
            "description": top_cve["summary"],
            "remediation": f"Upgrade {pv['product']} from version {pv['version']} to a patched release.",
            "cve_matches": cves
        }
        cache[query_key] = vuln_data
        save_cve_cache(cache)
        return vuln_data

    cache[query_key] = None
    save_cve_cache(cache)
    return None
