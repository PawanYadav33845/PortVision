import ssl
import socket
import urllib.request
import urllib.parse
import re
from datetime import datetime
from typing import Optional, Dict

WEB_PORTS = {80, 443, 3000, 5000, 8000, 8080, 8081, 8443, 8888, 9090, 9200, 10000}

def audit_tls_certificate(target_ip: str, port: int = 443, timeout: float = 3.0) -> Optional[dict]:
    """
    Fetches and inspects SSL/TLS certificate metadata for HTTPS services.
    Returns issuer, subject, validity dates, days remaining, and self-signed status.
    """
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((target_ip, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=target_ip) as ssock:
                cert = ssock.getpeercert(binary_form=False)
                if not cert:
                    # Retrieve binary cert if dictionary form is empty under CERT_NONE
                    der_cert = ssock.getpeercert(binary_form=True)
                    return {"cert_status": "Active TLS Connection", "verification": "Unverified / Self-Signed or Custom CA"}

                issuer = dict(x[0] for x in cert.get("issuer", []))
                subject = dict(x[0] for x in cert.get("subject", []))
                not_after_str = cert.get("notAfter", "")
                
                days_left = None
                if not_after_str:
                    try:
                        exp_date = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                        days_left = (exp_date - datetime.utcnow()).days
                    except Exception:
                        pass

                is_self_signed = issuer == subject

                return {
                    "issuer": issuer.get("organizationName") or issuer.get("commonName") or "Unknown Issuer",
                    "subject": subject.get("commonName") or subject.get("organizationName") or "Unknown Subject",
                    "expiration_date": not_after_str,
                    "days_remaining": days_left,
                    "is_self_signed": is_self_signed,
                    "is_expired": days_left is not None and days_left < 0
                }
    except Exception:
        return None

def audit_web_service(target_ip: str, port: int, timeout: float = 3.0) -> Optional[dict]:
    """
    Performs lightweight HTTP/HTTPS web application reconnaissance:
    - Page Title
    - Server & X-Powered-By headers
    - Security headers check (HSTS, CSP, X-Frame-Options)
    - SSL/TLS Certificate metrics (if HTTPS)
    """
    if port not in WEB_PORTS:
        return None

    scheme = "https" if port in {443, 8443} else "http"
    url = f"{scheme}://{target_ip}:{port}/"
    
    web_meta = {
        "url": url,
        "title": None,
        "server": None,
        "powered_by": None,
        "security_headers": {},
        "tls_cert": None
    }

    # Fetch TLS cert if HTTPS
    if scheme == "https":
        web_meta["tls_cert"] = audit_tls_certificate(target_ip, port, timeout=timeout)

    try:
        # Ignore SSL errors for testing self-signed apps
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        req = urllib.request.Request(url, headers={"User-Agent": "PortVision-Audit/2.0"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            headers = dict(resp.headers)
            web_meta["server"] = headers.get("Server") or headers.get("server")
            web_meta["powered_by"] = headers.get("X-Powered-By") or headers.get("x-powered-by")
            
            # Security Headers Audit
            sec_headers = {
                "HSTS": "Strict-Transport-Security" in headers or "strict-transport-security" in headers,
                "X-Frame-Options": "X-Frame-Options" in headers or "x-frame-options" in headers,
                "CSP": "Content-Security-Policy" in headers or "content-security-policy" in headers,
                "X-Content-Type-Options": "X-Content-Type-Options" in headers or "x-content-type-options" in headers
            }
            web_meta["security_headers"] = sec_headers

            body = resp.read(8192).decode("utf-8", errors="ignore")
            title_match = re.search(r"<title>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
            if title_match:
                web_meta["title"] = title_match.group(1).strip()[:100]

    except Exception:
        pass

    # Return web_meta if any useful information was discovered
    if web_meta["title"] or web_meta["server"] or web_meta["tls_cert"]:
        return web_meta
    return None
