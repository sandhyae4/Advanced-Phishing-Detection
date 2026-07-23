import datetime as dt
import hashlib
import ipaddress
import socket
import ssl
from urllib.parse import urlparse
import requests
from config import REQUEST_TIMEOUT, GOOGLE_SAFE_BROWSING_API_KEY, VIRUSTOTAL_API_KEY, BASE_DIR


def is_public_host(host):
    try:
        infos = socket.getaddrinfo(host, None)
        addresses = {item[4][0] for item in infos}
        return bool(addresses) and all(ipaddress.ip_address(a).is_global for a in addresses), sorted(addresses)
    except (socket.gaierror, ValueError):
        return False, []


def ssl_check(host, scheme):
    if scheme != "https":
        return {"status": "No certificate — HTTP", "valid": False, "days_remaining": None}
    public, _ = is_public_host(host)
    if not public:
        return {"status": "Unavailable", "valid": None, "days_remaining": None}
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=REQUEST_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=host) as wrapped:
                cert = wrapped.getpeercert()
        expires = dt.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=dt.timezone.utc)
        days = (expires - dt.datetime.now(dt.timezone.utc)).days
        return {"status": "Valid" if days >= 0 else "Expired", "valid": days >= 0, "days_remaining": days}
    except Exception:
        return {"status": "Validation failed", "valid": False, "days_remaining": None}


def whois_check(host):
    try:
        import whois
        data = whois.whois(host)
        created = data.creation_date
        if isinstance(created, list): created = created[0]
        if created and created.tzinfo is None: created = created.replace(tzinfo=dt.timezone.utc)
        days = (dt.datetime.now(dt.timezone.utc) - created).days if created else None
        return {"status": "Known" if days is not None else "Unknown", "age_days": days,
                "age_display": f"{days // 365}y {days % 365}d" if days is not None else "Unknown"}
    except Exception:
        return {"status": "Unknown", "age_days": None, "age_display": "Unknown"}


def blacklist_check(url):
    host = (urlparse(url).hostname or "").lower().rstrip(".")
    providers, hits, errors = ["Local domain blacklist"], 0, []
    local_file = BASE_DIR / "data" / "blacklist.txt"
    try:
        entries = {line.strip().lower().rstrip(".") for line in local_file.read_text(encoding="utf-8").splitlines()
                   if line.strip() and not line.lstrip().startswith("#")}
        if any(host == entry or host.endswith("." + entry) for entry in entries):
            hits += 1
    except OSError:
        errors.append("Local blacklist unavailable")
    if GOOGLE_SAFE_BROWSING_API_KEY:
        providers.append("Google Safe Browsing")
        try:
            body = {"client": {"clientId": "phishguard-academic", "clientVersion": "1.0"},
                    "threatInfo": {"threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                                   "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"],
                                   "threatEntries": [{"url": url}]}}
            r = requests.post("https://safebrowsing.googleapis.com/v4/threatMatches:find",
                              params={"key": GOOGLE_SAFE_BROWSING_API_KEY}, json=body, timeout=REQUEST_TIMEOUT)
            r.raise_for_status()
            hits += int(bool(r.json().get("matches")))
        except Exception: errors.append("Google Safe Browsing unavailable")
    if VIRUSTOTAL_API_KEY:
        providers.append("VirusTotal")
        try:
            url_id = __import__("base64").urlsafe_b64encode(url.encode()).decode().strip("=")
            r = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}",
                             headers={"x-apikey": VIRUSTOTAL_API_KEY}, timeout=REQUEST_TIMEOUT)
            if r.status_code == 200:
                stats = r.json()["data"]["attributes"]["last_analysis_stats"]
                hits += int(stats.get("malicious", 0) > 0 or stats.get("suspicious", 0) > 1)
        except Exception: errors.append("VirusTotal unavailable")
    live_configured = bool(GOOGLE_SAFE_BROWSING_API_KEY or VIRUSTOTAL_API_KEY)
    if hits:
        status = "Listed"
    elif errors:
        status = "Check incomplete"
    elif live_configured:
        status = "Clean"
    else:
        status = "Clean (local)"
    return {"status": status,
            "listed": bool(hits), "providers": providers, "errors": errors}
