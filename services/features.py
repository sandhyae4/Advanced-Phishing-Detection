import ipaddress
import math
import re
from urllib.parse import urlparse, unquote

MEDIA_PIRACY_WORDS = {"music", "mp3", "audio", "song", "track", "album", "torrent", "torrentz",
                      "crack", "warez", "keygen", "serial", "pirate", "stream", "streaming",
                      "freedownload", "rip", "codec", "mp3raid"}
MALWARE_TERMS = {"trojan", "payload", "exploit", "keylogger", "ransomware", "backdoor",
                 "spyware", "adware", "inject", "shell", "bypass", "malware", "virus", "botnet"}
EXECUTABLE_EXTENSIONS = {".exe", ".scr", ".bat", ".apk", ".zip", ".msi", ".iso", ".dmg",
                         ".jar", ".vbs", ".cmd", ".dll", ".bin", ".ps1"}
FREE_HOSTING_DOMAINS = {"firebaseapp.com", "pages.dev", "000webhostapp.com", "ngrok-free.app",
                        "duckdns.org", "weebly.com", "wixsite.com", "glitch.me", "surge.sh",
                        "vercel.app", "rf.gd", "epizy.com"}

SUSPICIOUS_WORDS = {"login", "verify", "verification", "secure", "account", "update", "confirm",
                    "password", "signin", "banking", "wallet", "invoice", "suspended", "restore",
                    "unlock", "webscr", "bonus", "crypto", "authenticate", "support", "security",
                    "alert", "billing", "payment", "auth", "identity", "id", "claim", "prize",
                    "winner", "reward", "giveaway", "gift", "free", "urgent", "limited", "expire",
                    "expired", "immediately", "warning", "blocked", "disabled", "locked", "breach",
                    "unauthorized", "unusual", "refund", "tax", "delivery", "parcel", "shipment",
                    "tracking", "fee", "overdue", "kyc", "recover", "recovery", "validate", "activation",
                    "deactivate", "compromised", "document", "download", "salary", "job", "offer",
                    "investment", "profit", "airdrop", "seed", "mnemonic", "exchange", "lottery"} | MEDIA_PIRACY_WORDS | MALWARE_TERMS
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly",
              "rebrand.ly", "shorturl.at", "tiny.cc"}
RISKY_TLDS = {"zip", "mov", "click", "top", "xyz", "work", "support", "site", "online", "live",
              "country", "stream", "gq", "tk", "ml", "cf"}
PROTECTED_BRANDS = {"facebook", "google", "microsoft", "paypal", "apple", "amazon", "netflix",
                    "instagram", "whatsapp", "github", "openai", "chatgpt", "dropbox", "linkedin"}


def _edit_distance(a, b):
    """Small deterministic Levenshtein distance used for brand typosquats."""
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current = [i]
        for j, cb in enumerate(b, 1):
            current.append(min(current[-1] + 1, previous[j] + 1,
                               previous[j - 1] + (ca != cb)))
        previous = current
    return previous[-1]


def extract_registered_domain(host):
    """Extract root registered domain from hostname."""
    if not host:
        return ""
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    parts = host.lower().rstrip(".").split(".")
    if len(parts) <= 2:
        return host
    second_level_prefixes = {
        "co", "com", "net", "org", "ac", "edu", "gov", "gob", "res",
        "mil", "gen", "firm", "ind", "sch", "govt", "ne", "or", "go", "ed"
    }
    if len(parts) >= 3 and parts[-2] in second_level_prefixes and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def count_subdomains(host):
    if not host:
        return 0
    try:
        ipaddress.ip_address(host)
        return 0
    except ValueError:
        pass
    reg = extract_registered_domain(host)
    if not reg or host == reg:
        return 0
    prefix = host[:-len(reg)].rstrip(".")
    return prefix.count(".") + 1


def brand_typosquat(host):
    reg = extract_registered_domain(host)
    candidate = reg.split(".")[0] if reg else host.split(".")[0]
    compact = re.sub(r"[^a-z0-9]", "", candidate)
    for brand in PROTECTED_BRANDS:
        if compact != brand and _edit_distance(compact, brand) == 1:
            return brand
    return None


def normalize_url(raw):
    if not raw or len(raw) > 2048 or any(c in raw for c in "\r\n\t"):
        raise ValueError("Enter a valid URL (maximum 2,048 characters).")
    candidate = raw.strip()
    if re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*:", candidate):
        scheme_prefix = candidate.split(":", 1)[0].lower()
        if scheme_prefix not in {"http", "https"}:
            raise ValueError("Only valid HTTP or HTTPS website URLs can be analyzed.")
    if "://" not in candidate:
        candidate = "https://" + candidate
    try:
        parsed = urlparse(candidate)
    except Exception as exc:
        raise ValueError("Only valid HTTP or HTTPS website URLs can be analyzed.") from exc
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Only valid HTTP or HTTPS website URLs can be analyzed.")
    try:
        host = parsed.hostname.encode("idna").decode("ascii").lower().rstrip(".")
    except UnicodeError as exc:
        raise ValueError("The domain name is invalid.") from exc
    try:
        port = f":{parsed.port}" if parsed.port else ""
    except ValueError:
        raise ValueError("The URL contains an invalid port number.")
    userinfo = (parsed.netloc.split("@", 1)[0] + "@") if "@" in parsed.netloc else ""
    return parsed._replace(netloc=f"{userinfo}{host}{port}").geturl()


def lexical_features(url):
    parsed = urlparse(url)
    host = parsed.hostname or ""
    text = unquote((parsed.path + "?" + parsed.query).lower())
    tokens = set(re.findall(r"[a-z]+", host + "/" + text))
    try:
        ipaddress.ip_address(host)
        is_ip = 1
    except ValueError:
        is_ip = 0
    entropy = 0.0
    if host:
        entropy = -sum((host.count(c) / len(host)) * math.log2(host.count(c) / len(host)) for c in set(host))
    typo_brand = brand_typosquat(host)
    path_lower = (parsed.path or "").lower()
    has_executable_ext = int(any(path_lower.endswith(ext) for ext in EXECUTABLE_EXTENSIONS))
    has_media_piracy = int(bool(tokens & MEDIA_PIRACY_WORDS))
    media_terms = sorted(tokens & MEDIA_PIRACY_WORDS)
    malware_terms = sorted(tokens & MALWARE_TERMS)
    is_free_hosting = int(any(host.endswith("." + dom) or host == dom for dom in FREE_HOSTING_DOMAINS))
    has_static_html = int(path_lower.endswith(".html") or path_lower.endswith(".htm"))
    subdomains_count = count_subdomains(host)
    return {
        "url_length": len(url), "host_length": len(host), "path_length": len(parsed.path),
        "dots": host.count("."), "hyphens": host.count("-"), "digits": sum(c.isdigit() for c in url),
        "special_chars": sum(url.count(c) for c in "@=_%?&"), "subdomains": subdomains_count,
        "is_ip": is_ip, "has_at": int("@" in url), "double_slash_path": int("//" in parsed.path),
        "https": int(parsed.scheme == "https"), "shortener": int(host in SHORTENERS),
        "risky_tld": int(host.rsplit(".", 1)[-1] in RISKY_TLDS),
        "punycode": int("xn--" in host), "suspicious_words": len(tokens & SUSPICIOUS_WORDS),
        "suspicious_terms": sorted(tokens & SUSPICIOUS_WORDS),
        "media_terms": media_terms, "malware_terms": malware_terms,
        "has_executable_ext": has_executable_ext, "has_media_piracy": has_media_piracy,
        "is_free_hosting": is_free_hosting, "has_static_html": has_static_html,
        "many_subdomains": int(subdomains_count >= 2), "encoded": url.count("%"), "host_entropy": round(entropy, 3),
        "brand_typosquat": int(bool(typo_brand)), "typosquat_brand": typo_brand,
    }


FEATURE_NAMES = ["url_length", "host_length", "path_length", "dots", "hyphens", "digits", "special_chars",
                 "subdomains", "is_ip", "has_at", "double_slash_path", "https", "shortener", "risky_tld",
                 "punycode", "suspicious_words", "many_subdomains", "encoded", "host_entropy", "brand_typosquat",
                 "has_executable_ext", "has_media_piracy", "is_free_hosting"]

def vectorize(url):
    f = lexical_features(url)
    return [f[name] for name in FEATURE_NAMES]
