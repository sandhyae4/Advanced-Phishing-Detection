import ipaddress
import math
import re
from urllib.parse import urlparse, unquote

SUSPICIOUS_WORDS = {"login", "verify", "verification", "secure", "account", "update", "confirm",
                    "password", "signin", "banking", "wallet", "invoice", "suspended", "restore",
                    "unlock", "webscr", "bonus", "crypto", "authenticate", "support", "security",
                    "alert", "billing", "payment", "auth", "identity", "id", "claim", "prize",
                    "winner", "reward", "giveaway", "gift", "free", "urgent", "limited", "expire",
                    "expired", "immediately", "warning", "blocked", "disabled", "locked", "breach",
                    "unauthorized", "unusual", "refund", "tax", "delivery", "parcel", "shipment",
                    "tracking", "fee", "overdue", "kyc", "recover", "recovery", "validate", "activation",
                    "deactivate", "compromised", "document", "download", "salary", "job", "offer",
                    "investment", "profit", "airdrop", "seed", "mnemonic", "exchange", "lottery"}
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


def brand_typosquat(host):
    labels = host.lower().split(".")
    candidate = labels[-2] if len(labels) >= 2 else labels[0]
    compact = re.sub(r"[^a-z0-9]", "", candidate)
    for brand in PROTECTED_BRANDS:
        if compact != brand and _edit_distance(compact, brand) == 1:
            return brand
    return None


def normalize_url(raw):
    if not raw or len(raw) > 2048 or any(c in raw for c in "\r\n\t"):
        raise ValueError("Enter a valid URL (maximum 2,048 characters).")
    candidate = raw.strip()
    if "://" not in candidate:
        candidate = "https://" + candidate
    parsed = urlparse(candidate)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Only valid HTTP or HTTPS website URLs can be analyzed.")
    try:
        host = parsed.hostname.encode("idna").decode("ascii").lower().rstrip(".")
    except UnicodeError as exc:
        raise ValueError("The domain name is invalid.") from exc
    port = f":{parsed.port}" if parsed.port else ""
    return parsed._replace(netloc=host + port).geturl()


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
    return {
        "url_length": len(url), "host_length": len(host), "path_length": len(parsed.path),
        "dots": host.count("."), "hyphens": host.count("-"), "digits": sum(c.isdigit() for c in url),
        "special_chars": sum(url.count(c) for c in "@=_%?&"), "subdomains": 0 if is_ip else max(0, host.count(".") - 1),
        "is_ip": is_ip, "has_at": int("@" in url), "double_slash_path": int("//" in parsed.path),
        "https": int(parsed.scheme == "https"), "shortener": int(host in SHORTENERS),
        "risky_tld": int(host.rsplit(".", 1)[-1] in RISKY_TLDS),
        "punycode": int("xn--" in host), "suspicious_words": len(tokens & SUSPICIOUS_WORDS),
        "suspicious_terms": sorted(tokens & SUSPICIOUS_WORDS),
        "many_subdomains": int(not is_ip and host.count(".") >= 3), "encoded": url.count("%"), "host_entropy": round(entropy, 3),
        "brand_typosquat": int(bool(typo_brand)), "typosquat_brand": typo_brand,
    }


FEATURE_NAMES = ["url_length", "host_length", "path_length", "dots", "hyphens", "digits", "special_chars",
                 "subdomains", "is_ip", "has_at", "double_slash_path", "https", "shortener", "risky_tld",
                 "punycode", "suspicious_words", "many_subdomains", "encoded", "host_entropy", "brand_typosquat"]

def vectorize(url):
    f = lexical_features(url)
    return [f[name] for name in FEATURE_NAMES]
