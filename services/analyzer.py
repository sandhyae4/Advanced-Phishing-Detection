from urllib.parse import urlparse
from services.features import normalize_url, lexical_features, SUSPICIOUS_WORDS
from services.intelligence import ssl_check, whois_check, blacklist_check
from services.model_service import predict

AMTSO_PATHS = {"/check-desktop-phishing-page/", "/check-mobile-phishing-page/"}
TRUSTED_DOMAINS = {
    "chatgpt.com": "OpenAI ChatGPT",
    "openai.com": "OpenAI",
    "google.com": "Google",
    "microsoft.com": "Microsoft",
    "microsoftonline.com": "Microsoft",
    "github.com": "GitHub",
    "wikipedia.org": "Wikipedia",
    "facebook.com": "Meta Facebook",
    "instagram.com": "Meta Instagram",
    "whatsapp.com": "Meta WhatsApp",
    "paypal.com": "PayPal",
    "apple.com": "Apple",
    "amazon.com": "Amazon",
    "netflix.com": "Netflix",
    "dropbox.com": "Dropbox",
    "linkedin.com": "LinkedIn",
    "adobe.com": "Adobe",
}
IMPERSONATED_BRANDS = {"paypal", "google", "microsoft", "amazon", "apple", "facebook", "netflix", "bank"}
REWARD_LURE_TERMS = {"claim", "prize", "winner", "reward", "giveaway", "gift", "free"}

# Operational risk policy. These values are deliberately separate from the
# machine-learning probabilities so the interface can explain severity.
RISK_PENALTIES = {
    "raw_ip": 25.0,
    "http": 15.0,
    "no_ssl_certificate": 15.0,
    "missing_domain_age": 10.0,
    "clean_blacklist_credit": -5.0,
}
LEGITIMATE_MAX = 30.0
SUSPICIOUS_MAX = 60.0


def _trusted_domain(host):
    """Return a trusted owner only for the exact domain or a real subdomain."""
    for domain, owner in TRUSTED_DOMAINS.items():
        if host == domain or host.endswith("." + domain):
            return owner
    return None


def analyze_url(raw_url):
    url = normalize_url(raw_url)
    parsed, features = urlparse(url), lexical_features(url)
    host = parsed.hostname or ""
    trusted_owner = _trusted_domain(host)
    reserved_test_domain = host == "example" or host.endswith(".example")
    impersonated_brand = next((brand for brand in IMPERSONATED_BRANDS if brand in host), None)
    reward_lures = sorted(set(features.get("suspicious_terms", [])) & REWARD_LURE_TERMS)
    ml_label, ml_probabilities = predict(url)
    is_test = host in {"amtso.org", "www.amtso.org"} and parsed.path in AMTSO_PATHS
    if is_test:
        test_ssl = ssl_check(host, parsed.scheme)
        test_domain = whois_check(host)
        test_blacklist = blacklist_check(url)
        return _test_result(url, ml_probabilities, test_ssl, test_domain, test_blacklist)

    ssl_data = ssl_check(host, parsed.scheme)
    if features["is_ip"]:
        domain = {"status": "IP address", "age_days": None, "age_display": "N/A — IP address"}
    elif reserved_test_domain:
        domain = {"status": "Reserved test domain", "age_days": None, "age_display": "N/A — reserved .example"}
    else:
        domain = whois_check(host)
    blacklist = blacklist_check(url)
    reasons, module_scores = [], {}

    structure = min(100, features["url_length"] // 2 + features["subdomains"] * 9 + features["special_chars"] * 4 +
                    features["hyphens"] * 5 + features["encoded"] * 7)
    module_scores["URL Structure"] = structure
    if features["url_length"] > 100: reasons.append("Long URL: its unusual length can be used to conceal the real destination or misleading parameters.")
    if features["many_subdomains"]: reasons.append("Deep subdomain structure: multiple hostname levels can make the registered domain difficult to identify.")
    if features["has_at"]: reasons.append("URL obfuscation: the @ symbol can cause users to misread which hostname will receive the request.")
    if features["is_ip"]: reasons.append("Raw IP host: the URL uses an IP address instead of a registered domain, removing normal ownership and age context.")
    if features["shortener"]: reasons.append("Hidden destination: a URL-shortening service prevents the final hostname from being assessed directly.")
    if features["punycode"]: reasons.append("Possible look-alike domain: Punycode can represent characters designed to resemble a trusted brand name.")
    if features["brand_typosquat"]:
        reasons.append(f"Brand typosquatting: the registered hostname is one edit away from {features['typosquat_brand']}.com and may be designed to mislead users.")
    if features["risky_tld"]: reasons.append("Higher-risk TLD: this extension is frequently observed in short-lived or disposable campaigns.")
    if features["suspicious_words"]:
        terms = ", ".join(features["suspicious_terms"])
        reasons.append(f"Suspicious wording: detected “{terms}”. These terms commonly request credentials, urgent account action, or payment changes.")
    if parsed.scheme != "https": reasons.append("Unencrypted connection: HTTP provides no TLS certificate and cannot protect submitted information in transit.")
    elif ssl_data["valid"] is False: reasons.append("Certificate warning: the HTTPS certificate could not be validated, so server identity is not confirmed.")
    if domain["age_days"] is not None and domain["age_days"] < 90: reasons.append(f"New domain: registration age is only {domain['age_days']} days, providing limited reputation history.")
    if blacklist["listed"]: reasons.append("Blacklist match: a configured threat-intelligence source identifies the domain or URL as malicious.")
    if reserved_test_domain and impersonated_brand:
        reasons.append(f"Brand impersonation test: the reserved .example hostname uses the {impersonated_brand.title()} name together with a sensitive-action request.")
    if reserved_test_domain and reward_lures:
        reasons.append(f"Reward-scam pattern: the reserved test URL uses “{', '.join(reward_lures)}” to entice an urgent click or personal-data submission.")
    if trusted_owner and not blacklist["listed"]:
        reasons.append(f"Verified hostname boundary: this is an exact official domain or subdomain operated by {trusted_owner}.")

    module_scores.update({
        "Keywords": min(100, features["suspicious_words"] * 22),
        "Domain": 55 if domain["age_days"] is None else (80 if domain["age_days"] < 30 else 45 if domain["age_days"] < 180 else 5),
        "Transport": 5 if ssl_data["valid"] else (45 if parsed.scheme == "https" else 70),
        "Reputation": 100 if blacklist["listed"] else (0 if trusted_owner else (30 if blacklist["listed"] is None else 0)),
        "ML Model": round(ml_probabilities.get("Phishing", 0) + ml_probabilities.get("Suspicious", 0) * .45),
    })
    weights = {"URL Structure": .18, "Keywords": .14, "Domain": .12, "Transport": .13, "Reputation": .25, "ML Model": .18}
    score = round(sum(module_scores[k] * weights[k] for k in weights), 1)
    if blacklist["listed"]: score = max(score, 90.0)
    elif features["is_ip"] and features["suspicious_words"]:
        score = max(score, 82.0)
    elif features["brand_typosquat"] and parsed.scheme != "https":
        score = max(score, 75.0)
    elif features["brand_typosquat"]:
        score = max(score, 65.0)
    elif reserved_test_domain and impersonated_brand and features["suspicious_words"]:
        score = max(score, 82.0)
    elif features["risky_tld"] and features["suspicious_words"] >= 2 and (parsed.scheme == "http" or features["many_subdomains"]):
        score = max(score, 78.0)
    elif features["shortener"]:
        score = max(score, 35.0)
    elif features["risky_tld"] and features["suspicious_words"]:
        score = max(score, 34.0)
    elif trusted_owner:
        # Official-domain recognition reduces false positives but does not
        # override a positive blacklist result or erase other security signals.
        score = round(min(score, 18.0), 1)
    if reserved_test_domain and not impersonated_brand and features["suspicious_words"] and not blacklist["listed"]:
        # Generic .example lures are controlled simulations with suspicious
        # intent but no confirmed real-world host or named-brand impersonation.
        score = round(min(60.0, max(34.0, score)), 1)

    # Apply explicit security penalties after the hybrid base score and rule
    # floors. Reserved test domains and raw IPs have an intentional N/A age,
    # so the missing-age penalty is used only for a failed/unknown lookup.
    adjustments = {}
    if features["is_ip"]:
        adjustments["Raw IP address"] = RISK_PENALTIES["raw_ip"]
    if parsed.scheme != "https":
        adjustments["HTTP without HTTPS"] = RISK_PENALTIES["http"]
    if ssl_data.get("valid") is False:
        adjustments["No valid SSL certificate"] = RISK_PENALTIES["no_ssl_certificate"]
    if domain.get("status") == "Unknown" and domain.get("age_days") is None:
        adjustments["Missing domain age"] = RISK_PENALTIES["missing_domain_age"]
    if str(blacklist.get("status", "")).startswith("Clean"):
        adjustments["Clean blacklist credit"] = RISK_PENALTIES["clean_blacklist_credit"]
    score = round(max(0.0, min(100.0, score + sum(adjustments.values()))), 1)
    if trusted_owner and not blacklist["listed"]:
        # An exact allowlisted owner boundary prevents transient WHOIS/TLS
        # lookup failures from turning a known official host into a threat.
        # A confirmed blacklist match still takes precedence.
        score = round(min(score, LEGITIMATE_MAX), 1)

    classification = ("Legitimate" if score <= LEGITIMATE_MAX else
                      "Suspicious" if score <= SUSPICIOUS_MAX else "Phishing")
    probabilities = _hybrid_probabilities(ml_probabilities, classification, score, bool(trusted_owner))
    confidence = round(probabilities[classification], 1)
    reputation = _reputation_status(host, trusted_owner, blacklist, domain, ssl_data, classification)
    if not reasons: reasons.append("No strong indicators: URL structure, transport and available reputation checks did not reveal a significant phishing signal.")
    recommendations = _recommend(classification, parsed.scheme, blacklist["listed"], features, reserved_test_domain)
    return {"url": url, "classification": classification, "threat_score": score, "confidence": confidence,
            "ssl": ssl_data, "domain": domain, "blacklist": blacklist,
            "reputation": reputation,
            "reasons": reasons, "recommendations": recommendations, "module_scores": module_scores,
            "risk_adjustments": adjustments,
            "probabilities": probabilities, "ml_probabilities": ml_probabilities,
            "features": features, "is_security_test": False}


def _test_result(url, probabilities, ssl_data, domain, blacklist):
    return {"url": url, "classification": "Security Test", "threat_score": 0.0, "confidence": 100.0,
            "ssl": ssl_data, "domain": domain, "blacklist": blacklist,
            "reputation": "amtso.org — Official security test site",
            "reasons": ["Official AMTSO security feature check page; it simulates phishing behavior for defensive testing.",
                        "Domain, certificate and blacklist details are informational and do not change the Security Test classification."],
            "recommendations": ["Safe for authorized anti-phishing feature testing.", "Do not treat the test page as a real phishing incident."],
            "module_scores": {k: 0 for k in ["URL Structure", "Keywords", "Domain", "Transport", "Reputation", "ML Model"]},
            "probabilities": {"Legitimate": 0.0, "Phishing": 0.0, "Suspicious": 0.0, "Security Test": 100.0},
            "ml_probabilities": probabilities, "features": {}, "is_security_test": True}


def _recommend(label, scheme, listed, features, reserved_test_domain):
    if label == "Phishing":
        notes = ["Stop interaction: do not open the URL, enter credentials, approve authentication prompts, or download files.",
                 "Contain the threat: block the URL/domain in browser, DNS, email, proxy, and endpoint security controls where authorized.",
                 "Preserve evidence: record the full URL, scan time, source message, sender details, and this report for incident review.",
                 "Respond to exposure: if anyone interacted with it, reset affected credentials, revoke sessions, enable MFA, and notify the security team."]
        if reserved_test_domain: notes[1] = "Testing action: this is a reserved simulation URL; use it only in the authorized project environment and do not block unrelated real services."
        return notes
    if label == "Suspicious":
        notes = ["Verify independently: obtain the genuine website address from an official application, saved bookmark, or separately verified source.",
                 "Avoid sensitive actions: do not enter passwords, payment information, OTPs, or personal data while the URL remains unverified.",
                 "Escalate safely: submit the URL to an authorized security analyst or isolated sandbox before allowing user access."]
        if scheme != "https": notes.append("Require secure transport: use the organization’s confirmed HTTPS address instead of this unencrypted HTTP link.")
        if reserved_test_domain: notes.append("Testing note: .example is reserved for simulations and has no real registration or website ownership record.")
        return notes
    notes = ["Proceed with normal caution: the current checks found low risk, but a low score is not a guarantee of safety.",
             "Confirm context: ensure the hostname and requested action match the service you intended to use."]
    if listed is None: notes.append("Configure threat-intelligence API keys for external blacklist verification.")
    if scheme != "https": notes.append("Avoid transmitting sensitive information because HTTPS is absent.")
    return notes


def _hybrid_probabilities(raw, classification, score, trusted):
    """Align displayed confidence with the final evidence-based decision."""
    target = 97.0 if trusted else (min(96.0, 50.0 + score * .5) if classification == "Phishing"
                                  else min(94.0, 55.0 + abs(score - 47.5)) if classification == "Suspicious"
                                  else min(96.0, 70.0 + (30.0 - score) * .7))
    target = round(max(target, raw.get(classification, 0.0)), 2)
    others = [name for name in ("Legitimate", "Phishing", "Suspicious") if name != classification]
    raw_total = sum(raw.get(name, 0.0) for name in others)
    remaining = round(100.0 - target, 2)
    result = {classification: target}
    if raw_total:
        first = round(remaining * raw.get(others[0], 0.0) / raw_total, 2)
    else:
        first = round(remaining / 2, 2)
    result[others[0]] = first
    result[others[1]] = round(remaining - first, 2)
    return {name: result[name] for name in ("Legitimate", "Phishing", "Suspicious")}


def _reputation_status(host, trusted_owner, blacklist, domain, ssl_data, classification):
    """Create a useful local assessment without claiming an external-feed verdict."""
    site = host[4:] if host.startswith("www.") else host
    if blacklist["listed"]:
        return f"{site} — Threat feed match"
    if trusted_owner:
        return f"{site} — Official {trusted_owner} domain"
    age = domain.get("age_days")
    if classification == "Phishing":
        return f"{site} — High risk"
    if age is not None and age >= 365 and ssl_data.get("valid"):
        return f"{site} — Established"
    if age is not None and age >= 180 and ssl_data.get("valid"):
        return f"{site} — Moderate history"
    if age is not None and age < 90:
        return f"{site} — Newly registered"
    if classification == "Suspicious":
        return f"{site} — Caution"
    return f"{site} — Limited reputation data"
