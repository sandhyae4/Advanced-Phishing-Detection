import ipaddress
import re
from urllib.parse import urlparse
from services.features import normalize_url, lexical_features, SUSPICIOUS_WORDS
from services.intelligence import ssl_check, whois_check, blacklist_check, safe_live_probe
from services.model_service import predict
from services.institutional import verify_institutional_domain

AMTSO_PATHS = {"/check-desktop-phishing-page/", "/check-mobile-phishing-page/"}
TRUSTED_DOMAINS = {
    "chatgpt.com": "OpenAI ChatGPT",
    "openai.com": "OpenAI",
    "google.com": "Google",
    "google.co.in": "Google India",
    "google.co.uk": "Google UK",
    "google.com.br": "Google Brazil",
    "microsoft.com": "Microsoft",
    "microsoftonline.com": "Microsoft",
    "github.com": "GitHub",
    "wikipedia.org": "Wikipedia",
    "facebook.com": "Meta Facebook",
    "instagram.com": "Meta Instagram",
    "whatsapp.com": "Meta WhatsApp",
    "paypal.com": "PayPal",
    "apple.com": "Apple",
    "icloud.com": "Apple iCloud",
    "amazon.com": "Amazon",
    "amazon.in": "Amazon India",
    "netflix.com": "Netflix",
    "dropbox.com": "Dropbox",
    "linkedin.com": "LinkedIn",
    "adobe.com": "Adobe",
    "mits.ac.in": "Madanapalle Institute of Technology & Science (MITS)",
}
KNOWN_BRANDS = {
    "metamask": ["metamask", "meta-mask"],
    "binance": ["binance", "binan"],
    "coinbase": ["coinbase", "coin-base"],
    "amazon": ["amazon", "arnazon", "amaz0n", "amazn"],
    "paypal": ["paypal", "paypa1", "paypl", "pay-pal"],
    "google": ["google", "gooogle", "gogle", "g00gle"],
    "microsoft": ["microsoft", "micros0ft", "mircosoft", "msft", "office365"],
    "apple": ["apple", "appple", "appl", "appleid", "icloud"],
    "facebook": ["facebook", "faceboook", "facbook", "faceb00k"],
    "netflix": ["netflix", "netflx", "netfliix"],
    "instagram": ["instagram", "instagrarn", "instg"],
    "whatsapp": ["whatsapp", "whatsap", "watsapp"],
    "chase": ["chase", "chasebank"],
    "wellsfargo": ["wellsfargo", "wells-fargo"],
    "bankofamerica": ["bankofamerica", "bofa"],
    "dhl": ["dhl", "dhl-express"],
    "fedex": ["fedex"],
    "usps": ["usps"],
}
IMPERSONATED_BRANDS = set(KNOWN_BRANDS.keys()) | {"bank"}
REWARD_LURE_TERMS = {"claim", "prize", "winner", "reward", "giveaway", "gift", "free"}

AUTH_KEYWORDS = {"login", "signin", "auth", "password", "authenticate", "webscr", "account", "credentials", "session", "sso"}
URGENCY_KEYWORDS = {"suspended", "security", "restore", "alert", "verify", "verification", "locked", "disabled", "warning", "immediately", "blocked", "breach", "unauthorized", "unusual", "urgent", "kyc", "activate", "deactivate", "compromised"}
FINANCE_KEYWORDS = {"order", "billing", "payment", "invoice", "refund", "fee", "overdue", "tax", "banking", "checkout", "creditcard", "pay", "bank"}
CRYPTO_KEYWORDS = {"wallet", "crypto", "seed", "mnemonic", "airdrop", "profit", "exchange", "metamask", "binance", "coinbase", "trustwallet"}
DELIVERY_KEYWORDS = {"parcel", "delivery", "shipment", "tracking", "usps", "dhl", "fedex", "ups"}
REWARD_KEYWORDS = {"prize", "winner", "reward", "giveaway", "gift", "free", "lottery", "bonus", "claim"}


def _detect_brand(host, path=""):
    host_lower = host.lower()
    path_lower = path.lower()
    full = f"{host_lower}/{path_lower}"
    tokens = [t for t in re.split(r"[\.-]", host_lower) if t]
    for brand, patterns in KNOWN_BRANDS.items():
        for pat in patterns:
            if pat in tokens or pat == host_lower or f"{pat}-" in host_lower or f"-{pat}" in host_lower:
                return brand, pat
            if pat in host_lower and len(pat) >= 5:
                return brand, pat
            if f"/{pat}" in path_lower or f"-{pat}" in full or f"{pat}-" in full:
                return brand, pat
    return None, None


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


def generate_findings_and_recommendations(url, parsed, host, features, trusted_owner,
                                          detected_brand, brand_token, impersonated_brand,
                                          ssl_data, domain, blacklist, reserved_test_domain,
                                          is_test=False, live_probe=None, institutional=None):
    findings = []
    recommendations = []

    def add_pair(f_id, f_title, f_sev, f_ev, f_exp, f_comp,
                 r_id, r_title, r_risk, r_action):
        findings.append({
            "id": f_id,
            "title": f_title,
            "severity": f_sev,
            "evidence": f_ev,
            "explanation": f_exp,
            "component": f_comp,
            "recommendation_id": r_id,
        })
        recommendations.append({
            "id": r_id,
            "finding_id": f_id,
            "title": r_title,
            "risk": r_risk,
            "action": r_action,
        })

    # 1. AMTSO Security Test check
    if is_test:
        add_pair(
            "FND-TEST-AMTSO",
            "AMTSO Defensive Security Verification Page",
            "Informational",
            f"Path '{parsed.path}' matches the Anti-Malware Testing Standards Organization (AMTSO) phishing test benchmark.",
            "This URL is an industry-standard simulation page designed specifically to test if web security solutions correctly trigger anti-phishing detections.",
            f"Path: {parsed.path}",
            "REC-TEST-AMTSO",
            "Authorized Security Testing Environment",
            "This is a benign simulation test bed and does not represent an unauthorized breach or malicious attack vector.",
            "Safe for authorized anti-phishing feature validation. Do not treat the test page as a real phishing incident."
        )
        return findings, recommendations

    # 2. Protocol Check
    if parsed.scheme == "http":
        add_pair(
            "FND-PROTO-HTTP",
            "Insecure HTTP Protocol Detected",
            "High",
            f"The submitted URL uses unencrypted {parsed.scheme}:// transport.",
            "HTTP transmits web requests and data in plaintext without cryptographic integrity, exposing interactions to interception or tampering.",
            f"Protocol: {parsed.scheme}://",
            "REC-PROTO-HTTP",
            "Enforce Encrypted Transport (HTTPS)",
            "Unencrypted connections allow attackers on the local network or internet transit path to intercept passwords, personal data, or session cookies.",
            "Avoid submitting passwords, financial details, or sensitive personal data over unencrypted HTTP. Navigate to the verified HTTPS version of the website."
        )
    elif parsed.scheme == "https":
        add_pair(
            "FND-PROTO-HTTPS",
            "HTTPS Transport Encryption Active",
            "Informational",
            "The submitted URL uses https:// encrypted transport.",
            "HTTPS secures the communication channel between client and server using TLS encryption, safeguarding data against passive network eavesdropping.",
            "Protocol: https://",
            "REC-PROTO-HTTPS",
            "Verify Destination Identity Beyond HTTPS",
            "HTTPS secures transport in transit, but does not verify website authenticity or benign intent; fraudulent sites routinely acquire free TLS certificates.",
            "Confirm domain spelling and verify brand identity before submitting sensitive credentials, rather than assuming HTTPS alone guarantees safety."
        )

    # 3. SSL/TLS Certificate State
    if parsed.scheme == "https":
        if ssl_data.get("valid") is True:
            days = ssl_data.get("days_remaining", "active")
            add_pair(
                "FND-SSL-VALID",
                "Valid SSL/TLS Certificate",
                "Informational",
                f"Active TLS certificate validated for host '{host}' ({days} days remaining).",
                "A cryptographically valid digital certificate issued by a recognized certificate authority is active and protecting connections to this hostname.",
                f"Host: {host} (Port 443)",
                "REC-SSL-VALID",
                "Validate Certificate Subject Match",
                "Valid certificates establish encryption for the named subject, but threat actors can register legitimate certificates for lookalike domains.",
                "Ensure the certificate subject name matches the legitimate organization you intended to visit before providing authentication credentials."
            )
        elif ssl_data.get("valid") is False:
            add_pair(
                "FND-SSL-INVALID",
                "Untrusted or Invalid SSL/TLS Certificate",
                "High",
                f"Certificate validation returned '{ssl_data.get('status', 'Validation failed')}' for host '{host}'.",
                "The server certificate could not be validated against trusted root authorities, is expired, self-signed, or the TLS handshake failed.",
                f"Host: {host} (TLS Handshake)",
                "REC-SSL-INVALID",
                "Do Not Bypass TLS Certificate Warnings",
                "Invalid or untrusted certificates indicate potential person-in-the-middle (PITM) interception, expired credentials, or an unmanaged server.",
                "Do not accept security exceptions or proceed past browser certificate warnings; verify server accessibility through official support."
            )
        elif ssl_data.get("status") == "Unavailable":
            add_pair(
                "FND-SSL-UNAVAILABLE",
                "SSL Verification Skipped for Non-Public Address",
                "Medium",
                f"Host '{host}' is a non-public or private network address; public CA verification is unavailable.",
                "The destination host resolves to a non-public or unroutable IP range (e.g. RFC 1918), preventing public trust hierarchy checks.",
                f"Host: {host}",
                "REC-SSL-UNAVAILABLE",
                "Inspect Internal Network Host Context",
                "Private or internal network services may use self-signed certificates or pose internal pivoting risks.",
                "Confirm this address corresponds to an authorized internal network device (such as a local router admin console) before logging in."
            )

    # 4. Authority & Structure: @ Symbol Check
    if features.get("has_at"):
        userinfo = parsed.username or (parsed.netloc.split("@", 1)[0] if "@" in parsed.netloc else "prefix")
        add_pair(
            "FND-STRUCT-AT",
            "Potentially Misleading URL Structure (@ Symbol)",
            "High",
            f"The URL contains an '@' character. The userinfo prefix is '{userinfo}', but the actual destination hostname is '{host}'.",
            "Browsers and network clients interpret text before '@' as userinfo, connecting strictly to the destination host following '@'. Attackers exploit this to display trusted brands before the '@' to mislead users.",
            f"Authority: {parsed.netloc}",
            "REC-STRUCT-AT",
            "Inspect Destination Host Following '@'",
            "Users can be deceived by trusted brand names appearing before '@' and mistakenly enter credentials on the unauthorized destination host.",
            "Inspect the parsed hostname carefully. Do not trust the brand-like text appearing before the @ character; verify the actual destination host."
        )

    # 5. IP Hostname Check
    if features.get("is_ip"):
        add_pair(
            "FND-DOM-IP",
            "IP Address Used as Hostname",
            "High",
            f"The URL destination is raw IP address '{host}' instead of a registered domain name.",
            "Legitimate consumer organizations rarely direct users to raw IP addresses. Phishing attacks deploy raw IPs to bypass domain reputation systems and WHOIS attribution.",
            f"Host: {host}",
            "REC-DOM-IP",
            "Verify Destination Host Identity",
            "Interacting with raw IP destinations exposes users to unverified, unauthenticated servers without organizational accountability.",
            "Verify the identity and legitimacy of the destination before interacting with it, especially if it requests credentials or administrative logins."
        )
        is_rfc1918 = False
        try:
            is_rfc1918 = ipaddress.ip_address(host).is_private
        except ValueError:
            pass
        if is_rfc1918:
            add_pair(
                "FND-DOM-RFC1918",
                "RFC 1918 Private IPv4 Address Allocation",
                "Medium",
                f"IP address '{host}' belongs to RFC 1918 private networking (non-routable on the public internet).",
                "RFC 1918 addresses are allocated exclusively for internal private networks and router gateways. Public CAs cannot issue publicly-trusted certificates for internal IP addresses.",
                f"Host: {host}",
                "REC-DOM-RFC1918",
                "Verify Internal Network Equipment",
                "Private IP addresses connect directly to local area network equipment (such as home or office router admin consoles).",
                "Access this address only if managing known local hardware on your private LAN; never enter domain credentials."
            )

    # 6. Brand Typosquatting & Impersonation
    if detected_brand and not trusted_owner:
        brand_name = detected_brand.title()
        if brand_token != detected_brand:
            add_pair(
                "FND-DOM-TYPO",
                "Brand Typosquatting & Visual Spoofing",
                "High",
                f"Domain incorporates '{brand_token}' mimicking '{detected_brand}'. Genuine {brand_name} services operate on official '{detected_brand}.com' domains.",
                "The domain mimics a well-known brand by adding, dropping, or substituting characters to visually mislead users.",
                f"Host: {host}",
                "REC-DOM-TYPO",
                "Navigate Directly to Verified Brand Portal",
                "Lookalike domains are engineered to harvest user credentials and payment information under the guise of the impersonated brand.",
                f"Navigate directly to {brand_name}'s verified official website (https://www.{detected_brand}.com) instead of following the submitted link."
            )
        else:
            add_pair(
                "FND-DOM-IMPERSONATION",
                "Targeted Brand Impersonation",
                "High",
                f"Unauthorized appearance of protected brand name '{brand_name}' within unverified host '{host}'.",
                "The domain or path incorporates the brand name without originating from the verified authoritative owner infrastructure.",
                f"Host: {host}",
                "REC-DOM-IMPERSONATION",
                "Access Organization via Bookmarked or Official Channels",
                "Brand spoofing is the primary tactic used by phishing campaigns to induce false trust and harvest sensitive data.",
                f"Do not interact with this page. Navigate to the verified official {brand_name} website or official mobile application directly."
            )
    elif features.get("brand_typosquat"):
        target_b = features["typosquat_brand"].title()
        add_pair(
            "FND-DOM-TYPO",
            "Brand Typosquatting Detected",
            "High",
            f"Domain '{host}' is one edit away from protected brand '{features['typosquat_brand']}.com'.",
            "The registered hostname is one edit away from a protected brand and is designed to visually mislead users.",
            f"Host: {host}",
            "REC-DOM-TYPO",
            "Navigate Directly to Verified Brand Portal",
            "Typosquatting sites are commonly established to capture mistyped traffic and harvest user account credentials.",
            f"Close this page and type the verified address (https://www.{features['typosquat_brand']}.com) directly into your browser address bar."
        )

    # 7. Institutional Domain Governance & Verification (MITS Focus)
    if institutional and institutional.get("is_institutional"):
        cat = institutional.get("category")
        if cat in {"Official", "Officially Verified Institutional Domain"}:
            add_pair(
                "FND-INST-VERIFIED",
                "Officially Verified Institutional Domain (MITS)",
                "Informational",
                institutional.get("evidence", ""),
                "The destination hostname belongs to the authoritative, verified academic root domain of Madanapalle Institute of Technology & Science (MITS), registered via ERNET India.",
                f"Apex Domain: {host}",
                "REC-INST-VERIFIED",
                "Confirm Requested Institutional Workflow",
                "Even on verified institutional domains, verify that requested actions match official academic, examination, or administrative workflows.",
                "Verify that the web page is serving expected MITS academic content. Confirm TLS certificate matches the institutional boundary before entering campus credentials."
            )
        elif cat in {"Subdomain", "Verified Institutional Subdomain"}:
            svc_name = institutional.get("service_name") or institutional.get("service") or "MITS Subdomain"
            add_pair(
                "FND-INST-SUBDOMAIN",
                f"Verified Institutional Subdomain ({svc_name})",
                "Informational",
                institutional.get("evidence", ""),
                f"The URL targets an authenticated institutional service partition operating within MITS's authoritative 'mits.ac.in' domain boundary.",
                f"Service Host: {host}",
                "REC-INST-SUBDOMAIN",
                f"Validate {svc_name} Institutional Context",
                "Official MITS subdomains handle dedicated services (such as Moodle LMS or Examination Management) requiring distinct campus portal credentials.",
                "Ensure you intended to access this specific MITS institutional service. Confirm the browser address bar displays the official '.mits.ac.in' domain."
            )
        elif cat in {"Phishing", "Known Malicious or Impersonated Domain"}:
            add_pair(
                "FND-INST-IMPERSONATION",
                "Deceptive MITS Institutional Impersonation",
                "Critical",
                institutional.get("evidence", ""),
                "The destination fraudulently uses Madanapalle Institute of Technology & Science (MITS) naming conventions, services (e.g. Moodle), or lookalike tokens to target students and faculty for credential theft.",
                f"Deceptive Host: {host}",
                "REC-INST-IMPERSONATION",
                "Do Not Enter MITS Campus Credentials",
                "Threat actors deploy lookalike academic portals to harvest student/faculty portal passwords and academic records.",
                "Immediately close this page. Do not submit your MITS roll number, faculty ID, or password. Access legitimate institutional portals strictly through https://mits.ac.in/."
            )
        elif cat in {"Lookalike", "Potential MITS Lookalike Domain"}:
            add_pair(
                "FND-INST-LOOKALIKE",
                "Potential MITS Lookalike Domain",
                "High",
                institutional.get("evidence", ""),
                "The domain incorporates 'mits' naming conventions or brand patterns but resolves to an unauthorized, third-party infrastructure outside the official 'mits.ac.in' ERNET registry.",
                f"Unverified Host: {host}",
                "REC-INST-LOOKALIKE",
                "Verify Institutional Affiliation via Official Channels",
                "Lookalike institutional domains frequently serve as staging infrastructure for academic fee scams or credential harvesting.",
                "Do not submit personal or financial details. Confirm whether this website is an officially sanctioned external partner by contacting MITS administration."
            )
        elif cat in {"Distinct Entity", "Unverified MITS-Related Domain"}:
            add_pair(
                "FND-INST-DISTINCT",
                "Distinct Educational Entity (Independent MITS Acronym)",
                "Informational",
                institutional.get("evidence", ""),
                f"This domain belongs to an independent educational institution ({institutional.get('institution_name')}) sharing the 'MITS' acronym, distinct from Madanapalle Institute of Technology & Science.",
                f"Registered Domain: {institutional.get('registered_domain', host)}",
                "REC-INST-DISTINCT",
                "Verify Intended Institution Context",
                "Ensure you intend to access this specific independent institution and not Madanapalle Institute of Technology & Science.",
                "Confirm that the target institution matches your academic requirements. For Madanapalle Institute, visit https://mits.ac.in/."
            )

    # 8. Official Domain Boundary vs Unverified Third-Party Domain
    if trusted_owner and not blacklist.get("listed"):
        if not (institutional and institutional.get("is_institutional") and institutional.get("category") in {"Official", "Subdomain", "Officially Verified Institutional Domain", "Verified Institutional Subdomain"}):
            add_pair(
                "FND-DOM-OFFICIAL",
                "Verified Official Domain Boundary",
                "Informational",
                f"Exact official domain or authorized subdomain operated by {trusted_owner} ('{host}').",
                "The hostname belongs to the verified infrastructure boundary of a recognized, authoritative organization.",
                f"Host: {host}",
                "REC-DOM-OFFICIAL",
                "Confirm Requested Service Context",
                "Even on legitimate official domains, ensure you are interacting with the intended application feature and not an open redirect or third-party user content.",
                f"Confirm that the requested workflow aligns with your intended use of {trusted_owner} services."
            )
    elif not trusted_owner and not features.get("is_ip") and not reserved_test_domain and not (detected_brand or impersonated_brand or features.get("brand_typosquat")) and not (institutional and institutional.get("is_institutional")):
        is_risky_media_or_file = bool(features.get("has_media_piracy") or features.get("has_executable_ext") or features.get("malware_terms"))
        add_pair(
            "FND-DOM-THIRD-PARTY",
            f"Unverified Third-Party Domain ('{host}')",
            "Medium" if is_risky_media_or_file else "Informational",
            f"Hostname '{host}' is an independent third-party web domain operating outside recognized enterprise trust hierarchies.",
            f"The domain '{host}' is managed by an independent entity without centralized organizational identity verification.",
            f"Domain: {host}",
            "REC-DOM-THIRD-PARTY",
            "Exercise Discretion on Third-Party Web Properties",
            "Third-party and community web services carry independent operational risks, unmonitored links, or potential adware payloads.",
            f"Avoid reusing primary passwords or executing unverified file downloads from '{host}'. Confirm site legitimacy before submitting data."
        )

    # 8. Subdomain Analysis
    if not features.get("is_ip") and "." in host:
        if features.get("many_subdomains"):
            add_pair(
                "FND-DOM-DEEP-SUBDOMAIN",
                "Excessive Subdomain Nesting",
                "Medium",
                f"Hostname '{host}' contains {features.get('dots', 0)} dot separators ({features.get('subdomains', 0)} subdomain levels).",
                "Multiple subdomain levels can be used by attackers to obscure the true registrable root domain on mobile screens and browser address bars.",
                f"Host: {host}",
                "REC-DOM-DEEP-SUBDOMAIN",
                "Verify Registrable Base Domain",
                "Attackers create deep subdomains (e.g. login.paypal.com.attacker.com) so users only see the brand name.",
                "Examine the rightmost domain labels preceding the TLD to verify the actual entity operating the base domain."
            )
        elif features.get("subdomains", 0) >= 1:
            sub_label = host.split(".")[0]
            if trusted_owner and host != trusted_owner:
                add_pair(
                    "FND-DOM-SUBDOMAIN",
                    f"Recognized Service Subdomain ({sub_label.title()})",
                    "Informational",
                    f"Hostname '{host}' is an operational service subdomain within {trusted_owner}'s official infrastructure.",
                    f"The subdomain '{sub_label}' routes to {trusted_owner}'s specialized service partition.",
                    f"Subdomain: {sub_label}.{host.split('.', 1)[1]}",
                    "REC-DOM-SUBDOMAIN",
                    f"Verify {sub_label.title()} Service Context",
                    f"Official {trusted_owner} subdomains handle specialized applications requiring distinct credentials and privacy scopes.",
                    f"Ensure this {sub_label.title()} portal is the specific {trusted_owner} application you intended to access."
                )
            elif not trusted_owner:
                add_pair(
                    "FND-DOM-SUBDOMAIN",
                    "Active Subdomain Prefix Detected",
                    "Informational",
                    f"Hostname '{host}' routes through subdomain '{sub_label}'.",
                    "The URL targets a partitioned subdomain host rather than the apex domain.",
                    f"Subdomain: {sub_label}",
                    "REC-DOM-SUBDOMAIN",
                    "Confirm Subdomain Authority",
                    "Subdomains can point to third-party services or sub-allocated hosting that differs from the main domain.",
                    "Verify that the subdomain prefix corresponds to the authentic service provided by the domain owner."
                )

    # 9. Shortened URL Check
    if features.get("shortener"):
        add_pair(
            "FND-STRUCT-SHORTENER",
            "URL Shortening Service Detected",
            "Medium",
            f"Host '{host}' is a recognized URL shortening service.",
            "URL shortening services conceal the destination host, preventing users from inspecting the actual domain before clicking.",
            f"Host: {host}",
            "REC-STRUCT-SHORTENER",
            "Expand Shortened URL Destination",
            "Shortened links are frequently used in phishing campaigns to bypass static domain reputation filters.",
            "Verify the final destination URL using a safe link expansion tool or curl HEAD request before opening it in a browser."
        )

    # 10. Punycode Check
    if features.get("punycode"):
        add_pair(
            "FND-DOM-PUNYCODE",
            "Internationalized Domain Name (Punycode) Detected",
            "High",
            f"Hostname '{host}' contains Punycode prefix 'xn--'.",
            "Punycode represents non-ASCII Unicode characters which can be exploited for homograph attacks that visually mimic authentic brands.",
            f"Host: {host}",
            "REC-DOM-PUNYCODE",
            "Inspect Decoded Unicode Homoglyphs",
            "Homoglyph attacks visually deceive users by replacing Latin characters with identical-looking international characters.",
            "Inspect the decoded Punycode representation to ensure characters are not visual duplicates designed to impersonate an authentic brand."
        )

    # 11. Risky TLD Check
    if features.get("risky_tld"):
        tld = host.rsplit(".", 1)[-1]
        add_pair(
            "FND-DOM-RISKY-TLD",
            f"Higher-Risk Top-Level Domain (.{tld})",
            "Medium",
            f"Hostname uses the .{tld} top-level domain.",
            f"The .{tld} extension is frequently observed in short-lived or disposable phishing campaigns due to low registration hurdles.",
            f"TLD: .{tld}",
            "REC-DOM-RISKY-TLD",
            f"Exercise Heightened Vigilance on .{tld} Domain",
            "Disposable or cheap TLDs are heavily favored in automated phishing campaigns and malware distribution.",
            "Verify the legitimacy of the organization operating on this TLD through independent external channels."
        )

    # 12. Reserved Test Domain Check
    rfc2606_tlds = {".test", ".example", ".invalid", ".localhost"}
    matched_rfc2606 = next((tld for tld in rfc2606_tlds if host.endswith(tld) or host == tld[1:]), None)
    if reserved_test_domain or matched_rfc2606:
        ns_label = matched_rfc2606 or ".example"
        add_pair(
            "FND-DOM-RESERVED",
            f"Reserved Documentation / Simulation Domain ({ns_label})",
            "Informational",
            f"Domain '{host}' belongs to RFC 2606 / RFC 6761 reserved namespaces ({ns_label} / example.com).",
            "Reserved domains are designated specifically for documentation, testing, and simulation; they have no real-world commercial ownership.",
            f"Domain: {host}",
            "REC-DOM-RESERVED",
            "Use Reserved Domains Solely for Simulation",
            "Reserved domains do not represent live production services or authentic corporate entities.",
            "Use this domain strictly within authorized security lab testing; do not expect active production credentials."
        )

    # 13. Domain Age Check
    if domain.get("age_days") is not None:
        created_info = f" (Created: {domain['creation_date']} via {domain.get('source', 'WHOIS/RDAP')})" if domain.get("creation_date") else ""
        if domain["age_days"] < 90:
            add_pair(
                "FND-DOM-NEW",
                "Newly Registered Domain",
                "Medium",
                f"Domain registration age is {domain['age_days']} days ({domain.get('age_display', '')}){created_info}.",
                "Phishing infrastructure is predominantly newly provisioned and discarded quickly to evade domain reputation blocklists.",
                f"Domain Age: {domain.get('age_display')}",
                "REC-DOM-NEW",
                "Treat Newly Created Domains with Caution",
                "Domains under 90 days old lack historical reputation and represent an elevated risk factor for brand impersonation.",
                "Avoid sharing credentials, making purchases, or downloading files from newly created domains until organizational reputation is established."
            )
        else:
            add_pair(
                "FND-DOM-ESTABLISHED",
                "Established Domain Registration History",
                "Informational",
                f"Domain registration history indicates established age of {domain.get('age_display')} ({domain['age_days']} days){created_info}.",
                "The domain has an established operational registration history, typical of authentic commercial organizations.",
                f"Domain Age: {domain.get('age_display')}",
                "REC-DOM-ESTABLISHED",
                "Maintain Standard Domain Hygiene",
                "While established age reduces likelihood of disposable burner domains, legitimate websites can still be compromised.",
                "Practice standard security hygiene and verify that specific requested actions match legitimate site functionality."
            )
    elif domain.get("status") == "Not Registered" and not reserved_test_domain and not features.get("is_ip"):
        add_pair(
            "FND-DOM-UNREGISTERED",
            "Unregistered / Non-Existent Domain",
            "High",
            f"Authoritative WHOIS and RDAP registry queries confirmed that domain '{domain.get('registered_domain', host)}' is not currently registered.",
            "Links pointing to unregistered domain names cannot host authentic services and frequently indicate typos, abandoned infrastructure, or speculative attack preparations.",
            f"Domain: {domain.get('registered_domain', host)}",
            "REC-DOM-UNREGISTERED",
            "Do Not Transmit Data to Unregistered Domains",
            "Unregistered domains cannot be legitimate organizational portals. Interacting with them risks navigating to parking sites with malicious ads or hijacked domains.",
            "Verify the exact spelling of the domain and do not attempt to enter login credentials or confidential access tokens."
        )
    elif domain.get("status") == "Not Verified" and not reserved_test_domain and not features.get("is_ip"):
        add_pair(
            "FND-DOM-UNVERIFIED-AGE",
            "Domain Registration Age Not Verified",
            "Low",
            f"Authoritative registry query for '{domain.get('registered_domain', host)}' did not return verified creation timestamps.",
            "The registration date could not be retrieved from public RDAP or WHOIS servers during this scan session.",
            f"Domain: {domain.get('registered_domain', host)}",
            "REC-DOM-UNVERIFIED-AGE",
            "Independently Validate Website Organization",
            "Absence of authoritative registration data prevents automated assessment of domain longevity.",
            "Verify the organization operating this service through external directory checks or independent contact information."
        )

    # 14. URL Length Check
    if features.get("url_length", 0) > 100:
        add_pair(
            "FND-STRUCT-LENGTH",
            "Excessive URL Length",
            "Low",
            f"URL contains {features['url_length']} characters (exceeds 100-character baseline threshold).",
            "Abnormally long URLs are often used to pad address bars, bury true destinations, or pass complex tracking payloads.",
            f"URL Length ({features['url_length']} chars)",
            "REC-STRUCT-LENGTH",
            "Inspect Extended URL Parameters",
            "Lengthy query parameters can carry encoded redirection destinations or obfuscated token data.",
            "Inspect query parameters for embedded open redirects (e.g. ?next= or ?url=) before proceeding."
        )

    # 15. URL Encoding Check
    if features.get("encoded", 0) >= 2:
        add_pair(
            "FND-STRUCT-ENCODED",
            "Percent-Encoded URL Characters Detected",
            "Low",
            f"URL contains {features['encoded']} percent-encoded hex sequences (e.g. %20, %2F).",
            "Percent-encoding can be legitimately used in query strings, but is also used in obfuscation to evade static keyword signature filters.",
            f"Path/Query Encoding ({features['encoded']} sequences)",
            "REC-STRUCT-ENCODED",
            "Review Decoded Path Parameters",
            "Obfuscated parameters may hide hostile destination scripts or evasive payloads.",
            "Ensure decoded parameter values represent expected application arguments rather than alternate URLs."
        )

    # 16. Attack Vector Keywords
    tokens_found = set(features.get("suspicious_terms", []))
    auth_hits = sorted(tokens_found & AUTH_KEYWORDS)
    if auth_hits:
        add_pair(
            "FND-LURE-AUTH",
            "Credential Harvesting Indicators Detected",
            "High",
            f"URL path/query contains authentication keyword(s): '{', '.join(auth_hits)}'.",
            "Authentication terminology in URL paths strongly correlates with login forms, credential harvesting gates, or session interception portals.",
            f"Path/Query: {parsed.path or '/'}",
            "REC-LURE-AUTH",
            "Protect Account Credentials & Enable MFA",
            "Entering passwords on unverified login pages results in immediate credential compromise and unauthorized account takeover.",
            "If credentials or passwords were entered, immediately reset your password on the genuine service and activate multi-factor authentication (MFA)."
        )

    urgency_hits = sorted(tokens_found & URGENCY_KEYWORDS)
    if urgency_hits:
        add_pair(
            "FND-LURE-URGENCY",
            "Urgent Account Panic Lure",
            "High",
            f"URL path/query contains urgency keyword(s): '{', '.join(urgency_hits)}'.",
            "Phishing campaigns fabricate emergencies (such as account suspension or security breach alerts) to bypass critical thinking and force immediate action.",
            f"Path/Query: {parsed.path or '/'}",
            "REC-LURE-URGENCY",
            "Do Not React to Fabricated Urgency",
            "Panic-inducing alerts pressure victims into bypassing safety protocols and supplying sensitive credentials.",
            "Verify account alerts by logging in through a known, trusted bookmark or official app rather than clicking links in urgency messages."
        )

    finance_hits = sorted(tokens_found & FINANCE_KEYWORDS)
    if finance_hits:
        add_pair(
            "FND-LURE-FINANCE",
            "Payment & Financial Exploitation Vector",
            "High",
            f"URL path/query contains transactional keyword(s): '{', '.join(finance_hits)}'.",
            "Payment and banking keywords are deployed in phishing to harvest credit card numbers, CVVs, and banking credentials under the guise of invoices or overdue fees.",
            f"Path/Query: {parsed.path or '/'}",
            "REC-LURE-FINANCE",
            "Protect Financial & Banking Information",
            "Submitting banking or card numbers exposes users to financial fraud, unauthorized recurring charges, and identity theft.",
            "Never enter payment details via unverified links. Contact your financial institution directly through phone numbers printed on your card."
        )

    crypto_hits = sorted(tokens_found & CRYPTO_KEYWORDS)
    if crypto_hits:
        add_pair(
            "FND-LURE-CRYPTO",
            "Cryptocurrency Asset Theft Vector",
            "High",
            f"URL path/query contains Web3/cryptocurrency keyword(s): '{', '.join(crypto_hits)}'.",
            "Cryptocurrency phishing campaigns specifically target browser wallet extensions, mnemonic recovery seed phrases, and private keys to drain digital assets irreversibly.",
            f"Path/Query: {parsed.path or '/'}",
            "REC-LURE-CRYPTO",
            "Never Disclose Wallet Seed Phrases or Keys",
            "Disclosing secret recovery phrases grants attackers full, irreversible control over digital cryptocurrency assets.",
            "Never input seed phrases or private keys into any website. Legitimate wallet providers will never ask for your recovery phrase online."
        )

    delivery_hits = sorted(tokens_found & DELIVERY_KEYWORDS)
    if delivery_hits:
        add_pair(
            "FND-LURE-DELIVERY",
            "Package Delivery Tracking Lure",
            "Medium",
            f"URL path/query contains courier keyword(s): '{', '.join(delivery_hits)}'.",
            "Courier-themed phishing schemes falsely notify users of failed deliveries or redelivery fees to harvest credit card numbers and personal addresses.",
            f"Path/Query: {parsed.path or '/'}",
            "REC-LURE-DELIVERY",
            "Verify Package Tracking Independently",
            "Fake delivery fees trick recipients into disclosing personal identities and payment information.",
            "Track packages exclusively on the courier's official tracking portal using your original tracking number; do not click SMS or email links."
        )

    reward_hits = sorted(tokens_found & REWARD_KEYWORDS)
    if reward_hits:
        add_pair(
            "FND-LURE-REWARD",
            "Reward & Prize Scam Incentive",
            "Medium",
            f"URL path/query contains prize/giveaway keyword(s): '{', '.join(reward_hits)}'.",
            "Scam schemes promise gifts, bonuses, or lottery winnings to entice users into submitting personal contact details or upfront processing fees.",
            f"Path/Query: {parsed.path or '/'}",
            "REC-LURE-REWARD",
            "Disregard Unsolicited Prize Claims",
            "Prize scams require victims to pay advance fees or surrender personal identification documents for non-existent rewards.",
            "Do not disclose personal information or pay processing fees for unsolicited lottery or giveaway announcements."
        )

    media_hits = sorted(set(features.get("media_terms", [])))
    is_media_resource = bool(media_hits or (features.get("has_static_html") and any(t in host for t in ["mp3", "music", "torrent", "media", "stream"])))
    if is_media_resource:
        terms_label = ", ".join(media_hits) if media_hits else "media/stream resource"
        add_pair(
            "FND-PATH-MEDIA-DOWNLOAD",
            "Media Content & File Download Endpoint",
            "Medium",
            f"URL path or domain indicates media distribution / download resources: '{terms_label}' ('{parsed.path or '/'}').",
            "Third-party multimedia indexing and file download pages frequently bundle adware, deceptive click-throughs, or drive-by redirect scripts.",
            f"Resource: {parsed.path or '/'}",
            "REC-PATH-MEDIA-DOWNLOAD",
            "Inspect Downloaded Media & Avoid Executable Payloads",
            "Third-party media sites commonly serve fake download buttons that deliver adware or unwanted browser extensions.",
            f"Never run downloaded executable installers or grant browser permissions on '{host}'. Use verified, official streaming platforms."
        )

    malware_hits = sorted(set(features.get("malware_terms", [])))
    if malware_hits or features.get("has_executable_ext"):
        ext_found = [ext for ext in [".exe", ".scr", ".bat", ".apk", ".zip", ".msi", ".iso", ".dll", ".ps1"] if (parsed.path or "").lower().endswith(ext)]
        ext_msg = f" (file: {ext_found[0]})" if ext_found else ""
        m_msg = f"keyword(s): {', '.join(malware_hits)}" if malware_hits else f"executable resource{ext_msg}"
        add_pair(
            "FND-PATH-MALWARE-DROP",
            "Suspicious Software or Executable Payload Vector",
            "High",
            f"URL targets software or suspicious executable payload ({m_msg}).",
            "Direct links to executable binaries or known malware terminology strongly correlate with trojan distributors, spyware drops, and ransomware droppers.",
            f"Payload: {parsed.path or '/'}",
            "REC-PATH-MALWARE-DROP",
            "Block Unauthorized Executable File Downloads",
            "Downloading and launching executable files from unverified web links can lead to immediate system compromise and endpoint infection.",
            f"Do not open or execute files originating from '{host}'. Verify file integrity via vendor checksums and multi-engine endpoint scanning."
        )

    if features.get("is_free_hosting") and not trusted_owner:
        add_pair(
            "FND-DOM-FREE-HOSTING",
            "Free Dynamic Cloud Hosting Service",
            "Medium",
            f"Hostname '{host}' is hosted on a free or dynamic cloud hosting platform.",
            "Free dynamic cloud subdomains are heavily exploited by threat actors to stage disposable phishing landing pages at zero financial cost.",
            f"Platform: {host}",
            "REC-DOM-FREE-HOSTING",
            "Verify Service Identity on Cloud Hosting",
            "Anyone can provision free cloud subdomains without identity verification, making them frequent staging grounds for brand impersonation.",
            "Confirm that the organization requesting your credentials officially hosts its services on this third-party cloud platform."
        )

    other_terms = sorted(tokens_found - (AUTH_KEYWORDS | URGENCY_KEYWORDS | FINANCE_KEYWORDS | CRYPTO_KEYWORDS | DELIVERY_KEYWORDS | REWARD_KEYWORDS | set(features.get("media_terms", [])) | set(features.get("malware_terms", []))))
    if other_terms and not (auth_hits or urgency_hits or finance_hits or crypto_hits or delivery_hits or reward_hits or is_media_resource or malware_hits):
        add_pair(
            "FND-LURE-GENERIC",
            "Suspicious Lure Wording Detected",
            "Low",
            f"Detected keyword(s): '{', '.join(other_terms)}'.",
            "These terms commonly appear in requests for credentials, account action, or payment changes.",
            f"Path/Query: {parsed.path or '/'}",
            "REC-LURE-GENERIC",
            "Verify Context of Sensitive Request",
            "Unsolicited requests for account action are frequently precursors to social engineering.",
            "Confirm whether this requested action was initiated by you before proceeding."
        )

    # 17. Clean Structure Check (if no structural flags)
    has_structural_flag = (features.get("url_length", 0) > 100 or
                           features.get("has_at") or
                           features.get("encoded", 0) >= 2 or
                           features.get("shortener") or
                           bool(tokens_found))
    if not has_structural_flag:
        add_pair(
            "FND-STRUCT-CLEAN",
            "Standard URL Structure",
            "Informational",
            f"URL length ({len(url)} chars), path structure ('{parsed.path or '/'}'), and character composition adhere to normal web conventions.",
            "No structural anomalies such as excessive length, parameter stuffing, special character manipulation, or userinfo delimiters were detected.",
            "URL Structure",
            "REC-STRUCT-CLEAN",
            "Follow Standard Web Browsing Hygiene",
            "Standard URL structure indicates absence of syntactic deception, though web application content must still be verified in context.",
            "Proceed with normal caution and verify that any page forms requesting sensitive actions are expected for this service."
        )

    # 17b. Live Dynamic Probing & DOM Inspection
    if live_probe and live_probe.get("probed"):
        if live_probe.get("cross_domain_redirect"):
            p_fin = urlparse(live_probe.get("final_url", ""))
            add_pair(
                "FND-LIVE-CROSS-REDIRECT",
                "Live Dynamic Redirection to Alternate Domain",
                "High",
                f"Submitted URL dynamically redirects to destination '{p_fin.hostname}' (via {len(live_probe.get('redirects', []))} hop(s)).",
                "Cross-domain redirects are a classic technique to mask hostile final landing pages behind reputable or intermediate forwarding services.",
                f"Redirect Target: {p_fin.hostname}",
                "REC-LIVE-CROSS-REDIRECT",
                "Inspect Final Landing Domain Identity",
                "Users following this link will be navigated away from the original domain to a different host.",
                f"Verify the destination domain ('{p_fin.hostname}') independently before entering any account credentials."
            )
        elif live_probe.get("same_domain_redirect"):
            orig_h = live_probe.get('orig_host') or host
            final_h = live_probe.get('final_host') or (urlparse(live_probe.get("final_url", "")).hostname)
            add_pair(
                "FND-REDIRECT-CANONICAL",
                "Canonical Subdomain Normalization",
                "Informational",
                f"Server canonicalizes traffic from '{orig_h}' to '{final_h}' within the same registered root domain.",
                "The web server performs standard canonical subdomain redirection (such as naked-to-www), keeping traffic within the authentic domain infrastructure.",
                f"Canonical Target: {final_h}",
                "REC-REDIRECT-CANONICAL",
                "Confirm Consistent Subdomain Routing",
                "Canonical same-domain redirects are standard web practice and do not cross administrative security boundaries.",
                f"Proceed normally, noting that navigation is standardized to '{final_h}'."
            )
        if live_probe.get("external_forms"):
            ext_target = urlparse(live_probe["external_forms"][0]).hostname or live_probe["external_forms"][0]
            add_pair(
                "FND-LIVE-FORM-EXTERNAL",
                "Live HTML Form Targets External Host",
                "High",
                f"Page contains a form action submitting user data to external host '{ext_target}'.",
                "Phishing kits frequently host cloned pages on compromised domains while submitting harvested credentials to an external attacker-controlled server.",
                f"Form Action: {ext_target}",
                "REC-LIVE-FORM-EXTERNAL",
                "Do Not Submit Form Data to External Endpoints",
                "Submitting data through this form will transmit your input to an external party differing from the page host.",
                "Discontinue interaction immediately; do not submit any personal, login, or payment data."
            )
        if live_probe.get("has_password_field") and (parsed.scheme == "http" or not trusted_owner):
            add_pair(
                "FND-LIVE-PASSWORD",
                "Live Credential Password Field Present",
                "High",
                "Live DOM inspection detected an active password input field on this unverified or unencrypted page.",
                "Login input fields on unverified domains are high-risk indicators of credential harvesting.",
                "DOM: <input type='password'>",
                "REC-LIVE-PASSWORD",
                "Protect Account Credentials from Unauthorized Capture",
                "Entering passwords on unverified sites risks credential compromise and account takeover.",
                "Do not type or auto-fill passwords on this page; use only official authenticated portals."
            )
        elif live_probe.get("reachable"):
            add_pair(
                "FND-LIVE-ACTIVE",
                "Live HTTP Service Active & Verified",
                "Informational",
                f"Live server responded (HTTP {live_probe.get('status_code', 200)}) with page title: '{live_probe.get('title') or 'Active'}'.",
                "Dynamic live probing verified that the destination web server is online, reachable, and serving content.",
                f"HTTP Status: {live_probe.get('status_code', 200)}",
                "REC-LIVE-ACTIVE",
                "Proceed with In-Context Verification",
                "Active web servers can serve dynamic applications; ensure page content matches your intended transaction.",
                "Verify that the displayed page title and requested actions match the authentic service."
            )

    # 18. Threat Intelligence & Blacklist
    if blacklist.get("listed"):
        matched_info = ", ".join(blacklist.get("matched_by", ["Threat feed match"]))
        add_pair(
            "FND-REP-BLACKLISTED",
            "Threat Intelligence Blacklist Match",
            "Critical",
            f"URL or host matched active security intelligence feed(s): {matched_info}.",
            "Security threat intelligence databases have identified this URL or domain as actively participating in phishing, malware, or credential harvesting.",
            f"Threat Intel ({blacklist.get('status', 'Listed')})",
            "REC-REP-BLACKLISTED",
            "Immediate Perimeter Threat Containment",
            "Confirmed malicious destinations will attempt to exploit browser vulnerabilities or steal credentials upon user interaction.",
            f"Block '{host}' immediately at the DNS resolver (sinkhole), firewall perimeter, and endpoint web security filters. Report to security operations."
        )
    elif blacklist.get("status") == "Clean" or (not blacklist.get("listed") and not blacklist.get("errors")):
        providers_str = ", ".join(blacklist.get("providers", ["Local domain blacklist"]))
        add_pair(
            "FND-REP-CLEAN",
            "Clean Threat Intelligence Feeds",
            "Informational",
            f"Queried threat intelligence feed(s) ({providers_str}) report no active malicious flags.",
            "The domain and URL are not currently indexed as known threats on configured threat feeds.",
            "Reputation: Clean",
            "REC-REP-CLEAN",
            "Maintain Defense-in-Depth Vigilance",
            "Clean feed results do not guarantee absolute safety, as newly crafted zero-day phishing sites often launch hours before appearing on global blacklists.",
            "Continue monitoring user reports and correlate with authentication logs rather than relying on blacklist status alone."
        )
    elif blacklist.get("status") == "Check incomplete":
        add_pair(
            "FND-REP-INCOMPLETE",
            "Threat Intelligence Feeds Incomplete",
            "Low",
            f"External threat intelligence check incomplete: {', '.join(blacklist.get('errors', ['API keys unconfigured']))}.",
            "External reputation lookup was partially skipped due to missing API keys (Google Safe Browsing / VirusTotal).",
            "Reputation: Check incomplete",
            "REC-REP-INCOMPLETE",
            "Configure Threat Intelligence API Keys",
            "Operating without external API keys limits reputation analysis to local domain feeds.",
            "Provide valid Google Safe Browsing and VirusTotal API keys in environment configuration to enable real-time threat feed querying."
        )

    return findings, recommendations


FINDING_PRIORITY = {
    # Security test
    "FND-TEST-AMTSO": 200,
    # Critical Threats & Blocklists
    "FND-REP-BLACKLISTED": 110,
    "FND-INST-IMPERSONATION": 108,
    "FND-DOM-TYPO": 105,
    "FND-DOM-IMPERSONATION": 104,
    "FND-PATH-MALWARE-DROP": 103,
    "FND-LIVE-CROSS-REDIRECT": 102,
    "FND-LIVE-FORM-EXTERNAL": 101,
    "FND-DOM-IP": 100,
    "FND-STRUCT-AT": 99,
    "FND-DOM-UNREGISTERED": 98,
    "FND-LURE-AUTH": 95,
    "FND-LIVE-PASSWORD": 94,
    "FND-LURE-URGENCY": 93,
    "FND-LURE-FINANCE": 92,
    "FND-LURE-CRYPTO": 91,
    "FND-DOM-PUNYCODE": 90,
    # High / Transport & Structural Risks
    "FND-INST-LOOKALIKE": 87,
    "FND-PROTO-HTTP": 85,
    "FND-SSL-INVALID": 84,
    "FND-STRUCT-SHORTENER": 80,
    "FND-DOM-RISKY-TLD": 78,
    "FND-PATH-MEDIA-DOWNLOAD": 77,
    "FND-DOM-DEEP-SUBDOMAIN": 76,
    "FND-DOM-FREE-HOSTING": 75,
    "FND-DOM-NEW": 74,
    "FND-LURE-DELIVERY": 73,
    "FND-LURE-REWARD": 72,
    "FND-DOM-RFC1918": 71,
    "FND-PROTO-HTTPS": 70,
    # Identity & Domain Authenticity
    "FND-INST-VERIFIED": 69,
    "FND-INST-SUBDOMAIN": 68,
    "FND-DOM-OFFICIAL": 67,
    "FND-DOM-THIRD-PARTY": 66,
    "FND-DOM-SUBDOMAIN": 65,
    "FND-DOM-RESERVED": 64,
    "FND-SSL-VALID": 62,
    "FND-SSL-UNAVAILABLE": 60,
    "FND-DOM-ESTABLISHED": 58,
    "FND-INST-DISTINCT": 57,
    "FND-STRUCT-LENGTH": 55,
    "FND-STRUCT-ENCODED": 54,
    "FND-LURE-GENERIC": 53,
    "FND-DOM-UNVERIFIED-AGE": 52,
    "FND-REP-INCOMPLETE": 50,
    "FND-REDIRECT-CANONICAL": 48,
    # Baseline / Filler Findings (Low priority)
    "FND-STRUCT-CLEAN": 20,
    "FND-REP-CLEAN": 15,
    "FND-LIVE-ACTIVE": 10,
}


def filter_top_findings(findings, recommendations, max_count=5):
    """
    Select up to `max_count` (target 4-5) of the most important URL-specific
    findings and matching recommendations. Always includes the transport protocol
    finding (HTTP or HTTPS) and preserves original logical display order.
    """
    if len(findings) <= max_count:
        return findings, recommendations

    # Must prioritize and include protocol finding (HTTP or HTTPS)
    proto_finding = next((f for f in findings if f["id"] in {"FND-PROTO-HTTP", "FND-PROTO-HTTPS"}), None)
    other_findings = [f for f in findings if f != proto_finding]

    # Sort remaining findings by severity priority
    other_findings.sort(key=lambda f: FINDING_PRIORITY.get(f["id"], 50), reverse=True)

    needed = max_count - (1 if proto_finding else 0)
    selected = []
    if proto_finding:
        selected.append(proto_finding)
    selected.extend(other_findings[:needed])

    # Preserve original logical presentation order
    order_map = {f["id"]: i for i, f in enumerate(findings)}
    selected.sort(key=lambda f: order_map.get(f["id"], 0))

    selected_ids = {f["id"] for f in selected}
    selected_recs = [rec for rec in recommendations if rec["finding_id"] in selected_ids]
    return selected, selected_recs


def analyze_url(raw_url):
    url = normalize_url(raw_url)
    parsed, features = urlparse(url), lexical_features(url)
    host = parsed.hostname or ""
    institutional = verify_institutional_domain(host, parsed.path)
    trusted_owner = _trusted_domain(host)
    if institutional.get("is_institutional"):
        cat = institutional.get("category")
        if cat in {"Official", "Subdomain", "Officially Verified Institutional Domain", "Verified Institutional Subdomain"}:
            trusted_owner = institutional["institution_name"]
    reserved_test_domain = host == "example" or host.endswith(".example") or host == "example.com" or host.endswith(".example.com")
    detected_brand, brand_token = _detect_brand(host, parsed.path)
    impersonated_brand = detected_brand or next((brand for brand in IMPERSONATED_BRANDS if brand in host), None)
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
    live_probe = safe_live_probe(url, timeout=2.0) if not is_test else None
    module_scores = {}

    structure = min(100, features["url_length"] // 2 + features["subdomains"] * 9 + features["special_chars"] * 4 +
                    features["hyphens"] * 5 + features["encoded"] * 7)
    module_scores["URL Structure"] = structure

    has_brand_impersonation = bool(
        ((detected_brand or impersonated_brand or features.get("brand_typosquat")) and not trusted_owner) or
        (institutional.get("is_institutional") and institutional.get("category") in {"Phishing", "Lookalike", "Known Malicious or Impersonated Domain", "Potential MITS Lookalike Domain"})
    )
    is_media_piracy = bool(features.get("has_media_piracy") or (features.get("has_static_html") and any(t in host for t in ["mp3", "music", "torrent", "media", "stream"])))
    is_malware_drop = bool(features.get("has_executable_ext") or features.get("malware_terms"))

    # 1. Evidence-based Domain risk score:
    inst_cat = institutional.get("category") if institutional.get("is_institutional") else ""
    if inst_cat in {"Phishing", "Known Malicious or Impersonated Domain"}:
        domain_score = 95
    elif inst_cat in {"Lookalike", "Potential MITS Lookalike Domain"}:
        domain_score = 75
    elif has_brand_impersonation:
        domain_score = 85 # Unauthorized domain incorporating a protected brand name
    elif is_malware_drop and not trusted_owner:
        domain_score = 80 # Potential malware distribution host
    elif is_media_piracy and not trusted_owner:
        domain_score = 55 # Unverified third-party multimedia piracy host
    elif features.get("is_free_hosting") and not trusted_owner:
        domain_score = 65 # Disposable cloud hosting platform
    elif domain.get("age_days") is None:
        domain_score = 55
    elif domain["age_days"] < 30:
        domain_score = 80
    elif domain["age_days"] < 180:
        domain_score = 45
    elif not trusted_owner:
        domain_score = 25 # Unverified third-party domain
    else:
        domain_score = 5 # Official trusted domain

    # 2. Evidence-based Transport risk score:
    # A valid SSL on an unauthorized brand domain protects the attacker's traffic, not the user!
    if has_brand_impersonation:
        transport_score = 45 if ssl_data.get("valid") else 75
    elif is_malware_drop and not trusted_owner:
        transport_score = 40 if ssl_data.get("valid") else 70
    else:
        transport_score = 5 if ssl_data.get("valid") else (45 if parsed.scheme == "https" else 70)

    # 3. Evidence-based Reputation risk score:
    if blacklist.get("listed"):
        rep_score = 100
    elif has_brand_impersonation:
        rep_score = 85 # Unverified third-party domain targeting a protected brand
    elif is_malware_drop and not trusted_owner:
        rep_score = 75
    elif is_media_piracy and not trusted_owner:
        rep_score = 40 # Unverified media indexing or file download source
    elif trusted_owner:
        rep_score = 0
    elif blacklist.get("status") == "Not Verified":
        rep_score = 30 # Unverified on external threat feeds
    else:
        rep_score = 10 if not trusted_owner else 0

    if has_brand_impersonation:
        structure = max(structure, 55)

    keyword_boost = (35 if is_media_piracy else 0) + (50 if is_malware_drop else 0)
    kw_score = min(100, features["suspicious_words"] * 22 + keyword_boost)
    ml_score = round(ml_probabilities.get("Phishing", 0) + ml_probabilities.get("Suspicious", 0) * .45)
    module_scores["URL Structure"] = max(2, structure)
    module_scores.update({
        "Keywords": kw_score,
        "Domain": max(2, domain_score),
        "Transport": max(2, transport_score),
        "Reputation": max(2, rep_score),
        "ML Model": max(2, ml_score),
    })
    weights = {"URL Structure": .18, "Keywords": .14, "Domain": .12, "Transport": .13, "Reputation": .25, "ML Model": .18}
    score = round(sum(module_scores[k] * weights[k] for k in weights), 1)

    # Explicit Evidence-based Rule Floors
    if blacklist.get("listed"):
        score = max(score, 90.0)
    elif institutional.get("is_institutional") and institutional.get("category") in {"Phishing", "Known Malicious or Impersonated Domain"}:
        score = max(score, 90.0)
    elif institutional.get("is_institutional") and institutional.get("category") in {"Lookalike", "Potential MITS Lookalike Domain"}:
        score = max(score, 65.0)
    elif features["is_ip"] and features["suspicious_words"]:
        score = max(score, 82.0)
    elif is_malware_drop and not trusted_owner:
        score = max(score, 65.0)
    elif features.get("brand_typosquat") and parsed.scheme != "https":
        score = max(score, 75.0)
    elif features.get("brand_typosquat"):
        score = max(score, 65.0)
    elif has_brand_impersonation:
        # High-severity rule: Unauthorized domain incorporating a protected brand name (combosquatting / brand spoofing)
        if live_probe and live_probe.get("cross_domain_redirect"):
            score = max(score, 80.0)
        elif features.get("suspicious_words") or parsed.scheme != "https":
            score = max(score, 78.0)
        else:
            score = max(score, 68.0)
    elif is_media_piracy and not trusted_owner:
        score = max(score, 38.0)
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
    if reserved_test_domain and not impersonated_brand and features["suspicious_words"] and not blacklist.get("listed"):
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
    if (domain.get("status") in {"Unknown", "Not Verified"} or domain.get("status") == "Not Registered") and domain.get("age_days") is None:
        adjustments["Missing domain age"] = RISK_PENALTIES["missing_domain_age"]
    # Credit is awarded when blacklist is unlisted and there is no brand impersonation or malware/piracy risk
    if (str(blacklist.get("status", "")).startswith("Clean") or not blacklist.get("listed")) and not has_brand_impersonation and not is_media_piracy and not is_malware_drop:
        adjustments["Clean blacklist credit"] = RISK_PENALTIES["clean_blacklist_credit"]
    # In cybersecurity, no automated scan provides a 100% guarantee; enforce a minimum 2.0 residual risk floor
    score = round(max(2.0, min(100.0, score + sum(adjustments.values()))), 1)
    if trusted_owner and not blacklist.get("listed"):
        # An exact allowlisted owner boundary prevents transient WHOIS/TLS
        # lookup failures from turning a known official host into a threat.
        # Enforce residual risk floor (never 0.0)
        score = round(max(2.0, min(score, LEGITIMATE_MAX)), 1)

    classification = ("Legitimate" if score <= LEGITIMATE_MAX else
                      "Suspicious" if score <= SUSPICIOUS_MAX else "Phishing")
    final_blacklist = dict(blacklist)
    if not final_blacklist.get("listed"):
        if classification == "Phishing":
            final_blacklist["status"] = "Unlisted (Heuristic Threat)"
        elif classification == "Suspicious":
            final_blacklist["status"] = "Unlisted"
        elif blacklist.get("status") == "Not Verified":
            final_blacklist["status"] = "Not Verified"
        else:
            final_blacklist["status"] = "Clean"
    probabilities = _hybrid_probabilities(ml_probabilities, classification, score, bool(trusted_owner))
    confidence = round(probabilities[classification], 1)
    reputation = _reputation_status(host, trusted_owner, final_blacklist, domain, ssl_data, classification, has_brand_impersonation=has_brand_impersonation)

    # Generate URL-specific detection findings and strictly linked recommendations
    findings, recommendations = generate_findings_and_recommendations(
        url, parsed, host, features, trusted_owner,
        detected_brand, brand_token, impersonated_brand,
        ssl_data, domain, final_blacklist, reserved_test_domain,
        is_test=False, live_probe=live_probe, institutional=institutional
    )
    # Filter to the top 4-5 most critical URL-specific findings and recommendations
    findings, recommendations = filter_top_findings(findings, recommendations, max_count=5)
    reasons = [
        f"[{f['id']}] {f['title']}: {f['explanation']} Evidence: {f['evidence']}"
        for f in findings
    ]

    return {
        "url": url,
        "classification": classification,
        "threat_score": score,
        "confidence": confidence,
        "ssl": ssl_data,
        "domain": domain,
        "blacklist": final_blacklist,
        "reputation": reputation,
        "findings": findings,
        "recommendations": recommendations,
        "reasons": reasons,
        "module_scores": module_scores,
        "risk_adjustments": adjustments,
        "probabilities": probabilities,
        "ml_probabilities": ml_probabilities,
        "features": features,
        "live_probe": live_probe,
        "institutional": institutional,
        "is_security_test": False,
    }


def _test_result(url, probabilities, ssl_data, domain, blacklist):
    parsed = urlparse(url)
    findings, recommendations = generate_findings_and_recommendations(
        url, parsed, parsed.hostname or "amtso.org", {}, None, None, None, None,
        ssl_data, domain, blacklist, False, is_test=True, institutional={"is_institutional": False, "status": "Non-Institutional Domain"}
    )
    findings, recommendations = filter_top_findings(findings, recommendations, max_count=5)
    reasons = [
        f"[{f['id']}] {f['title']}: {f['explanation']} Evidence: {f['evidence']}"
        for f in findings
    ]
    return {
        "url": url,
        "classification": "Security Test",
        "threat_score": 0.0,
        "confidence": 100.0,
        "ssl": ssl_data,
        "domain": domain,
        "blacklist": blacklist,
        "reputation": "amtso.org — Official security test site",
        "findings": findings,
        "recommendations": recommendations,
        "reasons": reasons,
        "module_scores": {k: 0 for k in ["URL Structure", "Keywords", "Domain", "Transport", "Reputation", "ML Model"]},
        "probabilities": {"Legitimate": 0.0, "Phishing": 0.0, "Suspicious": 0.0, "Security Test": 100.0},
        "ml_probabilities": probabilities,
        "features": {},
        "institutional": {"is_institutional": False, "status": "Non-Institutional Domain"},
        "is_security_test": True,
    }


def _recommend(label, scheme, listed, features, reserved_test_domain, detected_brand=None, host=""):
    """Legacy helper maintained for backward compatibility."""
    parsed = urlparse(f"{scheme}://{host}" if host else "https://example.com")
    ssl_data = {"valid": scheme == "https", "status": "Valid" if scheme == "https" else "No HTTPS"}
    domain = {"age_days": 365, "age_display": "1y 0d"}
    blacklist = {"listed": bool(listed), "status": "Listed" if listed else "Clean"}
    _, recs = generate_findings_and_recommendations(
        parsed.geturl(), parsed, host, features, None,
        detected_brand, None, None, ssl_data, domain, blacklist, reserved_test_domain, is_test=False
    )
    return [r["action"] for r in recs]


def _hybrid_probabilities(raw, classification, score, trusted):
    """Align displayed confidence with the final evidence-based decision."""
    target = 97.0 if trusted else (min(96.0, 50.0 + score * .5) if classification == "Phishing"
                                  else min(94.0, 55.0 + abs(score - 47.5)) if classification == "Suspicious"
                                  else min(96.0, 70.0 + (30.0 - score) * .7))
    # In cybersecurity, no automated scan provides a 100% guarantee; cap maximum probability at 98.0%
    target = round(min(98.0, max(target, raw.get(classification, 0.0))), 2)
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


def _reputation_status(host, trusted_owner, blacklist, domain, ssl_data, classification, has_brand_impersonation=False):
    """Create a useful local assessment without claiming an external-feed verdict."""
    site = host[4:] if host.startswith("www.") else host
    if blacklist.get("listed"):
        return f"{site} — Threat feed match"
    if trusted_owner:
        return f"{site} — Official {trusted_owner} domain"
    if has_brand_impersonation:
        return f"{site} — High risk (Unauthorized Brand Lookalike)"
    if classification == "Phishing":
        return f"{site} — High risk"
    if classification == "Suspicious":
        return f"{site} — Caution (Suspicious domain)"
    if blacklist.get("status") == "Not Verified":
        return f"{site} — Third-party domain (Not Verified)"
    age = domain.get("age_days")
    if age is not None and age >= 365 and ssl_data.get("valid"):
        return f"{site} — Established"
    if age is not None and age >= 180 and ssl_data.get("valid"):
        return f"{site} — Moderate history"
    if age is not None and age < 90:
        return f"{site} — Newly registered"
    return f"{site} — Limited reputation data"
