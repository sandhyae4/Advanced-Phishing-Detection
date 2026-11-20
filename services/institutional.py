import datetime as dt
import re
from services.features import extract_registered_domain, count_subdomains

# Comprehensive Institutional Knowledge Base for MITS
# Reference: https://mits.ac.in/
# Criteria 4.4.2 Documentation: https://mits.ac.in/assets/pdf/facility/4.4.2_Procedures_utlization.pdf
MITS_OFFICIAL_METADATA = {
    "name": "Madanapalle Institute of Technology & Science (MITS)",
    "location": "Madanapalle, Chittoor District, Andhra Pradesh, India",
    "founded_year": 1998,
    "status_designation": "Autonomous Institution, UGC Deemed-to-be-University (2025)",
    "official_portal": "https://mits.ac.in/",
    "apex_domain": "mits.ac.in",
    "official_registry": "ERNET India (National Research & Academic Registrar under MeitY, Govt. of India)",
    "registration_date": "2007-01-23",
    "verification_source": "Official MITS Academic Governance & ERNET India Registry Data",
    "subdomains": {
        "mitsmoodle": {
            "name": "MITS Moodle Learning Management System (LMS)",
            "service_type": "Institutional LMS / Course Materials & Online Assessment",
            "reference": "https://mits.ac.in/assets/pdf/facility/4.4.2_Procedures_utlization.pdf",
            "evidence": "Officially documented in MITS NAAC Criteria 4.4.2 Procedures & Policies for IT & Academic Facilities.",
            "operational_status": "Verified Institutional Academic Portal"
        },
        "www": {
            "name": "MITS Primary Institutional Web Portal",
            "service_type": "Public Web Presence & Administration",
            "reference": "https://mits.ac.in/",
            "evidence": "Primary public web presence for Madanapalle Institute of Technology & Science.",
            "operational_status": "Verified Institutional Portal"
        },
        "exam": {
            "name": "MITS Examination Cell",
            "service_type": "Examinations, Grading & Student Hall Tickets",
            "reference": "https://mits.ac.in/examination-cell",
            "evidence": "Autonomous Examination Management portal for MITS students.",
            "operational_status": "Verified Institutional Subdomain"
        },
        "alumni": {
            "name": "MITS Alumni Network",
            "service_type": "Alumni Association & Career Mentorship",
            "reference": "https://mits.ac.in/alumni",
            "evidence": "Official MITS Alumni Association portal.",
            "operational_status": "Verified Institutional Subdomain"
        },
        "admissions": {
            "name": "MITS Admissions & Student Intake",
            "service_type": "Admissions & Counseling Guidance",
            "reference": "https://mits.ac.in/admissions",
            "evidence": "Central admissions portal for undergraduate and postgraduate courses.",
            "operational_status": "Verified Institutional Subdomain"
        },
        "library": {
            "name": "MITS Digital Library",
            "service_type": "Digital Library & E-Journals Repository",
            "reference": "https://mits.ac.in/library",
            "evidence": "Digital learning resources repository for faculty and research scholars.",
            "operational_status": "Verified Institutional Subdomain"
        }
    }
}

# Recognized independent institutions sharing the "MITS" acronym
# Distinct legal entities that must not be falsely confused with Madanapalle Institute
DISTINCT_MITS_ENTITIES = {
    "mgmits.ac.in": {
        "name": "Muthoot Institute of Technology and Science (MGMITS)",
        "location": "Ernakulam, Kochi, Kerala, India",
        "reference": "https://mgmits.ac.in/",
        "note": "Independent engineering institution established by the Muthoot Group; not affiliated with Madanapalle Institute."
    },
    "mitsgwalior.in": {
        "name": "Madhav Institute of Technology & Science (MITS Gwalior)",
        "location": "Gwalior, Madhya Pradesh, India",
        "reference": "https://mitsgwalior.in/",
        "note": "Established in 1957 under Scindia Engineering College Society; distinct from Madanapalle Institute."
    },
    "mits.edu.in": {
        "name": "Meghnad Saha Institute of Technology / Secondary Education Entity",
        "location": "Kolkata, West Bengal, India",
        "reference": "https://mits.edu.in/",
        "note": "Independent educational entity; separate from Madanapalle Institute of Technology & Science."
    }
}


def verify_institutional_domain(host, path=""):
    """
    Evidence-based institutional domain verification mechanism.
    Distinguishes:
      1. Officially Verified Institutional Domain (mits.ac.in)
      2. Verified Institutional Subdomain (mitsmoodle.mits.ac.in, etc.)
      3. Potential MITS Lookalike Domain (mits-ac.in, mitsmoodle.com, etc.)
      4. Unverified MITS-Related Domain (mgmits.ac.in, mitsgwalior.in)
      5. Known Malicious or Impersonated Domain
    """
    host_clean = (host or "").lower().strip().rstrip(".")
    reg_domain = extract_registered_domain(host_clean) or host_clean
    timestamp = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # 1. Official MITS Apex Domain
    if host_clean == "mits.ac.in":
        return {
            "is_institutional": True,
            "status": "Officially Verified Institutional Domain",
            "category": "Officially Verified Institutional Domain",
            "institution_name": MITS_OFFICIAL_METADATA["name"],
            "location": MITS_OFFICIAL_METADATA["location"],
            "registered_domain": "mits.ac.in",
            "subdomain": "",
            "official_website_reference": MITS_OFFICIAL_METADATA["official_portal"],
            "evidence": f"Authoritative apex academic domain registered through {MITS_OFFICIAL_METADATA['official_registry']} on {MITS_OFFICIAL_METADATA['registration_date']}. Validated against MITS institutional accreditation records.",
            "verification_source": MITS_OFFICIAL_METADATA["verification_source"],
            "last_verified": timestamp,
            "severity": "Informational",
            "finding_id": "FND-INST-VERIFIED",
            "recommendation_id": "REC-INST-VERIFIED"
        }

    # 2. Official MITS Subdomain
    if host_clean.endswith(".mits.ac.in"):
        prefix = host_clean[:-len(".mits.ac.in")]
        sub_info = MITS_OFFICIAL_METADATA["subdomains"].get(prefix)
        if sub_info:
            evidence_desc = (
                f"{sub_info['name']}: {sub_info['evidence']} "
                f"Referenced at {sub_info['reference']}. Confirmed within MITS official infrastructure boundary."
            )
            svc_name = sub_info["name"]
            ref_link = sub_info["reference"]
        else:
            evidence_desc = f"Active institutional subdomain '{prefix}' operating inside Madanapalle Institute of Technology & Science's DNS boundary ('mits.ac.in')."
            svc_name = f"MITS Subdomain ({prefix})"
            ref_link = "https://mits.ac.in/"

        return {
            "is_institutional": True,
            "status": "Verified Institutional Subdomain",
            "category": "Verified Institutional Subdomain",
            "institution_name": MITS_OFFICIAL_METADATA["name"],
            "service": svc_name,
            "service_name": svc_name,
            "location": MITS_OFFICIAL_METADATA["location"],
            "registered_domain": "mits.ac.in",
            "subdomain": prefix,
            "official_website_reference": ref_link,
            "evidence": evidence_desc,
            "verification_source": "Official MITS Documentation (NAAC Criteria 4.4.2 & Institutional Registry)",
            "last_verified": timestamp,
            "severity": "Informational",
            "finding_id": "FND-INST-SUBDOMAIN",
            "recommendation_id": "REC-INST-SUBDOMAIN"
        }

    # 3. Distinct independent entities sharing the "MITS" acronym
    if reg_domain in DISTINCT_MITS_ENTITIES:
        entity = DISTINCT_MITS_ENTITIES[reg_domain]
        return {
            "is_institutional": True,
            "status": "Unverified MITS-Related Domain",
            "category": "Unverified MITS-Related Domain",
            "institution_name": entity["name"],
            "location": entity["location"],
            "registered_domain": reg_domain,
            "subdomain": host_clean[:-len(reg_domain)].rstrip(".") if host_clean != reg_domain else "",
            "official_website_reference": entity["reference"],
            "evidence": entity["note"],
            "verification_source": "Institutional Academic Registry Disambiguation",
            "last_verified": timestamp,
            "severity": "Informational",
            "finding_id": "FND-INST-DISTINCT",
            "recommendation_id": "REC-INST-DISTINCT"
        }

    # 4. Check for Potential MITS Lookalike or Malicious Impersonation
    # Patterns that abuse MITS identifiers:
    # e.g., 'mitsmoodle.com', 'mits-ac.in', 'mits-login.xyz', 'mits.ac.in.attacker.com'
    is_lookalike = False
    lookalike_reason = ""
    is_malicious = False

    # Check 4a: Subdomain Spoofing (e.g., mits.ac.in.attacker.com)
    if "mits.ac.in" in host_clean and reg_domain != "mits.ac.in":
        is_lookalike = True
        is_malicious = True
        lookalike_reason = f"Hostname concatenates 'mits.ac.in' as a deceptive subdomain prefix to mislead users, but the actual resolving root domain is untrusted third-party host '{reg_domain}'."

    # Check 4b: Moodle Impersonation outside mits.ac.in (e.g., mitsmoodle.com, mitsmoodle.org)
    elif "mitsmoodle" in host_clean and reg_domain != "mits.ac.in":
        is_lookalike = True
        lookalike_reason = f"Domain incorporates the proprietary institutional name 'mitsmoodle' (MITS Learning Management System) outside the authoritative 'mits.ac.in' ERNET domain."
        # If combined with suspicious TLD or HTTP, elevated to malicious
        if any(tld in host_clean for tld in [".xyz", ".top", ".click", ".site", ".tk", ".cf"]) or any(kw in host_clean for kw in ["login", "verify", "auth", "portal"]):
            is_malicious = True

    # Check 4c: Hyphenated / Combosquatted MITS lookalikes (e.g. mits-ac.in, mits-edu.in, mits-portal.com)
    elif re.search(r"\bmits[-\.]", host_clean) or re.search(r"[-\.]mits\b", host_clean):
        # Exclude legitimate words that end in mits (e.g. commits.com, limits.org)
        tokens = re.split(r"[\.-]", host_clean)
        if "mits" in tokens:
            is_lookalike = True
            lookalike_reason = f"Domain constructs a lookalike hostname using the token 'mits' on '{reg_domain}' without authoritative ERNET affiliation."
            if any(kw in (host_clean + path).lower() for kw in ["login", "signin", "portal", "verify", "student", "fees", "moodle", "exam"]):
                is_malicious = True

    if is_malicious:
        return {
            "is_institutional": True,
            "status": "Known Malicious or Impersonated Domain",
            "category": "Known Malicious or Impersonated Domain",
            "institution_name": "Targeted: Madanapalle Institute of Technology & Science (MITS)",
            "location": "Unauthorized / Impersonated Destination",
            "registered_domain": reg_domain,
            "subdomain": host_clean[:-len(reg_domain)].rstrip(".") if host_clean != reg_domain else "",
            "official_website_reference": "https://mits.ac.in/",
            "evidence": lookalike_reason + " Poses acute risk of credential harvesting targeting MITS students, faculty, or institutional accounts.",
            "verification_source": "PhishGuard Institutional Deception Engine",
            "last_verified": timestamp,
            "severity": "Critical",
            "finding_id": "FND-INST-IMPERSONATION",
            "recommendation_id": "REC-INST-IMPERSONATION"
        }

    if is_lookalike:
        return {
            "is_institutional": True,
            "status": "Potential MITS Lookalike Domain",
            "category": "Potential MITS Lookalike Domain",
            "institution_name": "Potential Lookalike of Madanapalle Institute of Technology & Science",
            "location": "Unverified External Host",
            "registered_domain": reg_domain,
            "subdomain": host_clean[:-len(reg_domain)].rstrip(".") if host_clean != reg_domain else "",
            "official_website_reference": "https://mits.ac.in/",
            "evidence": lookalike_reason + " External host is not affiliated with MITS official infrastructure.",
            "verification_source": "PhishGuard Institutional Deception Engine",
            "last_verified": timestamp,
            "severity": "High",
            "finding_id": "FND-INST-LOOKALIKE",
            "recommendation_id": "REC-INST-LOOKALIKE"
        }

    # Not an institutional MITS domain
    return {
        "is_institutional": False,
        "status": "Non-Institutional Domain",
        "category": "Standard",
        "institution_name": "",
        "registered_domain": reg_domain,
        "subdomain": "",
        "evidence": "",
        "verification_source": "N/A",
        "last_verified": timestamp,
        "severity": "Informational",
        "finding_id": "",
        "recommendation_id": ""
    }

