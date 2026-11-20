import os
os.environ["PHISHGUARD_DATABASE"] = ":memory:"
from app import app
from services.analyzer import analyze_url

def test_amtso_is_security_test():
    assert analyze_url("https://www.amtso.org/check-desktop-phishing-page/")["classification"] == "Security Test"

def test_ip_and_http_are_explained():
    r = analyze_url("http://192.0.2.10/login")
    assert r["classification"] in {"Suspicious", "Phishing"}
    assert any("IP address" in x for x in r["reasons"])
    assert r["ssl"]["status"] == "No HTTPS"

def test_malformed_scheme_rejected():
    try: analyze_url("javascript:alert(1)")
    except ValueError: pass
    else: raise AssertionError("unsafe scheme accepted")

def test_api_validation():
    with app.test_client() as client:
        response = client.post("/api/analyze", json={"url": "ftp://example.com"})
        assert response.status_code == 400

def test_risk_threshold_boundaries():
    from services.analyzer import LEGITIMATE_MAX, SUSPICIOUS_MAX
    assert LEGITIMATE_MAX == 30.0
    assert SUSPICIOUS_MAX == 60.0

def test_raw_ip_receives_explicit_penalties():
    r = analyze_url("http://192.0.2.10/login")
    assert r["risk_adjustments"]["Raw IP address"] == 25.0
    assert r["risk_adjustments"]["HTTP without HTTPS"] == 15.0
    assert r["risk_adjustments"]["No valid SSL certificate"] == 15.0
    assert r["risk_adjustments"]["Clean blacklist credit"] == -5.0
    assert r["classification"] == "Phishing"

def test_http_generic_lure_crosses_new_phishing_threshold():
    r = analyze_url("http://customer-support.example/restore")
    assert r["threat_score"] > 60
    assert r["classification"] == "Phishing"

def test_facebook_typosquat_is_phishing():
    r = analyze_url("http://faceboook.com")
    assert r["features"]["brand_typosquat"] == 1
    assert r["features"]["typosquat_brand"] == "facebook"
    assert r["threat_score"] > 60
    assert r["classification"] == "Phishing"
    assert any("typosquatting" in reason.lower() for reason in r["reasons"])

def test_blacklist_detection_listed():
    from services.intelligence import blacklist_check
    r = blacklist_check("http://arnazon-order-update.online/signin")
    assert r["listed"] is True
    assert r["status"] == "Listed"

def test_blacklist_detection_clean():
    from services.intelligence import blacklist_check
    r = blacklist_check("https://google.com")
    assert r["listed"] is False
    assert r["status"] == "Clean"

def test_finding_and_recommendation_schema():
    r = analyze_url("https://chatgpt.com")
    assert "findings" in r and len(r["findings"]) > 0
    assert "recommendations" in r and len(r["recommendations"]) > 0
    for f in r["findings"]:
        assert f["id"].startswith("FND-")
        assert f["title"]
        assert f["severity"] in {"Critical", "High", "Medium", "Low", "Informational"}
        assert f["evidence"]
        assert f["explanation"]
        assert f["component"]
        assert f["recommendation_id"].startswith("REC-")
    for rec in r["recommendations"]:
        assert rec["id"].startswith("REC-")
        assert rec["finding_id"].startswith("FND-")
        assert rec["title"]
        assert rec["risk"]
        assert rec["action"]
    # Check 1-to-1 linkage
    finding_map = {f["id"]: f["recommendation_id"] for f in r["findings"]}
    for rec in r["recommendations"]:
        assert rec["finding_id"] in finding_map
        assert finding_map[rec["finding_id"]] == rec["id"]

def test_chatgpt_and_mail_google_divergence():
    r1 = analyze_url("https://chatgpt.com")
    r2 = analyze_url("https://mail.google.com")
    f_ids1 = {f["id"] for f in r1["findings"]}
    f_ids2 = {f["id"] for f in r2["findings"]}
    # mail.google.com has subdomain finding that chatgpt.com does not
    assert "FND-DOM-SUBDOMAIN" in f_ids2
    assert "FND-DOM-SUBDOMAIN" not in f_ids1
    rec_ids1 = {rec["id"] for rec in r1["recommendations"]}
    rec_ids2 = {rec["id"] for rec in r2["recommendations"]}
    assert "REC-DOM-SUBDOMAIN" in rec_ids2
    assert "REC-DOM-SUBDOMAIN" not in rec_ids1

def test_protocol_findings_strict_isolation():
    r_http = analyze_url("http://example.com")
    r_https = analyze_url("https://example.com")
    http_findings = {f["id"] for f in r_http["findings"]}
    https_findings = {f["id"] for f in r_https["findings"]}
    assert "FND-PROTO-HTTP" in http_findings
    assert "FND-PROTO-HTTPS" not in http_findings
    assert "FND-PROTO-HTTPS" in https_findings
    assert "FND-PROTO-HTTP" not in https_findings
    http_recs = {r["id"] for r in r_http["recommendations"]}
    https_recs = {r["id"] for r in r_https["recommendations"]}
    assert "REC-PROTO-HTTP" in http_recs
    assert "REC-PROTO-HTTPS" not in http_recs
    assert "REC-PROTO-HTTPS" in https_recs
    assert "REC-PROTO-HTTP" not in https_recs

def test_at_symbol_detection_and_recommendation():
    r = analyze_url("https://example.com@evil.test")
    f_ids = {f["id"] for f in r["findings"]}
    assert "FND-STRUCT-AT" in f_ids
    rec_ids = {rec["id"] for rec in r["recommendations"]}
    assert "REC-STRUCT-AT" in rec_ids
    at_rec = next(rec for rec in r["recommendations"] if rec["id"] == "REC-STRUCT-AT")
    assert "Inspect" in at_rec["title"]
    assert "@" in at_rec["action"]

def test_ip_host_findings_and_recommendations():
    r = analyze_url("https://192.168.1.1/login")
    f_ids = {f["id"] for f in r["findings"]}
    rec_ids = {rec["id"] for rec in r["recommendations"]}
    assert "FND-DOM-IP" in f_ids
    assert "REC-DOM-IP" in rec_ids
    assert "FND-LURE-AUTH" in f_ids
    assert "REC-LURE-AUTH" in rec_ids

def test_shortener_findings_and_recommendations():
    r = analyze_url("https://bit.ly/example")
    f_ids = {f["id"] for f in r["findings"]}
    rec_ids = {rec["id"] for rec in r["recommendations"]}
    assert "FND-STRUCT-SHORTENER" in f_ids
    assert "REC-STRUCT-SHORTENER" in rec_ids

def test_br_icloud_combosquat_is_phishing():
    r = analyze_url("https://br-icloud.com.br")
    assert r["classification"] == "Phishing"
    assert r["threat_score"] >= 65.0
    assert "High risk" in r["reputation"]
    f_ids = {f["id"] for f in r["findings"]}
    assert "FND-DOM-TYPO" in f_ids or "FND-DOM-IMPERSONATION" in f_ids
    # External checks properly present with sources and Not Verified statuses
    checks_map = {c["source"]: c["status"] for c in r["blacklist"].get("checks", [])}
    assert checks_map.get("Google Safe Browsing") == "Not Verified"
    assert checks_map.get("VirusTotal") == "Not Verified"

def test_official_apple_and_icloud_are_legitimate():
    r_apple = analyze_url("https://www.apple.com")
    assert r_apple["classification"] == "Legitimate"
    assert r_apple["threat_score"] <= 18.0
    assert "Official Apple" in r_apple["reputation"]

    r_icloud = analyze_url("https://www.icloud.com")
    assert r_icloud["classification"] == "Legitimate"
    assert r_icloud["threat_score"] <= 18.0
    assert "Official Apple iCloud" in r_icloud["reputation"]

def test_mp3raid_media_download_is_suspicious_with_distinct_findings():
    r = analyze_url("https://mp3raid.com/music/krizz_kaliko.html")
    assert r["classification"] == "Suspicious"
    assert r["threat_score"] >= 30.0
    f_ids = {f["id"] for f in r["findings"]}
    assert "FND-DOM-THIRD-PARTY" in f_ids
    assert "FND-PATH-MEDIA-DOWNLOAD" in f_ids
    rec_ids = {rec["id"] for rec in r["recommendations"]}
    assert "REC-DOM-THIRD-PARTY" in rec_ids
    assert "REC-PATH-MEDIA-DOWNLOAD" in rec_ids

def test_mits_official_apex_verification():
    r = analyze_url("https://mits.ac.in/")
    assert r["classification"] == "Legitimate"
    assert r["threat_score"] <= 18.0
    inst = r.get("institutional", {})
    assert inst.get("category") == "Officially Verified Institutional Domain"
    assert "Officially Verified" in inst.get("status")
    assert "Madanapalle Institute of Technology & Science" in inst.get("institution_name", "")
    f_ids = {f["id"] for f in r["findings"]}
    assert "FND-INST-VERIFIED" in f_ids
    rec_ids = {rec["id"] for rec in r["recommendations"]}
    assert "REC-INST-VERIFIED" in rec_ids
    # Verify authoritative domain age >= 18y (registered 2007-01-23)
    assert r["domain"]["age_days"] >= 6000
    assert "19y" in r["domain"]["age_display"] or "18y" in r["domain"]["age_display"]

def test_mits_moodle_subdomain_verification():
    r = analyze_url("https://mitsmoodle.mits.ac.in/")
    assert r["classification"] == "Legitimate"
    assert r["threat_score"] <= 30.0
    inst = r.get("institutional", {})
    assert inst.get("category") == "Verified Institutional Subdomain"
    assert "Moodle" in inst.get("service", "")
    f_ids = {f["id"] for f in r["findings"]}
    assert "FND-INST-SUBDOMAIN" in f_ids
    rec_ids = {rec["id"] for rec in r["recommendations"]}
    assert "REC-INST-SUBDOMAIN" in rec_ids
    f_sub = next(f for f in r["findings"] if f["id"] == "FND-INST-SUBDOMAIN")
    assert "4.4.2" in f_sub["evidence"]

def test_mits_lookalike_combosquat_detection():
    r = analyze_url("https://mits-ac.in/")
    assert r["classification"] in {"Suspicious", "Phishing"}
    assert r["threat_score"] >= 65.0
    inst = r.get("institutional", {})
    assert inst.get("category") == "Potential MITS Lookalike Domain"
    f_ids = {f["id"] for f in r["findings"]}
    assert "FND-INST-LOOKALIKE" in f_ids
    rec_ids = {rec["id"] for rec in r["recommendations"]}
    assert "REC-INST-LOOKALIKE" in rec_ids

def test_mits_impersonation_phishing_detection():
    r = analyze_url("http://mitsmoodle-login.xyz/verify")
    assert r["classification"] == "Phishing"
    assert r["threat_score"] >= 85.0
    inst = r.get("institutional", {})
    assert inst.get("category") == "Known Malicious or Impersonated Domain"
    f_ids = {f["id"] for f in r["findings"]}
    assert "FND-INST-IMPERSONATION" in f_ids
    rec_ids = {rec["id"] for rec in r["recommendations"]}
    assert "REC-INST-IMPERSONATION" in rec_ids

def test_mits_distinct_entity_disambiguation():
    r = analyze_url("https://mgmits.ac.in/")
    inst = r.get("institutional", {})
    assert inst.get("category") == "Unverified MITS-Related Domain"
    f_ids = {f["id"] for f in r["findings"]}
    assert "FND-INST-DISTINCT" in f_ids
    rec_ids = {rec["id"] for rec in r["recommendations"]}
    assert "REC-INST-DISTINCT" in rec_ids
    f_distinct = next(f for f in r["findings"] if f["id"] == "FND-INST-DISTINCT")
    assert "Muthoot" in f_distinct["evidence"] or "distinct" in f_distinct["explanation"].lower()

def test_dashboard_full_history_and_schema():
    from services.database import dashboard_data
    data = dashboard_data()
    assert "recent" in data
    assert "metrics" in data
    assert isinstance(data["recent"], list)
    assert isinstance(data["metrics"], dict)

def test_pdf_report_build_with_numbered_canvas():
    from services.report import build_pdf
    sample_scan = {
        "id": 999,
        "url": "https://mits.ac.in/",
        "domain": {
            "status": "Known",
            "age_display": "19y 300d",
            "creation_date": "2007-01-23",
            "age_days": 7236,
            "registered_domain": "mits.ac.in",
            "source": "RDAP (ERNET India)"
        },
        "timestamp": "2026-11-15 08:30:00",
        "threat_score": 12.0,
        "classification": "Legitimate",
        "reputation": "Officially Verified Institutional Domain",
        "whois": {"age_human": "19y 300d", "created_raw": "2007-01-23", "age_days": 7236},
        "ssl": {"status": "Valid", "subject": "mits.ac.in", "issuer": "Let's Encrypt", "days_remaining": 85},
        "dns": {"status": "Resolved", "ips": ["104.21.55.2"]},
        "blacklist": {"status": "Clean", "checks": [
            {"source": "Local Signature Threat Blocklist", "status": "Clean", "timestamp": "2026-11-15 08:30:00", "details": "Domain not present"},
            {"source": "Google Safe Browsing", "status": "Not Verified", "timestamp": "2026-11-15 08:30:00", "details": "API key unconfigured"},
            {"source": "VirusTotal", "status": "Not Verified", "timestamp": "2026-11-15 08:30:00", "details": "API key unconfigured"}
        ]},
        "findings": [
            {"id": "FND-INST-VERIFIED", "title": "Officially Verified Institutional Domain", "severity": "Informational",
             "component": "Institutional Boundary", "evidence": "Official MITS domain", "explanation": "Verified.", "action_plan": "Access verified.", "recommendation_id": "REC-INST-VERIFIED"}
        ],
        "recommendations": [
            {"id": "REC-INST-VERIFIED", "finding_id": "FND-INST-VERIFIED", "title": "Access Official MITS Institutional Portal",
             "risk": "Minimal risk.", "action": "Ensure HTTPS."}
        ],
        "features": {"url_length": 19, "host_length": 10, "path_length": 1, "dots": 2, "hyphens": 0, "digits": 0, "is_ip": 0, "has_at": 0, "is_https": 1, "suspicious_keyword": 0, "brand_typosquat": 0, "shortened": 0, "entropy": 3.2, "dns_resolved": 1},
        "institutional": {
            "verified": True,
            "category": "Officially Verified Institutional Domain",
            "institution_name": "Madanapalle Institute of Technology & Science (MITS)",
            "official_website": "https://mits.ac.in/",
            "evidence": "Primary institutional domain registered via ERNET India.",
            "status": "Officially Verified"
        }
    }
    pdf_buf = build_pdf(sample_scan)
    pdf_bytes = pdf_buf.getvalue()
    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 1000
    assert pdf_bytes.startswith(b"%PDF")



