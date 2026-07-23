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
