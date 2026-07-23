import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split
from config import MODEL_PATH
from services.features import vectorize

MODEL_VERSION = 9
_bundle = None


def _training_corpus():
    brands = ["google", "microsoft", "github", "wikipedia", "apple", "amazon", "paypal", "dropbox", "linkedin", "adobe", "chatgpt", "openai"]
    good_tlds = ["com", "org", "net", "io"]
    bad_tlds = ["xyz", "top", "click", "zip", "gq", "tk"]
    rows = []
    for brand in brands:
        for tld in good_tlds:
            rows += [(f"https://www.{brand}.{tld}/", "Legitimate"),
                     (f"https://{brand}.{tld}/help/account", "Legitimate"),
                     (f"https://docs.{brand}.{tld}/guide/security", "Legitimate")]
        for tld in bad_tlds:
            rows += [(f"http://{brand}-account-verify.{tld}/login?session=83921", "Phishing"),
                     (f"http://secure-{brand}-support.{tld}/restore/password", "Phishing"),
                     (f"https://{brand}.signin.confirm-user.{tld}/authenticate", "Phishing")]
    suspicious = [
        "http://account-suspended-check.net/restore", "http://security-alert.example.net/login",
        "https://new-wallet-support.site/verify", "http://invoice-download.work/document",
        "https://unusual-domain.xyz/", "http://192.0.2.10/login", "https://bit.ly/example",
        "https://xn--pple-43d.com/signin", "http://four.three.two.example.com/account"
    ]
    for base in suspicious:
        for suffix in ["", "?id=84219", "/confirm"]:
            rows.append((base + suffix, "Suspicious"))
    # Legitimate modern application routes often contain UUIDs, opaque IDs and
    # account-related words. These examples reduce false positives on SaaS URLs.
    application_routes = [
        "https://chatgpt.com/c/6a5879c9-3348-83ee-bdd9-178e5f016a50",
        "https://chatgpt.com/share/67b12c19-1234-8000-a111-abcdef123456",
        "https://chatgpt.com/g/g-example-project",
        "https://platform.openai.com/docs/guides/security",
        "https://platform.openai.com/settings/organization/api-keys",
        "https://github.com/example/project/issues/1234",
        "https://accounts.google.com/signin/v2/identifier",
        "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
    ]
    for route in application_routes:
        rows.extend([(route, "Legitimate")] * 6)
    phishing_simulations = [
        "http://paypal-login-secure.example/login", "http://verify-bank-account.example/update",
        "http://secure-google-login.example/signin", "http://microsoft-account-verify.example/login",
        "http://amazon-security-alert.example/verify", "http://apple-id-confirm.example/login",
        "http://facebook-security.example/auth", "http://netflix-billing-update.example/payment",
        "http://bank-login-check.example/verify", "http://192.168.1.100/login",
        "http://45.12.67.89/secure/login",
        "http://claim-your-prize.example", "http://winner-reward.example/claim",
        "http://free-gift.example/confirm", "http://urgent-giveaway.example/claim-prize",
    ]
    for route in phishing_simulations:
        rows.extend([(route, "Phishing")] * 6)

    # Look-alike domains with one-character insertion, deletion, substitution
    # or transposition. These samples specifically cover typosquatting that
    # exact keyword matching cannot detect.
    typo_domains = [
        "faceboook.com", "facbook.com", "faceb00k.com", "gooogle.com", "gogle.com",
        "micros0ft.com", "mircosoft.com", "paypa1.com", "paypl.com", "appple.com",
        "amaz0n.com", "netflx.com", "instagrarn.com", "whatsap.com", "githab.com",
        "openal.com", "chatgptt.com", "dropb0x.com", "linkedln.com",
    ]
    for domain in typo_domains:
        rows.extend([
            (f"http://{domain}", "Phishing"),
            (f"http://{domain}/login", "Phishing"),
            (f"https://{domain}/account/verify", "Phishing"),
        ] * 4)

    # Broad phishing taxonomy: combinations model campaign variation across
    # brands, manipulation language, paths, domain shapes and abused TLDs.
    target_brands = ["paypal", "google", "microsoft", "apple", "amazon", "facebook", "netflix",
                     "instagram", "whatsapp", "dropbox", "dhl", "fedex", "bank", "coinbase"]
    campaign_terms = ["verify-account", "urgent-security-alert", "password-expired", "account-suspended",
                      "unusual-login", "confirm-identity", "billing-overdue", "payment-failed",
                      "claim-refund", "parcel-delivery-fee", "complete-kyc", "wallet-recovery",
                      "claim-airdrop", "document-download", "winner-claim-prize", "job-offer-confirm"]
    attack_paths = ["/login", "/signin/confirm", "/account/update", "/auth/validate", "/payment/verify",
                    "/secure/session", "/restore/password", "/document/download", "/claim/reward"]
    abused_tlds = ["xyz", "top", "click", "zip", "work", "support", "gq", "tk"]
    for i, brand in enumerate(target_brands):
        for j, term in enumerate(campaign_terms):
            tld = abused_tlds[(i + j) % len(abused_tlds)]
            path = attack_paths[(i * 3 + j) % len(attack_paths)]
            rows.extend([
                (f"http://{brand}-{term}.{tld}{path}?session={i}{j}842", "Phishing"),
                (f"https://{brand}.{term}.user-check-{i}.{tld}{path}", "Phishing"),
                (f"http://secure-{term}-{brand}.{tld}{path}", "Phishing"),
            ])

    # Non-brand social engineering and technical obfuscation cases.
    manipulation = ["act-immediately", "final-warning", "access-will-expire", "account-disabled",
                    "unauthorized-activity", "limited-time", "identity-required", "refund-pending",
                    "delivery-on-hold", "tax-payment-overdue", "investment-profit", "lottery-winner"]
    for i, lure in enumerate(manipulation):
        rows.extend([
            (f"http://{lure}.click/login?token={i}99821", "Phishing"),
            (f"http://192.0.2.{10+i}/secure/{lure}/login", "Phishing"),
            (f"https://user.{lure}.confirm-details.xyz/account/verify", "Phishing"),
            (f"https://xn--{lure[:8]}-9za.example/signin", "Phishing"),
        ])
    for shortener in ["bit.ly", "tinyurl.com", "t.co", "cutt.ly", "tiny.cc"]:
        rows.extend([(f"https://{shortener}/{code}", "Suspicious") for code in ["A8k2Lm", "verify84", "pay-now"]])

    # Ambiguous URLs teach the middle class rather than forcing every unusual
    # hostname into Phishing.
    generic_hosts = ["new-customer-portal", "billing-review", "account-help", "document-service",
                     "member-support", "online-wallet", "delivery-status", "security-notice"]
    for i, name in enumerate(generic_hosts):
        rows.extend([
            (f"https://{name}.site/info", "Suspicious"),
            (f"http://{name}.net/account", "Suspicious"),
            (f"https://service.{name}.xyz/review?id={i}42", "Suspicious"),
        ])

    # Hard negatives: legitimate applications legitimately use sensitive words,
    # UUIDs, query strings, authentication and billing routes.
    trusted_apps = ["github.com", "google.com", "microsoft.com", "apple.com", "amazon.com", "paypal.com",
                    "openai.com", "chatgpt.com", "wikipedia.org", "dropbox.com", "linkedin.com"]
    benign_paths = ["/login", "/account/security", "/help/password-reset", "/billing/invoices",
                    "/support/verify-email", "/settings/authentication", "/docs/payment-api",
                    "/c/6a5879c9-3348-83ee-bdd9-178e5f016a50", "/search?q=account+security"]
    for domain in trusted_apps:
        for path in benign_paths:
            rows.extend([(f"https://{domain}{path}", "Legitimate"), (f"https://www.{domain}{path}", "Legitimate")])

    # Deduplicate exact URL/label pairs while preserving deterministic ordering.
    rows = list(dict.fromkeys(rows))
    return rows


def train_and_save():
    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    corpus = _training_corpus()
    X = np.array([vectorize(url) for url, _ in corpus], dtype=float)
    y = np.array([label for _, label in corpus])
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=.25, random_state=42, stratify=y)
    model = RandomForestClassifier(n_estimators=300, class_weight="balanced", min_samples_leaf=2,
                                   random_state=42, n_jobs=-1)
    model.fit(X_train, y_train)
    predicted = model.predict(X_test)
    metrics = {"holdout_accuracy": float(accuracy_score(y_test, predicted)),
               "classification_report": classification_report(y_test, predicted, output_dict=True, zero_division=0),
               "samples": len(corpus), "note": "Synthetic-pattern holdout; not a claim of real-world detection accuracy."}
    bundle = {"model": model, "metrics": metrics, "version": MODEL_VERSION}
    joblib.dump(bundle, MODEL_PATH)
    return bundle


def ensure_model():
    global _bundle
    if MODEL_PATH.exists():
        try:
            candidate = joblib.load(MODEL_PATH)
            if candidate.get("version") == MODEL_VERSION:
                _bundle = candidate
                return
        except Exception:
            pass
    _bundle = train_and_save()


def predict(url):
    if _bundle is None:
        ensure_model()
    model = _bundle["model"]
    probs = model.predict_proba([vectorize(url)])[0]
    probabilities = {label: round(float(p) * 100, 2) for label, p in zip(model.classes_, probs)}
    label = max(probabilities, key=probabilities.get)
    return label, probabilities
