# Advanced Phishing Detection and Threat Intelligence System

Final-year major cybersecurity project by **DEVARA SANDHYA**.

PhishGuard analyzes HTTP/HTTPS URLs using explainable lexical machine learning plus URL structure, suspicious keywords, WHOIS age, DNS safety, TLS certificate validation, HTTPS checks, shortener/IP-host detection, and optional Google Safe Browsing and VirusTotal intelligence. Results are saved to SQLite, visualized on a dashboard, and exportable as PDF reports.

## Important accuracy statement

The included model is trained on a deterministic corpus spanning credential theft, urgency/fear manipulation, rewards, billing, delivery, tax/refund, crypto, employment scams, brand impersonation, IP hosts, shorteners, Punycode, deep subdomains, deceptive TLDs, ambiguous URLs, and legitimate hard-negative account/security routes. Its reported holdout score measures only those generated patterns and **must not be presented as real-world phishing accuracy**. For a defensible academic evaluation, replace or extend the corpus with timestamped, independently sourced benign and phishing URLs (for example PhishTank/OpenPhish plus Tranco), remove duplicates and domain leakage, then evaluate on an unseen time-based test set. Live blacklist checks require API keys.

## Features

- Normalized URL validation restricted to HTTP/HTTPS
- 20 explainable lexical/domain features and Random Forest classification trained on 1,366 pattern examples
- Hybrid weighted risk score with reasons and recommendations
- WHOIS domain age and TLS certificate checks with safe network timeouts
- Protection against private/local address probing in live TLS checks
- Optional Google Safe Browsing and VirusTotal reputation integrations
- Built-in editable local domain blacklist for default offline screening
- Correct special handling of official AMTSO phishing test pages
- SQLite scan history, dashboard chart, JSON API, and PDF reports
- Responsive, original CSS interface; no broken emoji/encoding characters

## Setup (Windows PowerShell)

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt
Copy-Item .env.example .env
python app.py
```

Open `http://127.0.0.1:5000`. Environment values are read by the host environment; load `.env` through your deployment service or set values before starting.

Python 3.11 through 3.14 is supported. The dependency versions include Windows wheels for Python 3.14, avoiding local NumPy/scikit-learn compilation.

## Retrain and test

```powershell
python train_model.py
python -m pytest -q
```

The trained artifact is stored in `models/url_classifier.joblib`. Delete it or run the trainer after changing feature logic.

## Default blacklist & threat intelligence

`data/blacklist.txt` provides extensive offline blacklist screening without requiring external API keys. It supports hostnames, subdomains, full URLs, and specific paths. When a URL is scanned, it is cross-referenced against the local blacklist, brand typosquatting rules, and any configured live feeds (Google Safe Browsing, VirusTotal). If listed, threat score is elevated to high severity and marked as `Listed (Threat Match)`.

You can also manage the blacklist directly via the web UI at `/blacklist`, or use the **+ Add to Blacklist** button on the result screen to blacklist newly identified phishing domains with one click.

## JSON API

`POST /api/analyze` with JSON: `{"url":"https://example.com"}`. Other routes: `/`, `/dashboard`, `/blacklist`, `/report/<id>.pdf`, and `/health`.

## Folder structure

```text
app.py                    Flask application and routes
config.py                 Environment-based configuration
services/                 Analysis, ML, intelligence, database, reports
templates/                Jinja user interface
static/css, static/js     Responsive styling and dashboard behavior
tests/                    Automated security and regression tests
docs/                     Design, diagrams, testing and deployment
instance/                 Generated SQLite database
models/                   Generated trained model
```

## Production deployment

See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md). Never commit API keys. This system is a triage aid: a low score does not prove that a URL is safe, and URLs should not be opened during analysis.
