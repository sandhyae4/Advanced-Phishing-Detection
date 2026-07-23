# Deployment guide

## Production checklist

1. Provision Python 3.11+ and install `requirements.txt` in a virtual environment.
2. Set a long random `SECRET_KEY`; optionally set the two threat-intelligence keys.
3. Set `PHISHGUARD_DATABASE` to a persistent writable location and back it up.
4. Run behind a TLS-enabled reverse proxy. On Linux, start with `gunicorn -w 2 -b 127.0.0.1:8000 app:app`.
5. Restrict outbound access to DNS, WHOIS/RDAP, TCP 443, and approved intelligence APIs.
6. Add authentication/rate limiting before exposing scan history publicly.
7. Monitor latency, provider errors, model drift, false positives, disk space, and API quota.

For higher volume, replace SQLite with PostgreSQL and move WHOIS/TLS/provider calls into a job queue. Treat submitted URLs as sensitive telemetry and define retention/deletion rules. Do not visit submitted pages or execute their content.

