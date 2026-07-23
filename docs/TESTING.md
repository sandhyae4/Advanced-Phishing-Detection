# Testing documentation

## Automated tests

Run `python -m pytest -q`. Tests cover AMTSO regression behavior, IP-host and HTTP findings, unsafe scheme rejection, and API validation. Add fixtures for database persistence, PDF output, timeout behavior, and each external provider before production rollout.

## Academic model evaluation protocol

1. Collect consent-compatible public feeds with timestamps and licenses; retain provenance.
2. Canonicalize URLs, remove duplicates, and prevent the same registrable domain appearing in train and test partitions.
3. Use a chronological split so newer campaigns are the test set.
4. Report confusion matrix, precision, recall, F1, ROC-AUC/PR-AUC, false-positive rate, and per-class sample counts.
5. Compare lexical ML, security rules, and hybrid ablations.
6. Test adversarial cases: Punycode, encoded paths, redirectors, compromised old domains, IPv6, user-info tricks, and benign long URLs.
7. Record feed retrieval date, model version, seed, configuration, and limitations.

Do not promise “100% accuracy.” Prioritize phishing recall while publishing the false-positive cost, and calibrate thresholds on a validation set rather than the final test set.

## Manual acceptance checklist

- Empty, oversized, FTP, JavaScript, and malformed inputs are rejected.
- Known AMTSO desktop/mobile phishing test paths show Security Test with score 0.
- Results remain readable on phone and desktop widths.
- Dashboard counts equal database records and PDF fields match the scan.
- Missing WHOIS/network/API services degrade to Unknown/Not configured without crashing.
- API keys never appear in pages, reports, source control, or logs.

