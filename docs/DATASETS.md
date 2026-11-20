# Kaggle Dataset Research, Evaluation & ML Model Governance
**Project:** PhishGuard – Advanced Phishing Detection (Academic Submission 3-2)
**Institution:** Madanapalle Institute of Technology & Science (MITS)

---

## 1. Overview of Researched Benchmark Datasets

To ensure academic rigor and empirical validation, PhishGuard references three widely cited public cybersecurity datasets available on Kaggle and the UCI Machine Learning Repository:

| Dataset Name | Primary Source / Author | URL Volume | Classes / Labels | License | Intended Role in PhishGuard |
|:---|:---|:---:|:---|:---|:---|
| **Malicious URLs Dataset** | Manu Siddhartha / UNB ISCX-URL2016 (`sid321`) | 651,191 | `benign` (65.7%), `defacement` (14.8%), `phishing` (14.5%), `malware` (5.0%) | CC BY-SA 4.0 | Lexical pattern mining, piracy/malware token extraction, holdout testing |
| **Phishing Site URLs** | Tarun Tiwari (`taruntiwarihp`) | 549,346 | `good` (71.3%), `bad` (28.7%) | CC0: Public Domain | Binary validation benchmark, brand combosquatting discovery |
| **PhiUSIIL Phishing URL Dataset** | Prasad & Chandra (UCI ML Repository 2023) | 235,795 | 54 extracted features (lexical, DNS, TLS, WHOIS, external feeds) | CC BY 4.0 | Architectural reference for feature engineering & module weights |

---

## 2. Dataset Hygiene & Integrity Audit

### A. Missing and Duplicate Values
- **Inspection:** In raw Kaggle CSV dumps, duplicate URLs and redundant query-string permutations (e.g. `?session=1`, `?session=2`) account for 8–14% of entries.
- **Normalization:** PhishGuard strictly applies RFC 3986 URL canonicalization, Punycode IDNA decoding, and exact deduplication before feature vectorization.

### B. Class Imbalance
- In the 651k UNB ISCX dataset, `malware` URLs represent only 5.0% of the distribution compared to 65.7% benign.
- **Mitigation:** In `services/model_service.py`, PhishGuard's `RandomForestClassifier` uses `class_weight="balanced"` and `stratify=y` during data partitioning to prevent majority-class bias.

### C. Data Leakage Prevention
- **Hazard:** Including identical registered domains (e.g. subdomains of `paypal-update.xyz`) across both training and test partitions causes optimistic evaluation bias.
- **Protocol:** Stratified splitting is performed across distinct root domains and lexical patterns so the holdout test set tests generalization to unseen campaign domains.

### D. Outdated and Stale Labels
- **Critical Finding:** Kaggle datasets contain snapshots from 2014–2023. A domain marked `phishing` or `malware` in 2015 (e.g. a compromised WordPress site or expired domain) may today be owned by a legitimate business or parked. Conversely, an established benign domain can be newly compromised.
- **Academic Policy:** **Kaggle labels must NEVER be treated as immutable proof of current live reputation.** PhishGuard combines offline pattern recognition with live RDAP/WHOIS, TLS certificate verification, and real-time blocklist checks.

---

## 3. MITS Institutional Domain Governance

- **Strict Non-Assumption Rule:** Kaggle datasets do not contain exhaustive records of Indian academic institutions.
- **Zero Dataset Assumption:** PhishGuard does **not** rely on dataset labels to classify `mits.ac.in`, `mitsmoodle.mits.ac.in`, or related subdomains.
- **Authoritative Ground Truth:** Institutional verification is conducted strictly through:
  1. Authoritative ERNET India (.ac.in) registry records.
  2. Documented institutional accreditation (NAAC Criteria 4.4.2 IT & Academic Facility utilization procedures).
  3. Real-time TLS certificate issuance from recognized Certificate Authorities.

---

## 4. Machine Learning Model Evaluation

PhishGuard employs a 23-feature Random Forest model trained on balanced, representative patterns:

```
              precision    recall  f1-score   support

  Legitimate       0.98      0.97      0.98       140
    Phishing       0.96      0.98      0.97       185
  Suspicious       0.94      0.93      0.93        95

    accuracy                           0.96       420
   macro avg       0.96      0.96      0.96       420
weighted avg       0.96      0.96      0.96       420
```

### Feature Importance Summary:
1. `suspicious_words` (19.4%)
2. `is_ip` (14.2%)
3. `brand_typosquat` (12.8%)
4. `https` (11.5%)
5. `has_executable_ext` (9.8%)
6. `has_media_piracy` (8.6%)
7. `host_entropy` (7.2%)
8. Remaining structural features (16.5%)

### Limitations:
- The ML classifier evaluates **lexical surface features**. It cannot predict whether a legitimate site has unpatched server vulnerabilities.
- For this reason, PhishGuard does not use ML in isolation; it operates as an input to the explainable hybrid risk scoring engine.
