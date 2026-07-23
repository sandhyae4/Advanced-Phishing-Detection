# Architecture and database design

## Data-flow diagram (Level 1)

```mermaid
flowchart LR
  U[User / Analyst] -->|URL| W[Flask Web Application]
  W --> V[URL Validation & Normalization]
  V --> F[Lexical Feature Engine]
  V --> T[Threat Intelligence Engine]
  F --> M[Random Forest Model]
  T --> D[DNS / WHOIS / TLS]
  T --> B[Safe Browsing / VirusTotal]
  M --> S[Hybrid Risk & Explanation Engine]
  D --> S
  B --> S
  S --> DB[(SQLite Scan Store)]
  S --> R[Result View]
  DB --> A[Dashboard]
  DB --> P[PDF Report]
  R --> U
  A --> U
  P --> U
```

## Use-case diagram

```mermaid
flowchart LR
  Analyst((Security Analyst)) --> Analyze[Analyze a URL]
  Analyst --> Dashboard[Review threat dashboard]
  Analyst --> History[Inspect scan history]
  Analyst --> Report[Download assessment PDF]
  Admin((Administrator)) --> Configure[Configure threat API keys]
  Admin --> Train[Retrain and evaluate model]
  Analyze --> Checks[Run security modules]
  Analyze --> Classify[Classify and score risk]
  Report --> History
```

## Database schema

The `scans` table stores normalized URL, final classification and scores, summarized intelligence status, JSON findings/recommendations, the complete result JSON, and UTC creation time. Indexes cover time-ordered history and classification aggregation. Schema creation is idempotent in `services/database.py`.

## Scoring design

The final score is not simply the model probability. It weights URL structure (18%), keywords (14%), domain intelligence (12%), transport/TLS (13%), reputation (25%), and ML output (18%). A positive configured blacklist result raises risk to at least 90. Thresholds are: Legitimate below 30, Suspicious from 30 to 64.9, and Phishing from 65. AMTSO official test paths are explicitly classified as Security Test before ordinary scoring.

