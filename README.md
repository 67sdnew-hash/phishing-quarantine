<div align="center">

# 🛡️ PhishGuard SOC

### Enterprise Phishing Detection, Explainable NLP & Automated Quarantine System

[![CI Build](https://github.com/67sdnew-hash/phishing-quarantine/actions/workflows/ci.yml/badge.svg)](https://github.com/67sdnew-hash/phishing-quarantine/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/Python-3.11%20%7C%203.12-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Django](https://img.shields.io/badge/Django-4.2%20%7C%205.x-092E20?logo=django&logoColor=white)](https://www.djangoproject.com/)
[![Scikit-Learn](https://img.shields.io/badge/scikit--learn-F7931E?logo=scikit-learn&logoColor=white)](https://scikit-learn.org/)
[![Celery](https://img.shields.io/badge/Celery-Task%20Queue-37814A?logo=celery&logoColor=white)](https://docs.celeryq.dev/)
[![Render](https://img.shields.io/badge/Deploy-Render-46E3B7?logo=render&logoColor=black)](https://github.com/67sdnew-hash/phishing-quarantine/deployments/main%20-%20phishguard-soc)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

<p align="center">
  <b>Ingest suspicious messages · Fuse heuristic threat indicators · Calibrate machine learning probabilities · Explain triggering tokens · Automate SOC incident quarantine</b>
</p>

[**🚀 Live Deployment**](https://github.com/67sdnew-hash/phishing-quarantine/deployments/main%20-%20phishguard-soc) • [**📖 Architecture**](#-system-architecture) • [**⚡ Quickstart**](#-quickstart) • [**🔌 REST API**](#-rest-api-reference) • [**🐳 Docker**](#-docker--docker-compose) • [**🤝 Contributing**](CONTRIBUTING.md)

</div>

---

## 📌 Executive Summary

Modern adversary campaigns bypass traditional email filters by combining subtle display-name spoofing, brand typosquatting, shortener redirections, and coercive social engineering triggers. 

**PhishGuard SOC** is an open-source, enterprise-grade Security Operations Center (SOC) defense application. Built with **Django**, **scikit-learn**, and **Celery**, it ingests suspicious emails across multiple vectors, applies a **dense signal fusion transformer** alongside **TF-IDF N-grams**, classifies threats via **Calibrated LinearSVC**, delivers **white-box token explainability**, and immediately triggers simulated quarantine incidents for security analysts.

---

## ✨ Key Capabilities

| Capability | Technical Implementation |
| :--- | :--- |
| **Multi-Vector Ingestion** | Web triage form with 1-click attack presets, raw RFC-822 `.eml` MIME parsing, CSV batch upload, and programmatic REST API. |
| **Signal Fusion Engine** | Feature transformers extracting display-name spoofing, Levenshtein brand typosquatting, high-risk TLDs, IP hosts, URL shorteners, and BEC urgency cues. |
| **Calibrated ML Pipeline** | `FeatureUnion` combining character/word TF-IDF n-grams with 12+ structured threat features into `LinearSVC` calibrated via isotonic regression. |
| **Explainable NLP** | White-box coefficient scoring mapping token contribution deltas, rendering interactive inline highlighted spans with hover tooltips across sender, subject, and body. |
| **Automated Quarantine** | Instant risk scoring (0–100) generating triage incidents, MITRE ATT&CK tags, and status tracking (Pending Review, Released, Remediated). |
| **Enterprise SOC Interface** | Spatial micro-interaction dashboard featuring 4 soft curated color palettes (Obsidian Dark, Opal Light, Midnight Indigo, Emerald Matrix) and 3.5° subtle 3D parallax tilt. |

---

## 🏛️ System Architecture

```
                    ┌────────────────────────────────────────────────────────┐
                    │               SUSPICIOUS EMAIL INGESTION               │
                    │  [Web Form]   [RFC-822 .eml]   [CSV Batch]   [REST API]│
                    └───────────────────────────┬────────────────────────────┘
                                                │
                                                ▼
┌────────────────────────────────────────────────────────────────────────────────────────────┐
│                                DENSE SIGNAL EXTRACTION LAYER                                │
│                                                                                            │
│   ┌──────────────────────────┐ ┌──────────────────────────┐ ┌──────────────────────────┐  │
│   │ SENDER SPOOFING ENGINE   │ │ URL HEURISTICS ENGINE    │ │ URGENCY & SOCIAL ENGIN.  │  │
│   │ • Display vs RFC header  │ │ • Direct IP address host │ │ • Coercion deadline cues │  │
│   │ • Brand typosquatting    │ │ • URL shortener triage   │ │ • Credential bait terms  │  │
│   │ • High-risk/toxic TLDs   │ │ • Credential paths       │ │ • Executive BEC keywords │  │
│   └──────────────────────────┘ └──────────────────────────┘ └──────────────────────────┘  │
└───────────────────────────────────────────────┬────────────────────────────────────────────┘
                                                │
                                                ▼
┌────────────────────────────────────────────────────────────────────────────────────────────┐
│                           FEATURE UNION & MACHINE LEARNING PIPELINE                         │
│                                                                                            │
│       Word & Char TF-IDF N-grams (1-2)    +    Standardized Heuristic Signal Vectors       │
│                                           │                                                │
│                                           ▼                                                │
│                              Dual-Faceted FeatureUnion                                     │
│                                           │                                                │
│                                           ▼                                                │
│                           Support Vector Classifier (LinearSVC)                            │
│                                           │                                                │
│                                           ▼                                                │
│                       Platt Scaling / CalibratedClassifierCV                               │
│                   [ Safe: P(S) ]   [ Spam: P(M) ]   [ Phishing: P(P) ]                     │
└───────────────────────────────────────────────┬────────────────────────────────────────────┘
                                                │
                                                ▼
┌────────────────────────────────────────────────────────────────────────────────────────────┐
│                               EXPLAINABILITY & INCIDENT TRIAGE                             │
│                                                                                            │
│   ┌────────────────────────────────────────┐  ┌────────────────────────────────────────┐   │
│   │ WHITE-BOX TOKEN EXPLAINABILITY         │  │ SOC RESPONSE & QUARANTINE ENGINE       │   │
│   │ • Per-token weight contribution        │  │ • Automated quarantine creation (>60)  │   │
│   │ • Inline visual span highlighter       │  │ • Celery background worker scan queue  │   │
│   │ • Contextual interactive tooltips      │  │ • Audit logging & disposition tracking │   │
│   └────────────────────────────────────────┘  └────────────────────────────────────────┘   │
└────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 🎨 Enterprise UI & Theme System

PhishGuard SOC includes a purpose-built, human-crafted design system engineered without harsh neon wireframes or artificial overlays:

- **🌙 Obsidian Dark (Default):** Soft obsidian charcoal (`#0a0b10`), slate card surfaces (`#12141d`), soft iris primary (`#818cf8`), muted rose threat indicators (`#fb7185`), and mint safe states (`#34d399`).
- **☀️ Opal Light:** Crisp high-contrast enterprise daylight palette (`#f8fafc`), pure card backgrounds (`#ffffff`), and deep indigo accents (`#4f46e5`).
- **🌌 Midnight Indigo:** Oceanic twilight atmosphere (`#070a14`) with sapphire and lavender accents.
- **🌿 Emerald Matrix:** Muted obsidian pine (`#06110f`) paired with soft terminal sage (`#34d399`).

All modes include responsive mobile drawers, keyboard accessibility shortcuts (`/` focuses search, `Esc` dismisses menus), reduced-motion compliance (`prefers-reduced-motion`), and soft specular card tilting.

---

## ⚡ Quickstart

### 1. Clone & Activate Virtual Environment

```bash
# Clone the repository
git clone https://github.com/67sdnew-hash/phishing-quarantine.git
cd phishing-quarantine

# Create virtual environment
python -m venv venv

# Windows (PowerShell)
.\venv\Scripts\Activate.ps1

# Linux / macOS
source venv/bin/activate
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Initialize Database & Seed SOC Data

```bash
# Apply database migrations
python manage.py migrate

# Seed realistic SOC demonstration incidents and threat templates
python manage.py seed_soc_data
```

### 4. Run Development Server

```bash
python manage.py runserver
```

Navigate to `http://127.0.0.1:8000/` in your browser. The ML pipeline will automatically train its initial model bundle on first run if no pre-existing artifacts are found.

---

## 🐳 Docker & Docker Compose

Deploy the complete stack—including **Django Web App**, **Redis**, and an asynchronous **Celery Worker**—with a single command:

```bash
# Build and start all services
docker compose up -d --build

# View container logs
docker compose logs -f

# Stop containers
docker compose down
```

The web interface will be available at `http://localhost:8000`.

---

## 🔌 REST API Reference

PhishGuard exposes a high-throughput, JSON-native scanning endpoint for integration into email security gateways, SIEM pipelines, and SOAR playbooks.

### `POST /api/scan/`

#### Request Headers
```http
Content-Type: application/json
```

#### Request Payload
```json
{
  "sender": "Security Team <security-alert@micr0soft-support.com>",
  "subject": "CRITICAL: Office 365 Password Expires in 2 Hours",
  "body": "Dear Employee,\n\nYour session has expired. Click here to verify your account immediately: http://192.168.1.105/auth/login?user=target\nFailure to comply will result in account suspension."
}
```

#### Response Payload (`200 OK`)
```json
{
  "status": "success",
  "scan_id": 42,
  "label": "Phishing",
  "risk_score": 98.4,
  "probabilities": {
    "Phishing": 0.942,
    "Spam": 0.051,
    "Safe": 0.007
  },
  "is_quarantined": true,
  "quarantine_id": 18,
  "features": {
    "domain_mismatch": {
      "detected": true,
      "claimed": "micr0soft-support.com",
      "actual": "micr0soft-support.com",
      "reason": "Typosquatting permutation of target brand 'microsoft'"
    },
    "urls_found": [
      {
        "url": "http://192.168.1.105/auth/login?user=target",
        "risk": 90,
        "is_ip": true,
        "is_https": false,
        "is_shortener": false
      }
    ],
    "urgency_keywords": ["immediately", "expires", "critical"],
    "credential_keywords": ["password", "verify", "account", "login"]
  },
  "top_contributing_tokens": [
    { "term": "micr0soft", "weight": 2.41 },
    { "term": "verify account", "weight": 1.89 },
    { "term": "expires in", "weight": 1.42 }
  ]
}
```

---

## 🧪 Automated Testing & Verification

PhishGuard maintains test coverage for the full ingestion pipeline, heuristics engine, explainability generator, and Celery tasks.

Run the test suite:
```bash
python manage.py test scanner --verbosity 2
```

Run Django system configuration verification:
```bash
python manage.py check
```

---

## ⚙️ Configuration & Environment Variables

Create a `.env` file in the repository root to configure operational settings:

| Variable | Default | Purpose |
| :--- | :--- | :--- |
| `DJANGO_DEBUG` | `True` | Toggle debug mode (`False` in production) |
| `DJANGO_SECRET_KEY` | *(insecure-dev)* | Cryptographic signing key |
| `DJANGO_ALLOWED_HOSTS` | `localhost,127.0.0.1` | Comma-separated list of allowed hostnames |
| `DJANGO_CSRF_TRUSTED_ORIGINS` | *(empty)* | Comma-separated list of trusted origins (`https://*.onrender.com`) |
| `CELERY_ALWAYS_EAGER` | `True` | Execute tasks synchronously without external broker (ideal for dev) |
| `CELERY_BROKER_URL` | `redis://localhost:6379/0` | Message broker connection string for async mode |
| `CELERY_RESULT_BACKEND` | `redis://localhost:6379/0` | Result backend connection string |

---

## ☁️ Cloud Deployment

### Deploy to Render

PhishGuard contains an automated blueprint (`render.yaml`):

1. Fork or push this repository to GitHub.
2. In the Render Dashboard, click **New + -> Blueprint**.
3. Select your repository. Render will automatically configure the Python environment, static collection, database migrations, and healthcheck path.

---

## 🛡️ Security & Responsible Disclosure

We take the security of defensive tooling seriously. Please review our [Security Policy](SECURITY.md) for details on our threat model, sanitization guarantees, and instructions for reporting vulnerabilities.

---

## 🤝 Contributing

Contributions, feature suggestions, and bug reports are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) to get started with our development guidelines and pull request process.

---

## 📄 License

This project is licensed under the terms of the [MIT License](LICENSE).

<div align="center">
<sub>Crafted with precision for enterprise Security Operations Center teams.</sub>
</div>
