# PhishGuard SOC — Phishing Email & Malicious URL Quarantine System

An enterprise Django + scikit-learn + Celery web application that ingests employee-reported suspicious emails, extracts domain/URL/urgency threat signals, classifies messages as **Safe**, **Spam**, or **Phishing** using **TF-IDF + LinearSVC**, highlights exact triggering words and URLs with **Explainable NLP**, and triggers simulated SOC quarantine alerts for high-risk threats.

## Key Capabilities
- **Multi-Channel Email Ingestion**: Manual forwarded email form (with 1-click demo threat presets), raw RFC-822 `.eml` parser/uploader, bulk CSV batch ingestion, and JSON REST API (`POST /api/scan/`).
- **Feature Extraction Engine** (`scanner/ml/features.py`):
  - **Sender Domain Mismatch & Spoofing**: Detects display-name brand impersonation, typosquatting (`micr0soft`, `app1e`, `wellsfarg0`), executive BEC via free webmail, and high-risk TLDs (`.xyz`, `.tk`, `.top`, `.click`, `.ru`).
  - **Malicious URL Inspection**: Flags direct IP hosts, URL shorteners (`bit.ly`, `tinyurl.com`), unencrypted HTTP, credential harvesting paths (`/login`, `/auth`, `/reset`), and suspicious TLDs.
  - **Urgency & Social Engineering Cues**: Extracts coercion/deadline triggers and financial/credential bait phrases.
- **Explainable NLP** (`scanner/ml/explainer.py`): White-box `LinearSVC` TF-IDF token contribution scoring combined with highlighted inline spans across sender, subject, and body with hover tooltips.
- **Celery Background Scanning & Simulated Quarantine Alerts** (`scanner/tasks.py`): Runs scans via Celery (`CELERY_ALWAYS_EAGER=True` by default for zero-setup local use; set `CELERY_ALWAYS_EAGER=False` with Redis for async workers) and creates `QuarantineAlert` records for high-risk detections.

## Quickstart

```powershell
cd phishing-quarantine
.\venv\Scripts\activate
python manage.py migrate
python manage.py seed_soc_data
python manage.py runserver
```

Then open `http://127.0.0.1:8000/`.

### Optional: Async Celery Worker Mode (with Redis)
Set `CELERY_ALWAYS_EAGER=False` and `CELERY_BROKER_URL=redis://localhost:6379/0` in `.env`, then run:
```powershell
celery -A config worker -l info
```

### Run Automated Tests
```powershell
python manage.py test scanner
```

## Deploy to Render (Free Tier)
The repo includes `render.yaml` and `.gitignore` ready for Render Blueprints or manual Web Service deployment:
1. Push the `phishing-quarantine` folder to a GitHub repository.
2. In Render, click **New + -> Blueprint** (to use `render.yaml` automatically) or **New + -> Web Service** with:
   - **Build Command:** `pip install -r requirements.txt && python manage.py collectstatic --noinput`
   - **Start Command:** `python manage.py migrate --noinput && python manage.py seed_soc_data && gunicorn config.wsgi:application --bind 0.0.0.0:$PORT --workers 2 --timeout 120`
   - **Environment Variables:** `DJANGO_DEBUG=False`, `DJANGO_SECRET_KEY=<random>`, `CELERY_ALWAYS_EAGER=True`, `PYTHON_VERSION=3.11.9`

