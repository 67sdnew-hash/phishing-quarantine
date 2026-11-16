# Contributing to PhishGuard SOC

Thank you for your interest in contributing to **PhishGuard SOC**! Whether you are reporting a bug, improving documentation, designing threat heuristics, or optimizing machine learning classifiers, your contributions are welcome.

---

## Code of Conduct

We are committed to providing a welcoming, inclusive, and harassment-free environment for everyone. Please be respectful, constructive, and collaborative in all discussions and pull requests.

---

## Development Setup

### 1. Prerequisites
- Python 3.11 or higher
- Git
- (Optional) Redis (for testing async Celery worker queues)

### 2. Local Environment
```bash
# Clone your fork
git clone https://github.com/<your-username>/phishing-quarantine.git
cd phishing-quarantine

# Create and activate virtual environment
python -m venv venv

# Windows (PowerShell)
.\venv\Scripts\Activate.ps1
# Linux / macOS
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run migrations and seed SOC demo data
python manage.py migrate
python manage.py seed_soc_data

# Start local server
python manage.py runserver
```

---

## Running Quality Checks & Tests

Before submitting a Pull Request, verify that all Django system checks and automated tests pass:

```bash
# Django configuration & model check
python manage.py check

# Run complete test suite (scanner app)
python manage.py test scanner
```

---

## Contribution Guidelines

1. **Branch Naming**:
   - `feat/feature-name` for new capabilities or heuristics
   - `fix/bug-description` for bug fixes
   - `docs/topic-name` for documentation enhancements
2. **Coding Standards**:
   - Follow **PEP 8** formatting conventions.
   - Include type annotations on new functions and methods where appropriate.
   - Ensure explainability logic and security heuristics in `scanner/ml/` have corresponding unit tests in `scanner/tests.py`.
3. **Frontend Guidelines**:
   - Any design enhancements should adhere to the established soft, glassmorphic SOC design system (CSS custom properties in `soc.css`).
   - All interactive controls must support keyboard navigation, ARIA attributes, and `prefers-reduced-motion`.
4. **Submitting a Pull Request**:
   - Provide a clear and descriptive PR title and summary.
   - Link related issue numbers (e.g., `Closes #12`).
   - Verify that GitHub Actions CI passes without warnings.
