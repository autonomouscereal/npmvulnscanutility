# CxOne Python Reporter

> Lightweight helper to query the Checkmarx One (CxOne) REST API and generate reports.

This repository **migrates** the original PowerShell scripts (`apiTokenLogin.ps1`, etc.)
to Python 3. It provides:

* A tiny SDK (`cxone` package) that authenticates via **refresh token / PAT** and calls the REST API.
* A ready-to-use CLI script that produces a **CSV report** with all projects and their maturity level.
* An extensible structure for adding additional benchmarks and reports.

---

## 1. Features

| Feature | Status |
|---------|--------|
| Refresh-token authentication | ✅ |
| List projects | ✅ |
| Retrieve latest scans | ✅ |
| Fetch SAST results | ✅ |
| Maturity level CSV report | ✅ |
| `.env`-based configuration | ✅ |
| Extensibility hooks | 🔧 planned |

See `TODO.md` for the full roadmap.

---

## 2. Quick start

### 2.1. Prerequisites

* Python **3.9+**
* Internet connection to your CxOne instance
* A **Personal Access Token** (PAT) generated in the CxOne portal
* The tenant / realm name you want to query

### 2.2. Installation

```bash
# Clone the repository
git clone https://github.com/your-org/cxone-python-reporter.git
cd cxone-python-reporter

# (Optional) Create a virtual environment
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 2.3. Configure environment variables

1. Copy the template:

```bash
cp env.example .env
```

2. Open `.env` in your editor and fill in the values:

| Variable | Description | Example |
|----------|-------------|---------|
| `CXONE_TOKEN_BASE_URL` | Base URL for token endpoint **without** tenant segment | `https://cxone-preprod/auth/realms` |
| `CXONE_TENANT` | Tenant / realm name | `cxone-preprod` |
| `CXONE_REFRESH_TOKEN` | The PAT / refresh token copied from the portal | `xxxxxxxx-xxxx-...` |
| `CXONE_API_BASE_URL` | Base URL for the API **with** `/api/` suffix | `https://cxone-preprod/api/` |
| `CXONE_CLIENT_ID` | OAuth client ID – keep `ast-app` unless you have a custom app | `ast-app` |
| `CXONE_VERIFY_SSL` | `true` (default) or `false` to *skip* SSL verification – useful for self-signed certs | `false` |

> **Note**: `.env` is **excluded** from version control in `.gitignore`.

### 2.4. Run the report

```bash
python scripts/generate_project_maturity_report.py
```

After a few seconds `project_maturity_report.csv` will appear in the project root.

---

## 3. Maturity levels

| Level | Criteria |
|-------|----------|
| 2 | At least one scan exists – baseline |
| 3 | At least one finding has comments (indicates a results review meeting) |
| 4 | The number of vulnerabilities decreased between the latest and the previous scan |

The heuristic can be adapted in `scripts/generate_project_maturity_report.py`.

---

## 4. Code structure

```
cxone-python-reporter/
├── cxone/                           # Re-usable SDK
│   ├── __init__.py
│   ├── api.py                       # REST helpers
│   └── session.py                   # Authentication / token handling
├── scripts/
│   └── generate_project_maturity_report.py  # CLI entry-point
├── env.example                     # Environment variable template
├── requirements.txt                 # Dependencies (requests, python-dotenv)
├── TODO.md                          # Roadmap
└── CHANGELOG.md                     # Version history
```

### 4.1. Adding new reports

1. Create a new script in `scripts/`.
2. Import `CxOneSession` and `CxOneAPI`.
3. Implement your logic!
4. Document the script with a top-level docstring.

---

## 5. Contributing

Open a pull request – make sure to update `CHANGELOG.md` and add a TODO entry
if necessary.

---

## 6. Troubleshooting

* **401 / 403 errors** – Check that the refresh token is valid and has not expired.
* **SSL issues** – For PoC environments set `verify_ssl=False` when instantiating
  `CxOneSession` / `CxOneAPI`.

---