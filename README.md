# VulnScan Lite

> **VulnScan Lite** is an asynchronous, on-demand web security health scanner and misconfiguration assessment dashboard. It analyzes publicly exposed security posture (SSL/TLS certificates, HTTP security headers, CMS technology footprints, and HTML metadata) with deterministic scoring, actionable remediation guidance, dynamic score progression charts, and downloadable executive PDF audit reports.

---

## ⚠️ Passive Scanning & Ethical Use Disclaimer

> **IMPORTANT NOTICE**: Only scan websites you own or have explicit permission to test.
>
> **VulnScan Lite performs passive security analysis only.** It does **NOT** perform:
> - Exploitation or penetration testing
> - SQL injection probes or cross-site scripting payloads
> - Brute force or password attacks
> - Denial-of-service or stress testing
> - Authentication bypass attempts
> - Destructive testing or automated POST requests against target web servers

---

## 🏗️ Architecture & System Design

```
┌─────────────────────────────────────────────────────────────┐
│                 React 19 + TypeScript + Vite                │
│  - Recharts Score Gauge & Historical Trend Chart            │
│  - Reusable 2-Second Status Polling Hook (useScanPolling)   │
│  - Modular Security Report & Remediation UI                 │
│  - JWT Authentication & Route Guards (ProtectedRoute)       │
└──────────────────────────────┬──────────────────────────────┘
                               │  1. POST /api/scan (Bearer JWT)
                               │  6. Polls GET /api/scan/{id}/status (every 2s)
                               │  7. GET /api/scan/{id}/result (when complete)
                               │  8. GET /api/reports/{id}/pdf (PDF download)
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                 FastAPI REST API Server                     │
│  - JWT Authentication (bcrypt + PyJWT)                      │
│  - Strict Ownership Authorization (scan.user_id == user.id) │
│  - SSRF Protection & DNS Re-resolution Filter               │
│  - Rate Limiting (SlowAPI)                                  │
│  - Inserts 'queued' Scan Record in PostgreSQL               │
│  - Dispatches Asynchronous Task to Celery                   │
└──────────────────────────────┬──────────────────────────────┘
                               │  2. execute_scan.delay(scan_id, url)
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                     Redis Message Broker                    │
└──────────────────────────────┬──────────────────────────────┘
                               │  3. Worker task consumption
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                   Celery Background Worker                  │
│  - Updates Scan status: queued ──► running                  │
│  - Executes Passive Python Scanner Engine                   │
│  - Computes Deterministic Scores (0–100) & Letter Grades    │
│  - Generates Actionable Remediation & Nginx/Apache Configs  │
│  - Persists ScanResult, SecurityChecks, & Findings Records  │
│  - Updates Scan status: running ──► completed               │
└──────────────────────────────┬──────────────────────────────┘
                               │  4. Commits relational rows
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                     PostgreSQL Database                     │
│  - Users (UUID, email, password_hash)                       │
│  - Scans (UUID, target_url, status, score, grade)           │
│  - Scan Results (JSON SSL, headers, CMS, HTML data)         │
│  - Security Checks (Individual check items & point impact)  │
│  - Findings (Severity-coded issues & remediation snippets)  │
└─────────────────────────────────────────────────────────────┘
```

---

## 🔍 Scanner Methodology & Diagnostics

VulnScan Lite inspects public information exposed by standard HTTP GET/HEAD requests and TLS handshakes:

1. **SSRF Guard & URL Pre-Validation** (`scanner/engine.py`):
   - Accepts `http://` and `https://` schemas.
   - Resolves target hostnames against both IPv4 and IPv6 DNS records.
   - Rejects loopback (`127.0.0.0/8`, `::1`), private ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), link-local (`169.254.0.0/16`, `fe80::/10`), unique local (`fc00::/7`), and cloud metadata IP endpoints (`169.254.169.254`, `metadata.google.internal`).
   - Validates each hop up to 5 redirects to prevent open-redirect SSRF bypasses.

2. **Security Headers Analysis** (`scanner/headers.py`):
   - **Scored Headers (±10 points each)**:
     - `Content-Security-Policy`: Restricts resource sources to mitigate XSS and data injection.
     - `X-Frame-Options`: Enforces framing restrictions (`DENY` or `SAMEORIGIN`) to prevent Clickjacking.
     - `Strict-Transport-Security` (HSTS): Enforces browser HTTPS connections.
   - **Bonus Headers (+5 points each, non-penalizing)**:
     - `X-Content-Type-Options`: Enforces `nosniff` to prevent MIME-sniffing vulnerabilities.
     - `Referrer-Policy`: Controls referrer information leakage.
     - `Permissions-Policy`: Restricts browser hardware APIs (camera, microphone, geolocation).

3. **SSL/TLS Certificate Inspection** (`scanner/ssl_check.py`):
   - Strict certificate chain validation using Python standard `ssl.create_default_context()`.
   - Inspects: validity, expiration date, days remaining, subject DN, issuer DN, negotiated TLS version (TLSv1.2, TLSv1.3), and cipher suite.
   - Categorizes targets into: `valid`, `expired`, `verification_failed`, `connection_failed`, and `http`.

4. **CMS Fingerprinting** (`scanner/cms_detector.py`):
   - Identifies CMS signatures (WordPress, Drupal, Joomla, Shopify, Wix, etc.) from generator meta tags, `X-Powered-By` headers, and known public asset paths.
   - Captures exposed version numbers honestly without guessing. Reports `"Version detected; outdated status not determined."` if outdated status cannot be authoritatively confirmed.

5. **HTML Metadata Analyzer** (`scanner/html_analyzer.py`):
   - Safely parses document structure via BeautifulSoup.
   - Skips non-HTML binary payloads (PDF, images) safely.
   - Extracts page `<title>`, `<meta name="description">`, script/style CDN technologies (jQuery, Bootstrap, React, Cloudflare, etc.), form counts, and HTTPS link enforcement.

6. **Deterministic Scoring Engine** (`app/services/scoring.py`):
   - Baseline score: **50.0 points**.
   - SSL Impact: +20 (valid >30d), +5 (valid <30d), -15 (expired), -10 (untrusted/self-signed or plain HTTP).
   - Headers: CSP (±10), XFO (±10), HSTS (±10), bonus headers (+5 each).
   - Score clamped strictly between `0.0` and `100.0`.
   - Letter Grade Thresholds:
     - **A**: 90 – 100 (*Strong security configuration based on passive checks*)
     - **B+**: 80 – 89.9 (*Good security posture with some improvements recommended*)
     - **B**: 70 – 79.9 (*Moderate security posture with several improvements recommended*)
     - **C**: 60 – 69.9 (*Security configuration needs attention*)
     - **D**: 50 – 59.9 (*Multiple security improvements recommended*)
     - **F**: 0 – 49.9 (*Multiple critical security improvements recommended*)

7. **Remediation Engine** (`app/services/remediation.py`):
   - Maps each missing header or SSL flaw to contextual guidance: description, impact, and copy-pasteable Nginx/Apache configuration blocks.

8. **Executive PDF Generator** (`app/api/reports.py`):
   - Multi-page PDF reports generated via **ReportLab**.
   - Features `NumberedCanvas` (Page X of Y), executive summary, security checks matrix, SSL/TLS inspection, CMS & HTML indicators, findings with severity colors, and server remediation code blocks.

---

## 📡 REST API Reference

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `POST` | `/api/auth/register` | Public | Register user and receive JWT access token |
| `POST` | `/api/auth/login` | Public | Authenticate user and receive JWT access token |
| `GET` | `/api/auth/me` | Bearer JWT | Return authenticated user profile |
| `POST` | `/api/scan` | Bearer JWT | Create queued scan record, dispatch Celery task, return HTTP 202 |
| `GET` | `/api/scan/{id}/status` | Bearer JWT | Poll status (`queued`, `running`, `completed`, `failed`) |
| `GET` | `/api/scan/{id}/result` | Bearer JWT | Fetch completed diagnostic results, checks, and findings |
| `GET` | `/api/history` | Bearer JWT | Return all past scans for the authenticated user (newest first) |
| `GET` | `/api/reports/{id}/pdf` | Bearer JWT | Stream ReportLab-generated PDF report (`application/pdf`) |
| `GET` | `/health` | Public | API health check |
| `GET` | `/health/db` | Public | Database connectivity verification |

---

## 💻 Local Development Setup

### 1. Prerequisites
- Python 3.12+
- Node.js 18+ & npm
- PostgreSQL 15+ (or Neon PostgreSQL)
- Redis 6+

### 2. Environment Configuration

**Backend (`backend/.env`)**:
```env
DATABASE_URL=postgresql+psycopg://postgres:password@localhost:5432/vulnscan
REDIS_URL=redis://localhost:6379/0
JWT_SECRET=your-secret-jwt-key-here-min-32-chars
JWT_ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=60
CORS_ORIGINS=http://localhost:5173,http://localhost:3000
ENVIRONMENT=development
```

**Frontend (`frontend/.env`)**:
```env
VITE_API_BASE_URL=
```

### 3. Start Redis Broker
```powershell
docker run -d --name vulnscan-redis -p 6379:6379 redis:alpine
```

### 4. Run Database Migrations
```powershell
cd backend
.\.venv\Scripts\alembic upgrade head
```

### 5. Start the Celery Worker
```powershell
cd backend
.\.venv\Scripts\celery -A app.tasks.celery_app worker --loglevel=info -P solo
```

### 6. Start the FastAPI Backend
```powershell
cd backend
.\.venv\Scripts\uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

### 7. Start the React Frontend
```powershell
cd frontend
npm run dev
```

---

## 🧪 Testing

### Backend Automated Test Suite (113 tests)
```powershell
cd backend
.\.venv\Scripts\pytest -v
```

### Frontend TypeScript & Bundle Build
```powershell
cd frontend
npm run build
```
