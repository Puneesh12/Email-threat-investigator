# AegisMail: AI-Powered Email Threat Investigation Platform

**AegisMail** is a production-quality, enterprise-grade Security Operations Center (SOC) investigation platform designed to automate and accelerate suspicious email analysis. The application mimics the workflow of a Senior Email Security Engineer and Threat Intelligence Analyst, parsing complete MIME layers, tracing Received SMTP hop paths, checking protocol integrity (SPF, DKIM, DMARC), mapping IOCs to threat databases, alignment checks, and leveraging LLMs (Gemini/OpenAI) to generate cohesive forensic investigation reports.

---

## Key Features

- **EML & MIME Parsing**: Decodes raw email headers and structured multipart content (Base64/Quoted-Printable). Extracts files, URLs, and mail hops.
- **Protocol Security Validation**: Verifies SPF, DKIM, and DMARC alignment status against public DNS (with graceful off-network overrides).
- **Spoofing & BEC Detection**: Identifies display-name spoofing, lookalike typo-squatted domains, and analyzes body context for business email compromise (financial urgency, gift cards, credentials).
- **IOC Defanging & Extraction**: Scans bodies and headers to extract public IPs, hashes, domains, and defangs them for safe dashboard display.
- **Threat Intelligence Enrichment**: Correlates IP reputation (AbuseIPDB), attachment hashes (VirusTotal), URL maliciousness (VirusTotal/URLScan), and domain age (WHOIS).
- **MITRE ATT&CK Mapping**: Correlates email attack behaviors to specific adversary techniques (T1566.001 Spearphishing, T1585.002 Lookalikes, T1071.003 Protocol abuse).
- **AI Analyst Assistant**: Drafts professional executive summaries, intent maps, and defense-in-depth recommendations.
- **Relational Case Database**: Stores investigation histories using SQLAlchemy (SQLite/PostgreSQL compatible).
- **Responsive SOC Dashboard**: High-fidelity dashboard displaying hop charts, risk contribution breakdown, domain verification grids, and AI recommendations. Serves directly from FastAPI or via Vite.

---

## System Architecture

```
email-threat-investigator/
├── backend/
│   ├── app/
│   │   ├── main.py              # FastAPI main entrypoint
│   │   ├── config.py            # Pydantic Settings management
│   │   ├── db/
│   │   │   ├── session.py       # Async engine & session lifecycle
│   │   │   └── models.py        # SQLAlchemy SQL schema
│   │   ├── api/
│   │   │   ├── deps.py          # Session dependency injection
│   │   │   ├── upload.py        # File & raw text upload controller
│   │   │   └── investigations.py# Past reports & analytics controller
│   │   ├── services/
│   │   │   ├── parser.py        # EML MIME Parser Engine
│   │   │   ├── validator.py     # SPF, DKIM, DMARC Validator
│   │   │   ├── spoof_detector.py# Impersonation & BEC Scanner
│   │   │   ├── ioc_extractor.py # Regex extractor & defanger
│   │   │   ├── threat_intel.py  # VT, URLScan, WHOIS, AbuseIPDB
│   │   │   ├── risk_scorer.py   # Dynamic risk/confidence calculation
│   │   │   ├── mitre_mapper.py  # MITRE ATT&CK technique compiler
│   │   │   └── ai_assistant.py  # LLM (Gemini/OpenAI) orchestration
│   │   └── tests/               # 17 Unit & Integration tests
│   ├── requirements.txt
│   └── Dockerfile
├── frontend/
│   ├── src/                     # React decoupled source files
│   │   ├── App.jsx
│   │   ├── index.css
│   │   └── main.jsx
│   ├── package.json
│   ├── tailwind.config.js
│   ├── postcss.config.js
│   ├── vite.config.js
│   └── Dockerfile
├── samples/                     # Test EML files (phishing invoice, lookalikes)
├── docker-compose.yml           # Complete container orchestrator
└── README.md
```

---

## Installation & Setup

### Local Quickstart (SQLite + Instant UI)

FastAPI serves the React UI directly at `/dashboard` out-of-the-box, meaning you do **not** need Node/NPM to run the dashboard locally.

1. **Clone the Repository** and navigate to the project directory:
   ```bash
   cd email-threat-investigator
   ```

2. **Configure Environment Variables** (Optional, falls back to offline mock profiles if empty):
   Create a `.env` file in the `backend/` directory:
   ```env
   # Database defaults to local SQLite. Set PostgreSQL URL for production.
   DATABASE_URL=sqlite+aiosqlite:///./email_investigator.db
   
   # Threat Intel & LLM Keys
   GEMINI_API_KEY=your_gemini_key
   # OR
   OPENAI_API_KEY=your_openai_key
   AI_PROVIDER=gemini # "gemini" or "openai"
   
   VIRUSTOTAL_API_KEY=your_vt_key
   ABUSEIPDB_API_KEY=your_abuseipdb_key
   URLSCAN_API_KEY=your_urlscan_key
   ```

3. **Set Up Python Virtual Environment** and Install Dependencies:
   ```bash
   cd backend
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

4. **Launch the FastAPI Server**:
   ```bash
   uvicorn app.main:app --reload
   ```

5. **Access AegisMail**:
   - **Interactive SOC Dashboard**: Open [http://127.0.0.1:8000/dashboard](http://127.0.0.1:8000/dashboard) in your browser.
   - **Interactive API Docs (Swagger)**: Open [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs).

---

## Running Decoupled Containerized Stack (PostgreSQL + React + FastAPI)

To run the complete production-grade decoupled stack using Docker Compose:

1. Provide your threat intel and AI keys in your environment variables.
2. Spin up the orchestrator:
   ```bash
   docker-compose up --build
   ```
3. Access services:
   - **Vite React Frontend**: [http://localhost:3000](http://localhost:3000)
   - **FastAPI Backend Swagger**: [http://localhost:8000/docs](http://localhost:8000/docs)
   - **PostgreSQL Database**: Port `5432`

---

## API Documentation

### Ingestion Routes

#### 1. Ingest EML File
- **Endpoint**: `POST /api/upload/file`
- **Content-Type**: `multipart/form-data`
- **Request Payload**: Form field `file` containing `.eml` or `.txt` binary.
- **Description**: Parses EML MIME layers, runs full authentication checks, extracts and defangs IOCs, requests reputation scores, maps MITRE strategies, initiates AI analysis, and saves the final forensic case.

#### 2. Ingest Raw Email MIME Text
- **Endpoint**: `POST /api/upload/text`
- **Content-Type**: `application/json`
- **Request Payload**:
  ```json
  {
    "raw_text": "From: billing@invoice-alerts.com\nTo: admin@corp.com\nSubject: Invoice overdue..."
  }
  ```

### Case Management Routes

#### 3. List Past Cases
- **Endpoint**: `GET /api/investigations`
- **Query Parameters**:
  - `risk_level`: Filter by `Low`, `Medium`, `High`, `Critical`.
  - `search`: Match keyword in Subject or Sender.
  - `limit`: Number of records (Default: 20).
- **Description**: Returns chronological cases list matching parameters.

#### 4. Get Case Detailed Report
- **Endpoint**: `GET /api/investigations/{id}`
- **Description**: Retrieves full structured metrics JSON including AI summary notes for a specific UUID.

#### 5. Get Analytics Metadata
- **Endpoint**: `GET /api/investigations/stats`
- **Description**: Calculates high-level metrics for dashboard cards (total cases count, average threat risk score, malicious case percentages, and daily timeline logs).

---

## Verification & Testing

We have built a test suite with **17 unit and integration tests** validating EML parsing, SPF/DKIM/DMARC alignment math, AbuseIPDB/VirusTotal reputation lookups, display-name spoofing heuristics, and API CRUD database transactions.

### Running Backend Tests
Ensure your virtual environment is active:
```bash
cd backend
pytest
```

#### Test Executions Result Log:
```text
============================= test session starts ==============================
platform darwin -- Python 3.14.6, pytest-9.1.1, pluggy-1.6.0
rootdir: /Users/puneeshgulati/.gemini/antigravity/scratch/email-threat-investigator/backend
plugins: asyncio-1.4.0, anyio-4.14.2
collected 17 items

app/tests/test_api.py ..                                                 [ 11%]
app/tests/test_ioc_intel.py ...                                          [ 29%]
app/tests/test_parser.py ...                                             [ 47%]
app/tests/test_risk_report.py ...                                        [ 64%]
app/tests/test_sec_engines.py ......                                     [100%]

======================== 17 passed in 0.35s =========================
```

---

## Future Improvements

1. **Graph-based Received hop geolocations**: Draw physical server locations on a map using MaxMind GeoIP.
2. **YARA rule attachment checks**: Add scanning of email attachments against locally compiled YARA rules.
3. **MFA and Role-based access control**: Secure the SOC platform with active Azure AD/OIDC logins.
4. **Header hop tracer enhancements**: Identify spoofed Received header entries injected by the sender to hide their source IP.
