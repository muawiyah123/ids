<div align="center">

# 🛡️ IDS Sentinel

### AI-Powered Real-Time Network Intrusion Detection & Security Monitoring

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688?style=flat-square&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-18-61DAFB?style=flat-square&logo=react&logoColor=black)](https://reactjs.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5-3178C6?style=flat-square&logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![XGBoost](https://img.shields.io/badge/XGBoost-2.1-FF6600?style=flat-square&logo=xgboost&logoColor=white)](https://xgboost.readthedocs.io/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-4169E1?style=flat-square&logo=postgresql&logoColor=white)](https://www.postgresql.org/)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=flat-square&logo=docker&logoColor=white)](https://www.docker.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](LICENSE)

**A production-ready, security-hardened network intrusion detection system powered by a trained XGBoost machine learning model (Weighted F1 = 0.9987). Built with real authentication, real-time WebSocket events, a full SOC-grade React dashboard, and complete Docker deployment.**

[Features](#-features) • [Architecture](#-architecture) • [Quick Start](#-quick-start) • [Attack Investigation](#-attack-investigation-and-prevention-workflow) • [Configuration](#-configuration) • [API Docs](#-api-documentation) • [ML Model](#-ml-model) • [Security](#-security) • [Deployment](#-deployment)

</div>

---

## ⚠️ Important Notices

> **Authorized Use Only.** This system is designed for deployment on networks you own or have explicit written authorization to monitor. All access is logged and audited.

> **AI Detections Are Not Infallible.** The XGBoost model achieves excellent metrics on the CIC-IDS2017 dataset, but no ML model is 100% accurate in all production environments. All detections must be validated by qualified security personnel. Do not take automated action solely based on model output.

> **Production Deployment.** Before deploying to production, change all default secrets, review the security checklist, and ensure the system meets your organization's compliance requirements.

---

## 🌟 Features

### Real-Time Detection Engine
- **47-feature CICFlowMeter-compatible flow analysis** — matches the exact feature engineering used during model training
- **XGBoost ML inference** with 15-class multiclass classification (Weighted F1: **0.9987**, Macro F1: **0.8916**)
- **Sub-10ms inference latency** — the pipeline runs warm-up inference at startup for consistent performance
- **Full class probability distribution** — not just the top prediction, but confidence for all 15 classes
- **Idempotent event processing** — agent-provided `event_id` prevents duplicate detections from retries

### Network Monitoring Agent
- **Scapy-based live packet capture** — deep packet inspection at the flow level
- **CICFlowMeter-compatible feature extraction** — 70+ flow statistics computed in real-time
- **Async reporting** — non-blocking flow submission via aiohttp
- **Offline/dry-run mode** — spool events to JSONL for testing without a backend
- **Token-based authentication** — each agent has a unique API key registered via the backend

### Enterprise Authentication & Authorization
- **JWT access tokens** (15-minute lifetime, configurable)
- **Rotating refresh tokens** (7-day lifetime, stored as SHA-256 hashes — never plaintext)
- **4-tier RBAC**: `SUPER_ADMIN` → `ADMIN` → `SOC_ANALYST` → `VIEWER`
- **Timing-oracle-safe** authentication — always runs bcrypt verify even on non-existent users
- **Complete session management** — logout revokes all refresh tokens; password change invalidates all sessions

### Real-Time WebSocket Events
- **Typed event stream**: `detection.created`, `alert.created`, `alert.updated`, `agent.heartbeat`
- **JWT-authenticated WebSocket connections** — token passed as query parameter
- **Auto-reconnect with exponential backoff** in the frontend (1s → 30s max)
- **Redis pub/sub bridge** for multi-instance deployments — events shared across all backend workers
- **Graceful degradation** — falls back to in-process broadcast if Redis is unavailable

### Alert Engine
- **Configurable deduplication window** (default 10 minutes) — prevents alert storms from repeated detections
- **Severity escalation** — existing alerts are upgraded if a new detection is more severe
- **Full lifecycle state machine**: `NEW` → `ACKNOWLEDGED` → `INVESTIGATING` → `RESOLVED` / `FALSE_POSITIVE`
- **Assignment and notes** — analysts can assign alerts and add investigation notes
- **Complete audit trail** — every state transition is recorded with actor, timestamp, and comment

### Attack Investigation and Response Guidance
- **Attack explanations in Live Monitor and Detections** — open any non-benign classification to see what the model detected, its confidence and severity, likely risk, and response recommendations
- **Built-in playbooks** — guidance is available without an external AI key
- **Optional AI enrichment** — backend-only Groq or OpenAI configuration can add contextual wording; provider failure falls back to the built-in playbook
- **Analyst-controlled response** — recommendations support triage; this project does not automatically block hosts, change firewall rules, or stop services

### Analytics & Observability
- **Dashboard KPIs**: total detections, threat counts, open/critical alerts, active agents, event rate
- **Detection timeline** — hourly bucketed chart (configurable window)
- **Attack class distribution** — bar chart of top threat classes
- **Severity distribution** — pie chart breakdown
- **Top threat sources/destinations** — ranked IP addresses
- **7-day trend line** — daily detection count over time
- **Confidence distribution** — histogram of model confidence scores

### Production Infrastructure
- **Async PostgreSQL** via SQLAlchemy 2.x + asyncpg — non-blocking DB operations
- **Alembic database migrations** with async support
- **Redis caching & pub/sub** (optional — app degrades gracefully without it)
- **Structured request logging** — request ID, method, path, status, latency
- **Security headers middleware** — X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy
- **CORS configuration** — whitelist-based origins
- **Immutable audit log** — append-only table, never updated or deleted
- **Model version tracking** — artifact hash, training metrics, load status stored in DB
- **Health and readiness endpoints** — proper 200/503 responses for Docker/k8s health checks

### Frontend SOC Dashboard
- **Dark SOC theme** — deep navy/charcoal palette optimized for long monitoring sessions
- **Inter + JetBrains Mono** fonts for readability
- **Role-gated navigation** — menu items hidden based on user role
- **TanStack Query** — server-state management with background refetch and caching
- **Zustand** — lightweight auth store with localStorage persistence
- **Recharts** — area charts, bar charts, pie charts, line charts — all live data
- **Live monitor** — real-time detection feed with class and BENIGN toggle filters
- **Security Assistant** — authenticated chatbot for general cybersecurity and defensive questions using the configured Groq/OpenAI provider
- **Responsive layout** — works on 1280px+ displays (desktop/workstation first)

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        FRONTEND (React + Vite)                      │
│  Login → Dashboard → Monitor → Alerts → Detections → Analytics     │
│  Agents → Models → Health → Audit → Settings                        │
│  WebSocket client  │  TanStack Query  │  Zustand auth store         │
└──────────────────────────────┬──────────────────────────────────────┘
                               │ HTTPS REST + WSS
┌──────────────────────────────▼──────────────────────────────────────┐
│                      BACKEND (FastAPI / Python 3.11)                │
│                                                                      │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌────────────────────┐ │
│  │ Auth API │  │ Agent API│  │ Event API│  │ Dashboard/Analytics│ │
│  │ JWT/RBAC │  │ Heartbeat│  │ Ingestion│  │ Alerts/Detections  │ │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └─────────┬──────────┘ │
│       │              │              │                   │            │
│  ┌────▼──────────────▼──────────────▼───────────────────▼────────┐ │
│  │                    Service Layer                                │ │
│  │  AuthService │ DetectionService │ AlertService │ AuditService  │ │
│  │  AttackAdvisor → built-in playbooks + optional AI enrichment  │ │
│  └──────────────────────┬──────────────────────────────────────--─┘ │
│                          │                                           │
│  ┌───────────────────────▼──────────────────────────────────────┐  │
│  │                   ML Inference Layer                           │  │
│  │  ModelManager (singleton) → ids_pipeline.pkl                  │  │
│  │  InfinityAndOutlierSanitizer → XGBClassifier                  │  │
│  │  47-feature input → 15-class probability distribution         │  │
│  └───────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────┘
         │                         │
┌────────▼─────────┐    ┌──────────▼──────────┐
│  PostgreSQL 16   │    │   Redis 7 (optional) │
│  • users         │    │   • WS pub/sub       │
│  • detections    │    │   • caching          │
│  • alerts        │    └─────────────────────-┘
│  • agents        │
│  • audit_logs    │
│  • model_versions│
└──────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│                    NETWORK AGENT (ids_agent.py)                     │
│  Scapy live capture → FlowTable → CICFlowMeter features             │
│  → Async HTTP POST → Backend Event Ingestion API (Bearer token)     │
└─────────────────────────────────────────────────────────────────────┘
```

### Directory Structure

```
ids/
├── agent/                          # Network monitoring agent
│   ├── ids_agent.py                # Core agent — Scapy capture + feature extraction
│   ├── test_offline.py             # Agent regression tests (no network required)
│   ├── simulator.py                # Traffic simulator for demo/testing
│   ├── requirements.txt
│   └── README.md
│
├── model/                          # ML model artifacts and training
│   ├── artifacts/
│   │   ├── ids_pipeline.pkl        # sklearn Pipeline (sanitizer + XGBoost)
│   │   ├── label_encoder.pkl       # LabelEncoder for 15 classes
│   │   └── metadata.json           # Feature list, class names, training metrics
│   ├── ids_common.py               # InfinityAndOutlierSanitizer (required for unpickling)
│   ├── train.py                    # Model training script
│   ├── test.py                     # Batch prediction tester
│   └── convert.py                  # JSONL → CSV converter for training data
│
├── backend/                        # FastAPI backend
│   ├── app/
│   │   ├── main.py                 # FastAPI app factory + lifespan
│   │   ├── config.py               # Pydantic Settings (all environment variables)
│   │   ├── database.py             # Async SQLAlchemy engine + session factory
│   │   ├── ml/
│   │   │   ├── ids_common.py       # Copy of model/ids_common.py (for pickle import)
│   │   │   ├── model_manager.py    # Singleton ModelManager (load, validate, predict)
│   │   │   └── inference.py        # InferenceService (validation + predict wrapper)
│   │   ├── models/                 # SQLAlchemy ORM models
│   │   │   ├── user.py             # User, UserRole, RefreshToken
│   │   │   ├── agent.py            # Agent, AgentHeartbeat
│   │   │   ├── detection.py        # Detection
│   │   │   ├── alert.py            # Alert, AlertEvent
│   │   │   ├── audit_log.py        # AuditLog (immutable)
│   │   │   └── model_version.py    # ModelVersion
│   │   ├── schemas/                # Pydantic request/response schemas
│   │   │   ├── auth.py
│   │   │   └── event.py            # AgentEvent, BatchEventRequest
│   │   ├── api/                    # FastAPI routers
│   │   │   ├── auth.py             # login, register, refresh, logout, me
│   │   │   ├── agents.py           # agent CRUD + heartbeat
│   │   │   ├── events.py           # event ingestion (single + batch)
│   │   │   ├── detections.py       # detection list, detail, export
│   │   │   ├── alerts.py           # alert CRUD + state machine
│   │   │   ├── dashboard.py        # summary KPIs + timeline
│   │   │   ├── analytics.py        # distribution + trend charts
│   │   │   ├── models_api.py       # model info + feature importance
│   │   │   ├── audit.py            # audit log read
│   │   │   ├── health.py           # /health + /ready endpoints
│   │   │   └── websocket.py        # authenticated WS endpoint
│   │   ├── services/               # Business logic
│   │   │   ├── auth_service.py
│   │   │   ├── detection_service.py
│   │   │   ├── alert_service.py
│   │   │   ├── websocket_service.py
│   │   │   └── audit_service.py
│   │   ├── security/
│   │   │   ├── jwt.py              # Access token create/decode
│   │   │   ├── hashing.py          # bcrypt + SHA-256 token hashing
│   │   │   └── dependencies.py     # get_current_user, require_roles, get_agent
│   │   ├── middleware/
│   │   │   ├── logging.py          # Request ID + structured logging
│   │   │   └── security_headers.py # OWASP security headers
│   │   └── utils/
│   │       ├── severity.py         # Severity mapping (class + confidence → severity)
│   │       └── pagination.py       # Page[T] generic response
│   ├── tests/
│   │   ├── conftest.py             # SQLite fixtures for unit tests
│   │   ├── test_auth.py            # Auth endpoint tests
│   │   ├── test_inference.py       # ML regression tests
│   │   └── test_severity.py        # Severity mapping unit tests
│   ├── alembic/
│   │   ├── env.py                  # Async migration environment
│   │   └── versions/               # Migration files
│   ├── requirements.txt
│   ├── pyproject.toml              # Ruff + Black + pytest config
│   ├── Dockerfile
│   └── alembic.ini
│
├── frontend/                       # React + Vite + TypeScript
│   ├── src/
│   │   ├── types/index.ts          # All TypeScript types
│   │   ├── services/api.ts         # Typed API client (axios)
│   │   ├── stores/authStore.ts     # Zustand auth store
│   │   ├── hooks/
│   │   │   └── useRealtimeEvents.ts # WebSocket hook with auto-reconnect
│   │   ├── lib/
│   │   │   ├── severity.ts         # Severity display config
│   │   │   └── utils.ts            # Date formatting, number formatting
│   │   ├── components/
│   │   │   ├── layout/
│   │   │   │   ├── Layout.tsx      # App shell
│   │   │   │   └── Sidebar.tsx     # Navigation (role-gated)
│   │   │   └── shared/
│   │   │       ├── SeverityBadge.tsx
│   │   │       ├── StatusBadge.tsx
│   │   │       └── LoadingSpinner.tsx
│   │   └── pages/
│   │       ├── Login.tsx
│   │       ├── Dashboard.tsx       # KPIs + charts
│   │       ├── Monitor.tsx         # Live WebSocket feed
│   │       ├── Alerts.tsx          # Alert management
│   │       ├── Detections.tsx      # Detection history
│   │       ├── Analytics.tsx       # Analytics charts
│   │       ├── Agents.tsx          # Agent management
│   │       ├── Models.tsx          # ML model info
│   │       ├── Health.tsx          # System health
│   │       ├── Audit.tsx           # Audit logs
│   │       └── Settings.tsx        # User settings
│   ├── tailwind.config.ts
│   ├── vite.config.ts
│   ├── package.json
│   └── Dockerfile
│
├── deploy/
│   └── nginx/nginx.conf            # Reverse proxy config
├── scripts/
│   ├── seed_demo.py                # Seed demo data
│   └── smoke_test.py               # End-to-end smoke test
├── .github/
│   └── workflows/
│       ├── ci.yml                  # Lint + test + build
│       ├── security.yml            # Bandit + pip-audit + Trivy
│       └── docker.yml              # Docker build + smoke test
├── docker-compose.yml              # Development stack
├── docker-compose.prod.yml         # Production stack
├── .env.example                    # Environment variable template
├── Makefile                        # Common tasks
└── README.md
```

---

## 🤖 ML Model

### Overview

The detection engine is built around a trained **XGBoost multiclass classifier** wrapped in a **scikit-learn Pipeline**. The model was trained on the **CIC-IDS2017 dataset** — a benchmark dataset from the Canadian Institute for Cybersecurity containing realistic network traffic with labeled attacks.

### Performance Metrics

| Metric | Value |
|--------|-------|
| **Weighted F1 Score (test)** | **0.9987** |
| **Macro F1 Score (test)** | **0.8916** |
| **Accuracy (test)** | **0.9986** |
| Test set size | ~378,000 flows |
| Training classes | 15 |

> ⚠️ These metrics are on the CIC-IDS2017 test split. Real-world performance depends on network environment, traffic patterns, and how closely they match the training data distribution.

### Supported Attack Classes

| Class | Category | Default Severity |
|-------|----------|-----------------|
| `BENIGN` | Normal traffic | INFO (no alert) |
| `Bot` | Botnet | CRITICAL |
| `DDoS` | Volumetric attack | CRITICAL |
| `DoS GoldenEye` | DoS attack | HIGH |
| `DoS Hulk` | DoS attack | HIGH |
| `DoS Slowhttptest` | DoS attack | HIGH |
| `DoS slowloris` | DoS attack | HIGH |
| `FTP-Patator` | Brute force | MEDIUM |
| `Heartbleed` | SSL vulnerability exploit | CRITICAL |
| `Infiltration` | Network infiltration | CRITICAL |
| `PortScan` | Reconnaissance | MEDIUM |
| `SSH-Patator` | Brute force | MEDIUM |
| `Web Attack - Brute Force` | Web application attack | HIGH |
| `Web Attack - Sql Injection` | Web application attack | HIGH |
| `Web Attack - XSS` | Web application attack | HIGH |

> **Note on Heartbleed:** This class is rare in the training data and may have lower recall in production. Predictions of "Heartbleed" should be investigated but treated with appropriate uncertainty.

### Feature Contract

The model consumes **47 CICFlowMeter-compatible features** in a specific order. The complete list is in [`model/artifacts/metadata.json`](model/artifacts/metadata.json) under `feature_names_in_order`.

Key features include: flow duration, packet count statistics, inter-arrival times (IAT), packet length statistics, TCP flag counts, window sizes, and bulk transfer statistics.

### Pipeline Architecture

```
Raw Feature Dict (47 features)
        ↓
InfinityAndOutlierSanitizer        ← custom class in ids_common.py
  • Replaces Inf with NaN
  • Clips extreme outliers
        ↓
XGBClassifier (multi:softprob)     ← outputs class probabilities
        ↓
predict_proba() → 15-class probability vector
        ↓
argmax → predicted class index
        ↓
LabelEncoder.inverse_transform() → class string
```

> **Critical:** `model/ids_common.py` **must** be importable when loading `ids_pipeline.pkl`. The backend copies this file to `backend/app/ml/ids_common.py` and adds it to `sys.path`. Never remove or modify this file without retraining the model.

### Severity Assignment

Severity is **not** a direct model output. It is computed by `backend/app/utils/severity.py` using this logic:

```
BENIGN                          → INFO  (never creates an alert)
Confidence < 60%                → LOW   (uncertain classification)
Confidence 60–85%               → base severity, except CRITICAL → HIGH
Confidence ≥ 85%                → full base severity per class
```

This is clearly documented application logic — not a claim about model capabilities.

---

## 🚀 Quick Start

### Prerequisites

- **Docker Desktop** with Docker Compose
- The ML model artifacts (`model/artifacts/`) are included in the repository

### Option 1: Docker Compose (Recommended)

```powershell
# Start Docker Desktop first, then open PowerShell in this project folder.
cd "C:\Users\Muawiyah\Desktop\fyp\ids"
if (-not (Test-Path .env)) {
    if (Test-Path .env.example) {
        Copy-Item .env.example .env
    } else {
        throw "No .env file or .env.example found. Open the IDS project folder first."
    }
}
docker compose up -d --build
docker compose ps
```

Access the dashboard at **http://localhost:5173**. Check backend/model readiness
at **http://localhost:8000/ready**. Database migrations run automatically.

### Option 2: Local Development

#### Backend

```bash
# Create virtual environment
python -m venv .venv
.venv\Scripts\activate        # Windows
# source .venv/bin/activate   # Linux/macOS

# Install dependencies
cd backend
pip install -r requirements.txt

# Set environment variables
$env:SECRET_KEY="dev_secret_key_replace_in_production"
$env:DATABASE_URL="postgresql+asyncpg://ids:ids@localhost/ids_sentinel"
$env:REDIS_ENABLED="false"   # Optional — skip Redis for local dev
$env:MODEL_DIR="../model/artifacts"

# Run migrations
alembic upgrade head

# Start backend
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

#### Frontend

```bash
cd frontend
npm install
npm run dev
# Opens at http://localhost:5173
```

#### Network Agent (Windows)

1. Open **Agents** in the dashboard and click **Register Agent**. Enter a name.
2. Click **Copy One-Step Start Command**.
3. In Administrator PowerShell, go to the project folder and paste the command
   at the PowerShell prompt.

The command prepares the agent and selects active capture adapters automatically.
You do not need to choose an interface. Install Npcap once for Windows packet
capture, and keep the agent PowerShell window open while monitoring. The token
is secret; do not share it or include it in screenshots.

---
## ⚙️ Configuration

All configuration is via environment variables (loaded from `.env` file). Copy `.env.example` and customize:

### Required Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `SECRET_KEY` | JWT signing key — **MUST change in production** | `python -c "import secrets; print(secrets.token_urlsafe(48))"` |
| `DATABASE_URL` | Async PostgreSQL URL | `postgresql+asyncpg://ids:pass@localhost/ids_sentinel` |

### Optional Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `APP_ENV` | `development` | Environment: `development`, `staging`, `production` |
| `DEBUG` | `false` | Enable debug mode (disable in production) |
| `LOG_LEVEL` | `INFO` | Logging level: `DEBUG`, `INFO`, `WARNING`, `ERROR` |
| `REDIS_URL` | `None` | Redis URL for pub/sub (optional) |
| `REDIS_ENABLED` | `true` | Enable Redis integration |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `15` | JWT access token lifetime |
| `REFRESH_TOKEN_EXPIRE_DAYS` | `7` | Refresh token lifetime |
| `MODEL_DIR` | `../model/artifacts` | Path to model artifact directory (when running from `backend/`) |
| `PUBLIC_SERVER_URL` | request host | Public backend URL used when generating agent start commands |
| `CORS_ORIGINS` | `http://localhost:5173` | Comma-separated allowed origins |
| `ALERT_CONFIDENCE_THRESHOLD` | `0.60` | Minimum confidence to create an alert |
| `ALERT_DEDUP_WINDOW_MINUTES` | `10` | Deduplication window for alerts |
| `AI_PROVIDER` | `groq` | Optional explanation provider: `groq` or `openai` |
| `AI_API_KEY` | empty | Optional provider key; backend only, never expose in frontend config |
| `AI_MODEL` | provider default | Optional chat-completions model override |
| `AI_BASE_URL` | provider default | Optional trusted OpenAI-compatible API base URL |
| `MAX_EVENT_BATCH_SIZE` | `500` | Maximum events per batch request |
| `SEED_ADMIN_EMAIL` | `None` | Admin email for initial seeding |
| `SEED_ADMIN_PASSWORD` | `None` | Admin password for initial seeding |

### Production Security Requirements

In `APP_ENV=production`, the app enforces:
- `SECRET_KEY` must not be `replace_me`, `changeme`, or empty
- `DEBUG` must be `false`
- API docs (`/docs`, `/redoc`) are disabled

---

## 🛡️ Attack Investigation and Prevention Workflow

This section explains the complete path from observing network traffic to investigating a classification and applying a defensive control. Follow it after completing [Quick Start](#-quick-start).

### 1. Know what the system does

The sensor/agent collects network flows and sends flow features to the backend. The ML model labels each flow (for example `PortScan`, `SSH-Patator`, `Web Attack - Sql Injection`, `DDoS`, or `BENIGN`). The backend stores the detection, may create or update an alert, and publishes a real-time event to the dashboard.

When a threat appears in **Live Monitor** or **Detections**, select **Explain** to view its attack class, confidence, severity, network endpoints, likely risk, and recommended response steps. The built-in playbook is always available. If AI is configured, the explanation can include provider-generated wording; it remains advisory and is not the detection engine.

> **Important prevention boundary:** IDS Sentinel is currently a network intrusion **detection and analyst-guidance** platform. It does not automatically prevent, block, quarantine, or remediate traffic. A detection is evidence to investigate, not proof that an attack succeeded. For actual prevention, use your firewall, router ACL, WAF, endpoint protection, identity controls, or upstream DDoS service. Apply changes through those controls after validation.

The agent observes traffic visible to the host/interface where it runs. For broader coverage, deploy authorized sensors on the relevant servers or provide traffic from a properly configured network TAP/SPAN/mirror port. A sensor on one workstation does not automatically see every device's traffic.

### 2. Start the stack and create an analyst account

From the project root, start Docker Desktop and run:

```powershell
if (-not (Test-Path .env)) { Copy-Item .env.example .env }
docker compose up -d --build
docker compose ps
```

Open `http://localhost:5173`, create an account from the login/register screen if you do not already have one, then sign in. Check `http://localhost:8000/ready`; a ready response means the API, database, and model are available. If readiness fails, inspect `docker compose logs backend` before continuing.

For a real monitoring run, register an agent from **Agents** and use the generated one-step command on a machine/network you are authorized to monitor. On Windows, install Npcap if required, run the capture process with the privileges required by the selected adapter, and leave the agent running. In **Agents**, confirm its status becomes **ONLINE**. Keep its token secret.

### 3. Configure optional AI explanations

AI is optional. Without a key, built-in explanations are returned and the **Explain** action still works. The recommended default is **Groq** for fast, cost-conscious enrichment. OpenAI is supported as an alternative. Choose a provider based on your organization's data handling, account, model availability, and cost requirements.

1. Create an API key in the provider account you control.
2. Open the project-root `.env` file. Do not put the key in frontend variables, source code, screenshots, issue reports, or a committed file.
3. Set one provider and a key:

```dotenv
AI_PROVIDER=groq
AI_API_KEY=your_groq_api_key_here
# Optional; if omitted, the backend uses its configured provider default.
AI_MODEL=
AI_BASE_URL=
```

For OpenAI, use:

```dotenv
AI_PROVIDER=openai
AI_API_KEY=your_openai_api_key_here
AI_MODEL=
AI_BASE_URL=
```

The current backend defaults are `llama-3.3-70b-versatile` for Groq and `gpt-4o-mini` for OpenAI. Provider model availability can change; if your account does not support its default, set `AI_MODEL` to a currently available chat-completions model for your selected provider. Set `AI_BASE_URL` only when using a trusted, compatible OpenAI-style endpoint. Do not set a browser `VITE_*` variable for a secret.

4. Save `.env` and restart the backend so it reloads the configuration:

```powershell
docker compose up -d --build backend
docker compose logs --tail 100 backend
```

5. Open **Live Monitor** or **Detections**, select **Explain** beside a non-`BENIGN` row, and confirm the explanation appears. When no key is configured, the response source is the built-in playbook. When AI succeeds, the source identifies the provider/model. If the provider times out, rejects the key, or returns an unusable response, the backend logs a warning and returns the built-in playbook instead.

The API key stays in backend configuration. Only the attack label and limited non-identifying flow context (severity, confidence, ports, and protocol) are sent to the configured provider; source and destination IP addresses are excluded. Do not send sensitive telemetry to a provider unless your organization permits it. Review the provider's current data, retention, and account terms before enabling it.

### 4. Read an alert and investigate the event

1. In **Live Monitor**, wait for the flow to appear. A non-benign predicted class is visually highlighted. Select **Explain** to expand its investigation and response guidance.
2. In **Detections**, filter by severity, attack class, or source IP, then select **Explain** on a threat to open the full investigation panel.
3. Check timestamp, class, severity, confidence, source/destination, protocol, and destination port against other telemetry. A high confidence score is the model's confidence in its label; it does not prove compromise or business impact.
4. Go to **Alerts** to acknowledge the alert, mark it investigating, add notes/assignment, and record the outcome. Resolve it or mark it false positive after investigation.
5. Preserve relevant logs and follow your incident-response procedure. Record what you checked and what control, if any, you applied.

### 5. Apply prevention through the appropriate control

Use the playbook as a starting point and adapt it to the affected service and your change-control process. Examples:

| Detection | Defensive controls to investigate |
|---|---|
| `PortScan` | Verify authorized scanner status; restrict exposed ports with firewall/security-group rules; disable unused services. |
| `SSH-Patator` / `FTP-Patator` | Review successful logins; restrict management access; use keys/MFA where supported; disable legacy FTP or password login where practical; rotate credentials if exposure is suspected. |
| `Web Attack - Sql Injection` | Check application/database logs; fix unsafe query construction using parameterized queries; apply input validation and least-privilege database permissions; use WAF rules as a compensating control. |
| `Web Attack - XSS` | Fix context-aware output encoding and unsafe templating; sanitize rich text; review affected pages; deploy a restrictive Content Security Policy. |
| `DoS`, `DDoS`, `DoS Hulk`, `DoS GoldenEye`, `DoS slowloris`, `DoS Slowhttptest` | Confirm service impact; use provider/CDN/WAF/load-balancer rate controls and appropriate request/connection timeouts; contact the upstream network provider for volumetric events. |
| `Heartbleed` | Identify affected TLS/OpenSSL services; patch; rotate certificates and secrets if a vulnerable service was exposed. |
| `Infiltration` / `Bot` | Correlate endpoint, DNS, identity, and network logs; contain a host or block a source only after validating ownership, scope, and impact. |

Do not blindly block an IP: it may be a shared NAT, proxy, scanner, CDN, internal system, or false positive. Prefer narrow, time-bounded controls with an owner, reason, expiry/review time, and rollback plan. Confirm the control worked and that legitimate service was not disrupted.

### 6. Verify the full path

Use this checklist for a controlled deployment or demonstration:

- [ ] `/ready` succeeds and the **AI Model** page shows the model ready.
- [ ] The registered agent reports **ONLINE** and the WebSocket indicator shows **Live feed connected**.
- [ ] An authorized test flow appears in **Live Monitor** and **Detections** with a timestamp, class, confidence, and severity.
- [ ] A non-benign flow creates/updates an alert when it meets the configured alert confidence threshold.
- [ ] **Explain** returns a built-in playbook without a key; with a valid provider key, AI enrichment succeeds and indicates its source.
- [ ] Provider failure still returns built-in guidance; the backend logs do not reveal the API key.
- [ ] An analyst records validation and a response outcome in **Alerts**.
- [ ] Any actual prevention rule is applied and verified in the relevant firewall/WAF/endpoint platform, with rollback available.

Use the repository's traffic simulator or a controlled lab dataset for demos. Only generate attack-like traffic against systems you own or have explicit authorization to test. A simulator may submit crafted flow features for UI demonstration; this proves the application path works, not that a production network attack was prevented.

### 7. Operational limitations and next steps for automated response

- Detection quality depends on sensor placement, captured traffic, feature extraction, model coverage, and how closely live traffic resembles training data. Validate detections in your own environment.
- Flow-based classification provides metadata and statistics; it may not contain the full packet or application payload needed to prove an exploit.
- The explanation is generated on request when an analyst selects **Explain**. Detection itself does not wait for an LLM, and built-in advice remains available if the provider is offline.
- There is no automatic firewall/EDR/WAF action in this implementation. To add one, build an explicit, authenticated response integration for your chosen control plane; define source validation, RBAC, approval thresholds, allowlists, rate limits, deduplication, audit records, expiration, rollback, dry-run mode, and failure handling first. Keep human approval enabled until the integration has passed controlled testing. Never execute arbitrary LLM-generated commands or firewall rules.
- For production, use HTTPS, restrict dashboard/API access, store secrets in a managed secret store, back up the database, synchronize clocks, and alert on agent/API/provider failures.

### Security Assistant

Open **Security Assistant** from the left navigation to ask general cybersecurity questions, including attack concepts, hardening, incident-response triage, secure configuration, and IDS Sentinel workflows. It uses the same backend `AI_PROVIDER`, `AI_API_KEY`, `AI_MODEL`, and `AI_BASE_URL` settings as attack explanations. If no provider key is configured, the assistant page explains how to enable it and keeps chat disabled. Conversation history is held in the current browser page only; **New chat** clears it. The backend accepts up to 16 messages per request, up to 4,000 characters per message, and 12 chat requests per user per minute per backend process. User chat text is sent to the configured AI provider, so do not include credentials, API keys, personal data, or sensitive logs.

The assistant is for authorized defensive use. It cannot access stored detections unless you include relevant non-sensitive context in your question, cannot inspect your network, and cannot apply firewall or system changes. It may make mistakes; validate advice before using it, especially during an incident. Requests to attack third-party systems are outside its intended use.

### Troubleshooting attack explanations

| Symptom | What to check |
|---|---|
| No detections arrive | Confirm the agent is running and ONLINE, the correct interface is being captured, the backend is reachable, and the event-ingestion logs show accepted events. |
| Detection appears but no alert | Check whether the event is `BENIGN`, its confidence is below `ALERT_CONFIDENCE_THRESHOLD`, or the alert is deduplicated into an existing alert. |
| Explain action is missing | Explanations are only offered for non-benign detections. Refresh the page and confirm the frontend/backend versions are current. |
| Built-in advice appears without AI | `AI_API_KEY` may be empty, the backend may not have been restarted, or the provider request may have failed. Check backend logs and confirm `AI_PROVIDER`, key, model, and provider account access. |
| Explain request returns an error | Confirm the user is signed in, the detection still exists, and the backend is reachable. Inspect backend logs for provider/network errors; built-in guidance should be returned for provider failures. |
| Container does not see updated settings | Confirm `.env` is in the project root (next to `docker-compose.yml`) and recreate/restart the backend with `docker compose up -d --build backend`. |

---

## 📡 API Documentation

### Base URL

```
http://localhost:8000/api/v1
```

When running in development mode, interactive API docs are available at:
- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

### Authentication

All endpoints (except `/health`, `/ready`, `/auth/login`, `/auth/register`) require a JWT Bearer token:

```http
Authorization: Bearer <access_token>
```

### Endpoint Reference

#### Authentication

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `POST` | `/auth/login` | None | Login with email/password → token pair |
| `POST` | `/auth/register` | None | Register new user (role: VIEWER) |
| `POST` | `/auth/refresh` | None | Rotate refresh token |
| `POST` | `/auth/logout` | JWT | Revoke all sessions |
| `GET` | `/auth/me` | JWT | Get current user profile |
| `POST` | `/auth/change-password` | JWT | Change password + revoke sessions |

#### Agent Management

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET` | `/agents` | JWT | List all agents |
| `GET` | `/agents/{id}` | JWT | Get agent details |
| `POST` | `/agents/register` | JWT (Admin+) | Register new agent — returns token **once** |
| `POST` | `/agents/{id}/heartbeat` | Agent Token | Submit heartbeat |
| `DELETE` | `/agents/{id}` | JWT (Admin+) | Disable agent |

#### Event Ingestion (Agent → Backend)

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `POST` | `/events` | Agent Token | Ingest single flow event → run inference |
| `POST` | `/events/batch` | Agent Token | Ingest up to 500 events |

**Single Event Example:**

```bash
curl -X POST http://localhost:8000/api/v1/events \
  -H "Authorization: Bearer <agent-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "event_id": "unique-event-id-123",
    "timestamp": "2024-01-15T10:30:00Z",
    "source_ip": "192.168.1.100",
    "destination_ip": "10.0.0.5",
    "destination_port": 22,
    "protocol": "TCP",
    "features": {
      "Destination Port": 22,
      "Flow Duration": 500000,
      "Total Fwd Packets": 15,
      "Flow Bytes/s": 12000.5,
      ...
    }
  }'
```

**Response:**

```json
{
  "status": "accepted",
  "detection_id": "550e8400-e29b-41d4-a716-446655440000",
  "prediction": "SSH-Patator",
  "confidence": 0.9234,
  "severity": "MEDIUM",
  "alert_id": "660e8400-e29b-41d4-a716-446655440001"
}
```

#### Detections

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET` | `/detections` | JWT | Paginated list with filtering |
| `GET` | `/detections/{id}` | JWT | Detection detail |
| `GET` | `/detections/{id}/features` | JWT | Raw feature payload |
| `POST` | `/detections/{id}/explanation` | JWT | Built-in/AI explanation and defensive guidance for a threat |
| `GET` | `/detections/export/csv` | JWT | Stream CSV export |

#### Security Assistant

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET` | `/assistant/status` | JWT | Report whether an AI key is configured and the selected provider |
| `POST` | `/assistant/chat` | JWT | Answer a cybersecurity question using the configured provider; accepts up to 16 user/assistant messages; limited to 12 requests/user/minute per process |

Chat request example:

```json
{
  "messages": [
    {"role": "user", "content": "How do I investigate an SSH brute-force alert?"}
  ]
}
```

The chat endpoint returns `answer`, `provider`, and `model`. It returns HTTP 503 when the provider key is not configured and HTTP 502 when the provider is unavailable or rejects the request. Chat messages are not persisted by this endpoint.

**Filtering parameters:** `severity`, `predicted_class`, `source_ip`, `destination_ip`, `agent_id`, `from_time`, `to_time`, `min_confidence`, `sort_by`, `sort_dir`, `page`, `page_size`

**Request an explanation directly:** first sign in to obtain a user access token, and get a detection ID from `GET /api/v1/detections`. Then call the authenticated explanation endpoint:

```bash
curl -X POST "http://localhost:8000/api/v1/detections/<detection-id>/explanation" \
  -H "Authorization: Bearer <user-access-token>"
```

The response contains `attack`, `summary`, `risk`, `actions`, and `source`. The same endpoint is used by the dashboard's **Explain** controls. It returns HTTP 400 for a `BENIGN` detection and HTTP 404 when the detection ID does not exist. Provider errors use built-in advice as a fallback rather than failing the explanation request.

#### Alerts

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET` | `/alerts` | JWT | Paginated list |
| `GET` | `/alerts/{id}` | JWT | Alert detail |
| `GET` | `/alerts/{id}/events` | JWT | Alert lifecycle timeline |
| `POST` | `/alerts/{id}/acknowledge` | JWT | Acknowledge alert |
| `POST` | `/alerts/{id}/investigate` | JWT | Set investigating status |
| `POST` | `/alerts/{id}/resolve` | JWT | Resolve alert |
| `POST` | `/alerts/{id}/false-positive` | JWT | Mark as false positive |
| `PATCH` | `/alerts/{id}` | JWT | Update notes/assignment |

#### Dashboard & Analytics

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET` | `/dashboard/summary` | JWT | KPI metrics |
| `GET` | `/dashboard/timeline` | JWT | Detection timeline |
| `GET` | `/analytics/attack-distribution` | JWT | Counts by attack class |
| `GET` | `/analytics/severity-distribution` | JWT | Counts by severity |
| `GET` | `/analytics/top-sources` | JWT | Top threat source IPs |
| `GET` | `/analytics/top-destinations` | JWT | Top threat destination IPs |
| `GET` | `/analytics/trends` | JWT | Daily detection counts |
| `GET` | `/analytics/confidence-distribution` | JWT | Confidence histogram |

#### ML Model

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET` | `/models/current` | JWT | Model metadata + status |
| `GET` | `/models/current/features` | JWT | 47 feature names |
| `GET` | `/models/current/importance` | JWT | XGBoost feature importance |

#### WebSocket

```
ws://localhost:8000/api/v1/ws/events?token=<access_token>
```

**Sent by server:**

```json
// Detection event
{"type": "detection.created", "timestamp": "...", "data": { ...Detection... }}

// Alert event
{"type": "alert.created", "timestamp": "...", "data": { ...Alert... }}

// Alert state change
{"type": "alert.updated", "timestamp": "...", "data": {"id": "...", "status": "RESOLVED"}}

// Agent heartbeat
{"type": "agent.heartbeat", "timestamp": "...", "data": {"agent_id": "...", "status": "ONLINE"}}
```

**Sent by client:**
```json
{"type": "ping"}
// Server responds with:
{"type": "pong"}
```

#### Health

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET` | `/health` | None | Liveness probe (always 200) |
| `GET` | `/ready` | None | Readiness probe (503 if DB/model not ready) |

#### Audit Logs

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET` | `/audit` | JWT (ADMIN+) | Paginated audit log |

---

## 🗄️ Database Schema

### Tables

| Table | Description |
|-------|-------------|
| `users` | User accounts with RBAC roles, soft-delete |
| `refresh_tokens` | Hashed refresh tokens with expiry and revocation |
| `agents` | Registered network agents with token hashes |
| `agent_heartbeats` | Agent heartbeat history |
| `detections` | ML detection results with raw features (JSONB) |
| `alerts` | Alert lifecycle with deduplication state |
| `alert_events` | Immutable alert state transition history |
| `audit_logs` | Immutable system audit trail |
| `model_versions` | ML model artifact registry |

### Relationships

```
User ──< RefreshToken
User ──< AuditLog
Agent ──< Detection
Agent ──< AgentHeartbeat
Detection ──< Alert
Alert ──< AlertEvent
User ──── Alert (assigned_to)
```

---

## 🔒 Security

### Authentication Security
- Passwords hashed with **bcrypt** (adaptive hashing — adjustable work factor)
- JWT signing with **HS256** (configurable — RS256 recommended for production)
- Refresh tokens stored as **SHA-256 hashes** — raw tokens never persisted
- **Token rotation** on every refresh — old token revoked immediately
- **Timing-oracle-safe** login — bcrypt always runs even for non-existent emails
- Session invalidation on password change

### Transport Security
- **TLS required** in production (handled by nginx reverse proxy)
- **HSTS** via nginx (not app-level — correct placement)
- **Security headers** on every response:
  - `X-Content-Type-Options: nosniff`
  - `X-Frame-Options: DENY`
  - `Referrer-Policy: strict-origin-when-cross-origin`
  - `X-XSS-Protection: 0` (modern browsers ignore this; CSP is better)
  - `Permissions-Policy: camera=(), microphone=(), geolocation=()`

### Input Validation
- All API inputs validated with **Pydantic v2** — strict type checking
- IP addresses validated with regex (invalid IPs are nullified, not rejected)
- Batch event size capped (default: 500 events)
- Sort fields whitelisted to prevent SQL injection
- Query parameters validated with type annotations

### Authorization
- **4-tier RBAC** enforced on every protected endpoint
- Agent endpoints use a **separate Bearer token** scheme
- Constant-time token comparison (`secrets.compare_digest`) for agent tokens
- Role checks applied with `require_roles()` FastAPI dependency

### Data Security
- Passwords and tokens **never logged or returned** in responses
- Audit logs are **append-only** — no update/delete operations permitted
- Raw feature payloads stored for investigation but not exposed without authentication
- Model artifacts accessed only server-side — never streamed to clients

### Security Scanning
```bash
# Python security scan
bandit -r backend/app/

# Dependency vulnerability check
pip-audit --require-hashes -r backend/requirements.txt

# Docker image scan
trivy image ids-sentinel-backend:latest
```

---

## 🚢 Deployment

### Docker Compose (Development)

```bash
# Start all services
docker compose up -d

# View logs
docker compose logs -f backend

# Run migrations
docker compose exec backend alembic upgrade head

# Stop all
docker compose down
```

### Docker Compose (Production)

```bash
# Review and set all variables in .env
cp .env.example .env
vim .env

# Start production stack
docker compose -f docker-compose.prod.yml up -d

# Check readiness
curl http://localhost/ready
```

### Services

| Service | Port (Dev) | Description |
|---------|------------|-------------|
| `frontend` | 5173 | Vite dev server / nginx (prod) |
| `backend` | 8000 | FastAPI + uvicorn |
| `postgres` | 5432 | PostgreSQL 16 |
| `redis` | 6379 | Redis 7 (optional) |
| `nginx` | 80/443 | Reverse proxy (prod only) |

### Production Checklist

- [ ] Set strong `SECRET_KEY` (minimum 48 characters)
- [ ] Set `APP_ENV=production` and `DEBUG=false`
- [ ] Configure TLS certificates in nginx
- [ ] Set `CORS_ORIGINS` to your actual domain(s)
- [ ] Enable Redis (`REDIS_ENABLED=true`) for multi-instance deployments
- [ ] Configure PostgreSQL with a strong password and dedicated user
- [ ] Set up database backups
- [ ] Configure log aggregation (ship logs to ELK/Loki)
- [ ] Set `DETECTION_RETENTION_DAYS`, `ALERT_RETENTION_DAYS` per compliance requirements
- [ ] Review and apply `ALERT_CONFIDENCE_THRESHOLD` for your environment
- [ ] Disable `/docs` and `/redoc` (automatic in production mode)
- [ ] Run `pip-audit` and `bandit` before deployment
- [ ] Scan Docker images with Trivy
- [ ] Test `/health` and `/ready` endpoints with your load balancer

---

## 🧪 Testing

### Backend Tests

```bash
cd backend

# Unit tests only (uses in-memory SQLite — no PostgreSQL required)
pytest tests/ -v

# With coverage report
pytest tests/ --cov=app --cov-report=html

# ML regression tests (requires model artifacts)
pytest tests/test_inference.py -v

# Integration tests (requires PostgreSQL)
TEST_DATABASE_URL=postgresql+asyncpg://ids:ids@localhost/ids_test pytest tests/ -v
```

### Agent Regression Tests

```bash
cd agent

# Offline test — no network, no backend required
# Simulates a complete TCP flow and verifies all feature computations
python test_offline.py
```

Expected output:
```
=== Computed flow feature record ===
Destination Port              : 443
Total Fwd Packets             : 6
...
All sanity checks passed. Agent logic is working correctly.
```

### Smoke Test

```bash
# End-to-end test against a running stack
python scripts/smoke_test.py --base-url http://localhost:8000
```

---

## 🛠️ Development

### Code Quality

```bash
# Format
black backend/
ruff check backend/ --fix

# Type check
mypy backend/app/

# Frontend lint
cd frontend && npm run lint

# Frontend type check
cd frontend && npx tsc --noEmit
```

### Database Migrations

```bash
cd backend

# Create a new migration
alembic revision --autogenerate -m "add_new_table"

# Apply migrations
alembic upgrade head

# Rollback one step
alembic downgrade -1

# Check current revision
alembic current
```

### Adding a New Attack Class

If you retrain the model with new classes:
1. Update `model/train.py` with the new class in training data
2. Retrain: `python model/train.py` — new artifacts saved to `model/artifacts/`
3. Add the new class to `CLASS_SEVERITY_MAP` in `backend/app/utils/severity.py`
4. Update the `CLASSES` list in `frontend/src/pages/Detections.tsx`
5. Add a new Alembic migration if any schema change is needed
6. Update tests in `backend/tests/test_inference.py`

---

## 🤝 Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) before submitting pull requests.

**Key guidelines:**
- Run all tests before submitting (`pytest tests/ -v`)
- Run `bandit -r app/` — zero high-severity findings allowed
- Do not commit secrets, model training data, or network captures
- Follow the existing code style (Black, Ruff)
- Add tests for any new service-layer logic

---

## 📄 License

This project is licensed under the **MIT License** — see [LICENSE](LICENSE) for details.

---

## 🙏 Acknowledgements

- **CIC-IDS2017 Dataset** — Canadian Institute for Cybersecurity, University of New Brunswick
- **CICFlowMeter** — Network flow feature extraction methodology
- **XGBoost** — Chen & Guestrin, KDD 2016
- **FastAPI** — Sebastián Ramírez
- **Scapy** — Philippe Biondi

---

<div align="center">

**Built as a Final Year Project — IDS Sentinel Team**

*Network security monitoring system. For authorized use only.*

</div>
