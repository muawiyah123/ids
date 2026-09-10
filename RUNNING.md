# 🛡️ IDS Sentinel — Complete Usage Guide

**AI-Powered Real-Time Network Intrusion Detection System**

---

## Table of Contents

1. [What This Project Does](#1-what-this-project-does)
2. [Prerequisites](#2-prerequisites)
3. [First-Time Setup](#3-first-time-setup)
4. [Starting the Project](#4-starting-the-project)
5. [Using the Dashboard](#5-using-the-dashboard)
6. [All Pages Explained](#6-all-pages-explained)
7. [Setting Up the Network Agent](#7-setting-up-the-network-agent)
8. [API Access](#8-api-access)
9. [Quick Restart (Daily Use)](#9-quick-restart-daily-use)
10. [Troubleshooting](#10-troubleshooting)

---

## 1. What This Project Does

IDS Sentinel is a **real-time network intrusion detection system**. It:

- **Monitors live network traffic** using a Python agent (Scapy) running on any machine
- **Analyses each network flow** using an XGBoost ML model trained on 15 attack categories
- **Classifies traffic** as BENIGN or one of 14 attack types (DDoS, PortScan, SQL Injection, etc.)
- **Raises alerts** when threats are detected, with severity levels (LOW → CRITICAL)
- **Displays everything** in a real-time SOC (Security Operations Center) dashboard

```
[Network Agent] → captures packets → extracts 47 features → sends to backend
[Backend API]   → ML model classifies → creates detection → raises alert if threat
[Dashboard]     → shows detections, alerts, charts, live stream in real-time
```

---

## 2. Prerequisites

Make sure these are installed before starting:

| Tool | Version | Check |
|---|---|---|
| Python | 3.10 or higher | `python --version` |
| Node.js | 18 or higher | `node --version` |
| PostgreSQL | 16 or higher | must be running as a service |

PostgreSQL must be **running** before you start. Check in PowerShell:
```powershell
Get-Service -Name postgresql*
# Status should say: Running
```

---

## 3. First-Time Setup

> ⚠️ Do this **once only**. Skip to Section 4 on subsequent runs.

### Step 1 — Create Python Virtual Environment

```powershell
cd C:\Users\Jawad Shaikh\OneDrive\Desktop\ids
python -m venv .venv
```

### Step 2 — Install Backend Dependencies

```powershell
.venv\Scripts\activate
cd backend
pip install -r requirements.txt
```

### Step 3 — Create the Database

Open a terminal and run (enter your postgres password when prompted):

```powershell
psql -U postgres -c "CREATE USER ids_user WITH PASSWORD 'ids_password';"
psql -U postgres -c "CREATE DATABASE ids_sentinel OWNER ids_user;"
psql -U postgres -c "GRANT ALL PRIVILEGES ON DATABASE ids_sentinel TO ids_user;"
```

> If you see `already exists` errors — that's fine, the DB is already set up.

### Step 4 — Run Database Migrations

This creates all the tables in the database:

```powershell
# From: C:\Users\Jawad Shaikh\OneDrive\Desktop\ids\backend
Get-Content ..\.env | ForEach-Object {
    if ($_ -match '^\s*([^#=]+?)\s*=\s*(.+)\s*$') {
        [System.Environment]::SetEnvironmentVariable($Matches[1], $Matches[2])
    }
}
..\\.venv\Scripts\alembic.exe upgrade head
```

You should see:
```
INFO  [alembic.runtime.migration] Context impl PostgresqlImpl.
INFO  [alembic.runtime.migration] Will assume transactional DDL.
```

### Step 5 — Install Frontend Dependencies

```powershell
cd C:\Users\Jawad Shaikh\OneDrive\Desktop\ids\frontend
npm install
```

---

## 4. Starting the Project

You need **two terminals** open at the same time.

---

### Terminal 1 — Start the Backend

```powershell
cd C:\Users\Jawad Shaikh\OneDrive\Desktop\ids\backend

# Load environment variables from .env file
Get-Content ..\.env | ForEach-Object {
    if ($_ -match '^\s*([^#=]+?)\s*=\s*(.+)\s*$') {
        [System.Environment]::SetEnvironmentVariable($Matches[1], $Matches[2])
    }
}

# Start the backend server
..\\.venv\Scripts\uvicorn.exe app.main:app --reload --host 0.0.0.0 --port 8000
```

✅ Backend is ready when you see:
```
INFO:     Application startup complete.
INFO:     Uvicorn running on http://0.0.0.0:8000
```

---

### Terminal 2 — Start the Frontend

```powershell
cd C:\Users\Jawad Shaikh\OneDrive\Desktop\ids\frontend
npm run dev
```

✅ Frontend is ready when you see:
```
VITE v8.x.x  ready in xxx ms
➜  Local:   http://localhost:5173/
```

---

### Open the App

Open your browser and go to:

**👉 http://localhost:5173**

The dashboard will open directly — no login required in development mode.

> If the page is blank/black: press **`Ctrl + Shift + R`** to hard refresh and clear the cache.

---

## 5. Using the Dashboard

When you open the app, you land on the **Security Dashboard**. Here's what each part means:

### Threat Level Indicator (top right)

| Level | Meaning |
|---|---|
| 🟢 NORMAL | No significant threats detected |
| 🟡 ELEVATED | Some suspicious activity |
| 🟠 HIGH | Active threats detected |
| 🔴 CRITICAL | Critical attacks in progress |

### KPI Cards (top row)

| Card | What it shows |
|---|---|
| **Total Detections** | All network flows ever analysed |
| **Threats Detected** | Non-BENIGN classifications (actual attacks) |
| **Open Alerts** | Unresolved alerts needing attention |
| **Active Agents** | Network monitoring agents sending data |

### Charts

- **Detection Timeline** — hourly bar chart of threats vs benign traffic over last 24h
- **Attack Distribution** — which attack types were detected most
- **Severity Distribution** — pie chart of CRITICAL / HIGH / MEDIUM / LOW / INFO

---

## 6. All Pages Explained

### 📊 Dashboard (`/dashboard`)
**Overview of the entire system.** Shows real-time KPIs, threat level, timelines, and charts. Data refreshes automatically every 15 seconds.

---

### 📡 Live Monitor (`/monitor`)
**Real-time stream of every detection as it happens.**

- Shows a live WebSocket feed — events appear instantly without refreshing
- 🟢 Connected indicator means the stream is live
- Toggle **"Show BENIGN"** to include normal traffic
- Use the **filter box** to search for specific attack classes (e.g., type `DDoS` to only see DDoS events)
- Each row shows: timestamp, predicted class, confidence score, severity badge, source IP, destination IP

> This page only shows data when a Network Agent is actively running and sending events (see Section 7).

---

### 🚨 Alerts (`/alerts`)
**Manage security alerts raised by the system.**

Alerts are automatically created when the ML model detects a threat. Each alert has a **lifecycle**:

```
NEW → ACKNOWLEDGED → INVESTIGATING → RESOLVED
                                   → FALSE_POSITIVE
```

- Click an alert to see full details, history, and notes
- Change the alert **status** to track your investigation
- Add **investigation notes** for team collaboration
- Filter alerts by severity: CRITICAL / HIGH / MEDIUM / LOW

> Alerts use a 10-minute deduplication window — repeated detections of the same type don't create duplicate alerts.

---

### 🔍 Detections (`/detections`)
**Full history of every ML classification.**

- Every network flow analysed by the model appears here
- Shows: timestamp, class, confidence %, severity, agent, source/destination IP
- Filter by class name, severity, or time range
- Click a detection to see all 15 class probabilities from the model
- Export data for offline analysis

---

### 📈 Analytics (`/analytics`)
**Deep dive charts and statistics.**

- 7-day trend line of detection counts
- Confidence score distribution histogram
- Top threat source IPs and destination IPs
- Attack class breakdown over custom time windows

---

### 🖥️ Agents (`/agents`)
**Manage network monitoring agents.**

An "agent" is a Python script (`ids_agent.py`) running on a machine to capture network traffic.

- **Register a new agent** — creates an API token for a new monitoring endpoint
- **View agent status** — ONLINE / DEGRADED / OFFLINE based on last heartbeat
- **See agent location** — which network interface it's monitoring
- **Copy the API token** — needed when starting the agent on a remote machine

---

### 🧠 Models (`/models`)
**Information about the ML model.**

- Model version, load status, training metrics
- Weighted F1: **0.9987**, Accuracy: **0.9986**
- Feature importance — which of the 47 network features matter most
- Training dataset info (CIC-IDS2017, ~2.8M flows, 15 classes)

---

### ❤️ Health (`/health`)
**System health status.**

- Backend API status
- Database connectivity
- Redis connectivity (optional)
- ML model load status
- Useful for diagnosing problems

---

### 📋 Audit (`/audit`)
**Immutable audit log of all system actions.**

- Every login, logout, alert status change, detection, user action is logged here
- Records cannot be modified or deleted
- Useful for compliance and security investigation

---

### ⚙️ Settings (`/settings`)
**User account settings.**

- Change your display name and email
- Change your password
- All sessions are invalidated on password change

---

## 7. Setting Up the Network Agent

The network agent is what actually **captures real network traffic** and sends it to the backend for analysis.

### Step 1 — Register an Agent in the Dashboard

1. Go to **Agents** page → click **"Register Agent"**
2. Give it a name (e.g., `home-router`, `server-01`)
3. Copy the **API Token** that appears — you'll need it in the next step

### Step 2 — Install Agent Dependencies

*(Already installed in your `.venv`!)* If needed in the future:

```powershell
cd "C:\Users\Jawad Shaikh\OneDrive\Desktop\ids\agent"
..\.venv\Scripts\pip.exe install -r requirements.txt
```

> The agent uses **Scapy** which requires **Npcap** on Windows to capture live packets.  
> Download from: https://npcap.com/#download

### Step 3 — Run the Agent

**Live Mode (Sending to Backend):**
```powershell
cd "C:\Users\Jawad Shaikh\OneDrive\Desktop\ids\agent"

# Replace YOUR_TOKEN with the token from Step 1
..\.venv\Scripts\python.exe ids_agent.py --url http://localhost:8000/api/v1/events --token YOUR_TOKEN --iface "Wi-Fi"
```

**Offline / Dry-Run Mode (Testing without sending to server):**
```powershell
cd "C:\Users\Jawad Shaikh\OneDrive\Desktop\ids\agent"
..\.venv\Scripts\python.exe ids_agent.py --dry-run
```

Common interface names on Windows:
- `Wi-Fi` — wireless network adapter
- `Ethernet` — wired connection
- `Local Area Connection`

List your available interfaces:
```powershell
..\.venv\Scripts\python.exe -c "from scapy.arch.windows import get_windows_if_list; [print(i['name']) for i in get_windows_if_list()]"
```

### Step 4 — Verify the Agent is Working

- Go to the **Agents** page — your agent should show as **ONLINE**
- Go to the **Live Monitor** — you should see detections appearing in real-time
- Go to the **Dashboard** — the "Active Agents" count will update

### Offline Test Script (No Root / No Npcap Required)

You can also run the built-in offline test to verify feature extraction:

```powershell
cd "C:\Users\Jawad Shaikh\OneDrive\Desktop\ids\agent"
..\.venv\Scripts\python.exe test_offline.py
```

---

## 8. API Access

The backend exposes a full REST API.

**Interactive API docs:** http://localhost:8000/docs  
**OpenAPI schema:** http://localhost:8000/openapi.json

### Key Endpoints

| Method | Endpoint | Description |
|---|---|---|
| GET | `/health` | System health check |
| GET | `/api/v1/dashboard/summary` | Dashboard KPIs |
| GET | `/api/v1/detections` | List all detections |
| GET | `/api/v1/alerts` | List all alerts |
| PATCH | `/api/v1/alerts/{id}` | Update alert status |
| GET | `/api/v1/agents` | List registered agents |
| POST | `/api/v1/agents` | Register new agent |
| POST | `/api/v1/events` | Submit a detection event |
| POST | `/api/v1/events/batch` | Submit up to 500 events at once |
| GET | `/api/v1/analytics/attack-distribution` | Attack class chart data |
| GET | `/api/v1/models/current` | ML model info |

---

## 9. Quick Restart (Daily Use)

After the first-time setup, just run these two commands in two terminals:

**Terminal 1 — Backend:**
```powershell
cd "C:\Users\Jawad Shaikh\OneDrive\Desktop\ids\backend"
Get-Content ..\.env | ForEach-Object { if ($_ -match '^\s*([^#=]+?)\s*=\s*(.+)\s*$') { [System.Environment]::SetEnvironmentVariable($Matches[1], $Matches[2]) } }
..\.venv\Scripts\uvicorn.exe app.main:app --reload --host 0.0.0.0 --port 8000
```

**Terminal 2 — Frontend:**
```powershell
cd "C:\Users\Jawad Shaikh\OneDrive\Desktop\ids\frontend"
npm run dev
```

Then open: **http://localhost:5173**

---

## 10. Troubleshooting

| Problem | Cause | Fix |
|---|---|---|
| `SECRET_KEY` / `DATABASE_URL` missing error | `.env` not loaded | Run the `Get-Content ..\.env \| ForEach-Object {...}` block before uvicorn |
| `password authentication failed` | DB user doesn't exist | Run the 3 `psql` commands from Section 3 Step 3 |
| Blank black page in browser | Stale cached JS | Press `Ctrl + Shift + R` in the browser |
| Page stuck on `/login` | Old Vite server running | Kill all node processes: `Get-Process node \| Stop-Process -Force`, then `npm run dev` |
| Port 5173 already in use | Old Vite still running | Same as above |
| Agent shows OFFLINE | No heartbeat received | Make sure the agent script is running and pointing to `http://localhost:8000` |
| No detections showing | Agent not running | Start the agent (Section 7) or the simulator |
| `alembic` not found | Venv not activated | Run `..\\.venv\Scripts\activate` first |
| Backend crashes on start | Missing env vars | Always load `.env` before starting uvicorn |
| Npcap error in agent | Npcap not installed | Download from https://npcap.com/#download |
