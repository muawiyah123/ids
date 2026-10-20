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

Install and start **Docker Desktop**. Docker Compose starts the database, API,
and website together. Install **Npcap** once only if you want Windows to
capture live network packets.

---

## 3. First-Time Setup

No separate Python, Node.js, or PostgreSQL setup is needed for the dashboard.
The network agent sets up its Python packages the first time you start it.

---

## 4. Starting the Project

Start Docker Desktop, open PowerShell, and run these commands:

    cd "C:\Users\Muawiyah\Desktop\fyp\ids"
    docker compose up -d --build
    docker compose ps

Open **http://localhost:5173**. To check the backend and model, open
**http://localhost:8000/ready**. On later starts, run docker compose up -d
from the project folder.

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
- **See agent details** — hostname, status, and events sent
- **Copy one-step start command** — sets up and starts the agent

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

## 7. Starting the Network Agent

The agent sends traffic from this computer to the dashboard.

1. Start the project with the Docker commands in Section 4.
2. In the dashboard, open **Agents** and click **Register Agent**.
3. Enter a name and click **Register Agent**.
4. Click **Copy One-Step Start Command**.
5. In PowerShell, go to the project folder and paste the copied command at the normal prompt:

       cd "C:\Users\Muawiyah\Desktop\fyp\ids"

The command prepares the agent and automatically selects active capture
adapters. You do not need to enter an interface name. Run PowerShell as
Administrator and install Npcap on Windows for packet capture. Keep the
PowerShell window open while monitoring.

The agent card should change to **Online**. After network traffic, its **Events
Sent** count should increase. Online by itself confirms only that the agent
checked in. The agent can report only traffic visible to the computer where it
is running.

For live SYN-flood monitoring, the agent raises a rule signal after it sees at
least 200 TCP SYN packets to the same destination port within 5 seconds. The
backend records this as a high-severity **DoS** detection. The XGBoost model
still classifies ordinary completed flows against its 15 training labels; the
rate rule covers this specific high-rate SYN pattern and is not a promise to
identify every possible DoS technique.

To stop the agent, press Ctrl+C in its PowerShell window.
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

Start Docker Desktop. In PowerShell:

    cd "C:\Users\Muawiyah\Desktop\fyp\ids"
    docker compose up -d

Open http://localhost:5173. To stop the project, run docker compose down from
the same folder. This keeps the database data.

---
## 10. Troubleshooting

| Problem | What to do |
|---|---|
| Docker says the engine is unavailable | Open Docker Desktop and wait until it says it is running. |
| The website does not open | From the project folder run docker compose up -d, then refresh http://localhost:5173. |
| The agent shows Offline | Start the copied one-step agent command and leave its PowerShell window open. |
| The agent is Online but sends no events | Run PowerShell as Administrator and make sure Npcap is installed. The agent only sees traffic visible to its computer. |
| Agent reports a packet-capture error | Repair/install Npcap, then restart the agent. |
