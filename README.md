# SentinelAI

**An Autonomous Multi-Agent System for Intelligent Malware, Anomaly, Bug, and System Threat Detection**

## Current Status: Phase 2 — MonitorAgent

Phase 1 (foundation) and Phase 2 (MonitorAgent) are both complete. See
**PHASE1_GUIDE.md** for the foundational setup walkthrough and
**PHASE2_GUIDE.md** for what was added in Phase 2 and how to test it.

### Phase 1 — Foundation

This repository contains the Phase 1 foundation of SentinelAI:

- A working FastAPI backend
- Health check API
- System status API (CPU / memory, via `psutil`)
- Centralized configuration (`.env`)
- Centralized logging
- A `BaseAgent` class that will be the parent of all future agents
  (MonitorAgent, InvestigationAgent, AnalysisAgent, DecisionAgent, ResponseAgent)
- A safe, isolated `test_environment/` folder for future controlled monitoring

Nothing in Phase 1 monitors your real filesystem, scans for malware, or performs
any kind of detection yet. It is purely the scaffolding the rest of the system
will be built on top of.

### Phase 2 — MonitorAgent

Phase 2 adds the first real agent, **MonitorAgent**, which watches the
sandboxed `test_environment/` folder (via `settings.monitored_directory`)
for file create/modify/delete/move events using `watchdog`, normalizes
them, keeps the most recent 100 in memory, and exposes them through a
new `/api/monitor/*` API. See **PHASE2_GUIDE.md** for full details.

Still not built: InvestigationAgent, AnalysisAgent, DecisionAgent,
ResponseAgent, Orchestrator, any malware/anomaly scoring, or the frontend.

## Project Structure

```text
sentinel-ai/
│
├── backend/
│   ├── app/
│   │   ├── __init__.py
│   │   ├── main.py
│   │   ├── config.py
│   │   ├── agents/
│   │   │   ├── __init__.py
│   │   │   ├── base_agent.py
│   │   │   └── monitor_agent.py
│   │   ├── routers/
│   │   │   ├── __init__.py
│   │   │   ├── health.py
│   │   │   ├── system.py
│   │   │   └── monitor.py
│   │   ├── services/
│   │   │   ├── __init__.py
│   │   │   └── file_monitor.py
│   │   └── utils/
│   │       ├── __init__.py
│   │       └── logger.py
│   ├── tests/
│   │   ├── __init__.py
│   │   └── test_monitor_agent.py
│   ├── .env
│   ├── .env.example
│   ├── requirements.txt
│   └── .gitignore
│
├── frontend/            (empty — future phase)
├── test_environment/    (safe sandbox folder, watched by MonitorAgent)
├── README.md
├── PHASE1_GUIDE.md
├── PHASE2_GUIDE.md
└── .gitignore
```

## Quick Start (after setup — see PHASE1_GUIDE.md)

```powershell
cd sentinel-ai\backend
.\venv\Scripts\Activate.ps1
uvicorn app.main:app --reload
```

Then visit:
- http://127.0.0.1:8000
- http://127.0.0.1:8000/docs

See **PHASE1_GUIDE.md** for the full step-by-step walkthrough, including
Windows-specific instructions, expected outputs, and troubleshooting.
