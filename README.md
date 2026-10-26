# SentinelAI

**A multi-agent system for real-time file and process monitoring, with explainable threat scoring, decisions, alerts, and SQLite history.**

SentinelAI watches one or more folders (a sandbox by default, or real folders such as Downloads and Desktop) and the running processes on a machine, scores what it sees with transparent rules, decides whether a human needs to look, explains why, and stores every result in SQLite. It is **observation-only**: it never deletes, quarantines, or kills anything.

Built with Python, FastAPI, Watchdog, psutil, SQLite, and Pytest (209 automated tests), with a live web dashboard.

---

## How it works

```
 file change in sandbox                     running processes
          │                                         │
          ▼                                         ▼
   FileMonitor (watchdog)                  ProcessMonitor (psutil)
          │                                 rule-based risk score
          ▼                                         │
   MonitorAgent ── keeps last 100 events            ▼
          │                               /api/system/processes/suspicious
          ▼   (real-time hand-off)
   SecurityOrchestrator
          │
          ├─ SecurityAgent → OrchestratorAgent → ProcessingPipeline
          │       EventProcessor  (validate + normalise, stable event id)
          │       Investigator    (file metadata, read-only)
          │       Analyzer        (observations)
          │       AnalysisAgent   (suspicion / threat score 0–100)
          │
          ├─ DecisionEngine          LOW → ALLOW, MEDIUM → ALERT, HIGH/CRITICAL → ESCALATE
          ├─ ResponseRecommendation  summary, explanation, evidence, next steps
          │
          ▼
   SecurityEventRepository → SQLite (security_events table)
          │
          ▼
   /api/security/events · /alerts · /stats
```

### Agents
| Agent | Job |
| --- | --- |
| `BaseAgent` | Shared lifecycle (start, stop, status, logging) for every agent |
| `MonitorAgent` | Watches the configured folders with watchdog, skips noise, normalises events, forwards them for real-time analysis, counts alerts |
| `InvestigationAgent` | Collects safe file metadata (exists, size, type) |
| `AnalysisAgent` | Applies scoring rules and returns findings and reasons |
| `OrchestratorAgent` | Runs the pipeline stages in order for one event |
| `SecurityAgent` | Entry point that combines orchestration and scoring |

### Threat scoring (file events)
Rule-based and explainable. Each rule adds points and a human-readable reason; the total is capped at 100.
Example: a suspicious executable or script extension (`.exe`, `.ps1`, `.bat`, `.vbs`, …) adds 70 points.

| Score | Level | Decision | Recommended action |
| --- | --- | --- | --- |
| 0–30 | LOW | ALLOW | NONE |
| 31–60 | MEDIUM | ALERT | MONITOR |
| 61–85 | HIGH | ESCALATE | REVIEW |
| 86–100 | CRITICAL | ESCALATE | REVIEW |

### Process scoring (psutil)
| Rule | Points |
| --- | --- |
| CPU ≥ 80% of the whole machine (like Task Manager) | +30 |
| Memory ≥ 25% | +20 |
| Runs from a temp, downloads, or public folder | +35 |
| Name imitates a system process (e.g. `svch0st.exe`) and is not running from `C:\Windows\System32` | +40 |
| Script host running (PowerShell, wscript, …) | +10 |

### Design decisions
- **Idempotent events:** an event's id is a SHA-256 fingerprint of its type, path, timestamp and destination, so the same event submitted twice is stored once (UNIQUE constraint on `event_id`).
- **Thread safety:** watchdog runs on its own thread; the in-memory event buffer and the SQLite writes are protected by locks.
- **Safe by design:** watched folders come only from `.env` (clients cannot redirect them), and nothing is ever modified or killed.
- **Noise filter:** skips "folder modified" events, SentinelAI's own database (which would otherwise cause an endless save-and-detect loop), and configurable folders and file types such as `.git`, `node_modules`, `AppData`, and `*.tmp`.
- **Renames are judged by the new name:** a download finishing as `setup.crdownload` → `setup.exe` is scored as an executable.
- **Failures never stop monitoring:** every stage catches and logs its own errors.
- **Layered code:** routers (HTTP) → agents/services (logic) → repositories (SQL) → SQLite.

---

## Dashboard

Open `http://127.0.0.1:8000/dashboard` while the server is running.

- Start and stop live monitoring with one click
- Totals: events analysed, alerts, average threat score, CPU and memory
- Events by threat level (LOW, MEDIUM, HIGH, CRITICAL)
- Latest alerts: click a row to see the explanation, evidence, and recommended next steps
- Suspicious processes with reasons, and the top processes by CPU
- Recent events, refreshed every 3 seconds

It is one static HTML file (`backend/app/static/dashboard.html`) with plain JavaScript and no build step. It polls the REST API below, and inserts all API text with `textContent`, so a malicious file name cannot inject HTML.

## API

Interactive docs: `http://127.0.0.1:8000/docs`

| Method | Endpoint | Purpose |
| --- | --- | --- |
| GET | `/api/health` | Health check |
| GET | `/api/system/status` | CPU and memory usage |
| GET | `/api/system/processes?limit=10&sort_by=cpu` | Top processes with risk assessment |
| GET | `/api/system/processes/suspicious?min_score=31` | Processes at MEDIUM risk or above, with reasons |
| POST | `/api/monitor/start` · `/stop` | Start or stop live monitoring |
| GET | `/api/monitor/status` | Running state, events seen, alerts raised, last alert |
| GET | `/api/monitor/events?limit=50` | Recent normalised events |
| POST | `/api/security/analyze` | Analyse one event manually (full pipeline) |
| GET | `/api/security/events` | Stored history, with filters and pagination |
| GET | `/api/security/events/{event_id}` | One stored event |
| GET | `/api/security/alerts` | Events with decision ALERT or ESCALATE |
| GET | `/api/security/stats` | Totals by threat level and decision, average score |

---

## Choosing what to watch

Set `MONITORED_DIRECTORY` in `backend/.env`, then restart the server.

| Goal | Value |
| --- | --- |
| Safe demo (default) | `../test_environment` |
| Where malware usually arrives | `C:\Users\YourName\Downloads;C:\Users\YourName\Desktop` |
| Your whole user folder | `C:\Users\YourName` |

Separate several folders with `;`. A folder inside another watched folder is merged automatically. Watching an entire drive such as `C:\` is not recommended: Windows writes to system folders constantly, which buries real alerts. Adjust `IGNORE_PATTERNS` to skip anything else that is noisy on your machine.

## Run it

```powershell
cd sentinel-ai\backend
py -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy .env.example .env
uvicorn app.main:app --reload
```

Then open `http://127.0.0.1:8000/dashboard`, click **Start monitoring**, and create a file such as `test.exe` inside `test_environment/`. The alert appears within a few seconds. Every endpoint can also be tried at `http://127.0.0.1:8000/docs`.

## Tests

```powershell
cd backend
pytest -q
```

209 tests cover event processing, investigation, scoring, decisions, recommendations, orchestration, persistence, live monitoring with alerts, multi-folder watching and the noise filter, process monitoring, the dashboard, and the API. Tests use temporary folders and a temporary database, so they never touch real files or data.

## Project structure

```
backend/
  app/
    agents/        BaseAgent, MonitorAgent, InvestigationAgent, AnalysisAgent, OrchestratorAgent, SecurityAgent
    services/      file_monitor, process_monitor, event_processor, investigator, analyzer,
                   pipeline, decision_engine, response_recommendation, security_orchestrator
    repositories/  security_event_repository (all SQL)
    db/            database (SQLite connection + schema)
    models/        dataclasses / pydantic models for each stage's result
    routers/       health, system, monitor, investigation, analysis, pipeline, security, dashboard
    static/        dashboard.html (live web dashboard)
    utils/         logger
    config.py      settings from .env
    main.py        FastAPI app
  tests/           Pytest suite
test_environment/  safe sandbox folder that is monitored
```

## Development history
Built in phases: foundation (1), MonitorAgent (2), processing pipeline (3), analysis and scoring (4), orchestration (5), security agent (6), decision engine (7), recommendations and explainability (8), central orchestrator (9), SQLite persistence (10), process monitoring (11), real-time analysis with alerts and statistics (12), a live web dashboard (13), and multi-folder watching with a noise filter (14). `PHASE1_GUIDE.md` and `PHASE2_GUIDE.md` document the first two phases in detail.

## Possible next steps
- Email or Slack notifications for ESCALATE decisions
- Feed process risk into the same decision and persistence pipeline
- Baseline-based anomaly detection (learn normal activity, flag deviations)

## Deploy (Render, free)

The repo includes a `Dockerfile` and `render.yaml`.

1. Sign in at render.com with GitHub.
2. Choose **New → Blueprint** and select this repository.
3. When the deploy finishes, open `https://<your-service>.onrender.com/dashboard`.

The hosted app watches its own `test_environment` folder (not your computer), starts monitoring automatically, and shows a **Simulate activity** button that creates harmless sample files so visitors can watch ALLOW / ESCALATE decisions happen live. On the free plan the service sleeps when idle and its SQLite history resets on restart.

Run the same container locally:

```bash
docker build -t sentinel-ai .
docker run -p 8000:8000 sentinel-ai
```
