# SentinelAI — Phase 1 Technical Implementation Document

**Project:** SentinelAI — An Autonomous Multi-Agent System for Intelligent Malware, Anomaly, Bug, and System Threat Detection
**Phase:** 1 of N — Foundation
**Platform:** Windows, VS Code
**Status:** Complete and ready for testing

All the code described below is already written and included in this zip, under `backend/`. This document explains what each piece does and walks you through running and verifying it yourself.

---

## SECTION 1 — Phase 1 Overview

**What Phase 1 is:** the foundational skeleton of SentinelAI — a working FastAPI backend, a virtual environment, configuration, logging, two simple API endpoints, and a base class that every future agent will inherit from.

**Why it matters:** every later phase (MonitorAgent watching files, InvestigationAgent gathering evidence, AnalysisAgent scoring threats, DecisionAgent choosing actions, ResponseAgent acting, and the Orchestrator tying it all together) will run *inside* this backend and *depend on* this configuration and logging setup. Getting Phase 1 solid means later phases are just "add a new agent/router," not "restructure the project."

**What is built in Phase 1:**
- Project + backend folder structure
- Python virtual environment
- FastAPI app with two working endpoints (`/api/health`, `/api/system/status`)
- `.env`-based configuration
- Centralized logging
- A `BaseAgent` class (no real agents yet — just the shared contract)
- A safe `test_environment/` sandbox folder for future monitoring

**What is NOT built yet:** MonitorAgent, InvestigationAgent, AnalysisAgent, DecisionAgent, ResponseAgent, the Orchestrator, any anomaly/malware detection logic, any database, and the frontend. Those are future phases.

**How it connects to the future architecture:**

```text
BaseAgent (Phase 1)
    │
    ├── MonitorAgent        ← Phase 2+
    ├── InvestigationAgent  ← Phase 2+
    ├── AnalysisAgent       ← Phase 2+
    ├── DecisionAgent       ← Phase 2+
    └── ResponseAgent       ← Phase 2+

FastAPI app (Phase 1) ← routers/services added per phase
Security Memory        ← later phase
Orchestrator Agent      ← later phase, coordinates all agents
```

### Phase 1 Final Deliverables

- [x] Project folder created
- [x] Python verified
- [x] VS Code configured
- [x] Virtual environment created
- [x] Virtual environment activated
- [x] Required packages installed
- [x] Backend structure created
- [x] FastAPI application created
- [x] Health API working
- [x] System status API working
- [x] Configuration created
- [x] Logging created
- [x] Base Agent architecture created
- [x] Test environment created
- [x] Application successfully tested (you'll do this in Section 15)

---

## SECTION 2 — Prerequisites

### Required software

| Tool | Purpose |
|---|---|
| VS Code | Where you'll write/run code |
| Python 3.10+ | Runs the backend |
| pip | Installs Python packages (comes with Python) |
| VS Code "Python" extension | Interpreter selection, linting, debugging |
| Git (optional) | Only needed if you plan to version-control the project |

### Check Python is installed

Open **VS Code Terminal** (`` Ctrl+` ``) — it defaults to PowerShell on Windows — and run:

```powershell
python --version
```

**Expected output:** something like `Python 3.11.4`.

Then check pip:

```powershell
pip --version
```

**Expected output:** something like `pip 24.0 from ... (python 3.11)`.

**If you see "python is not recognized as an internal or external command":**
Python isn't installed, or isn't on your PATH.
1. Install Python from https://www.python.org/downloads/ — during install, **check the box "Add python.exe to PATH"**.
2. Close and reopen VS Code's terminal after installing.
3. Re-run `python --version`.

**If you see "pip is not recognized":**
Pip normally installs with Python. Try `python -m pip --version` instead — if that works, use `python -m pip ...` in place of `pip ...` throughout this guide.

### Select the correct interpreter in VS Code

1. Press `Ctrl+Shift+P` → type "Python: Select Interpreter" → Enter.
2. Choose the Python 3.10+ interpreter shown (before you create the venv, this will be your global Python; after Section 4, re-run this and pick the `venv` one instead — VS Code usually detects it automatically and prompts you).

---

## SECTION 3 — The Project Structure

This zip already contains the full structure:

```text
sentinel-ai/
│
├── backend/
├── frontend/
├── test_environment/
├── README.md
└── .gitignore
```

- **`backend/`** — all Python/FastAPI code lives here. This is what you'll run.
- **`frontend/`** — empty for now; a future phase will add a UI here.
- **`test_environment/`** — an isolated sandbox folder. When the Monitor Agent is built in a later phase, it will watch *only this folder* for changes, not your real filesystem. That keeps testing safe: you can freely create/delete files here to trigger detection logic without any risk to your actual system.
- **`README.md`** — project overview.
- **`.gitignore`** — keeps `venv/` and `.env` (which may contain machine-specific paths) out of version control.

If you ever need to recreate this by hand, the Windows commands are:

```powershell
mkdir sentinel-ai
cd sentinel-ai
mkdir backend, frontend, test_environment
New-Item README.md, .gitignore -ItemType File
```

---

## SECTION 4 — Backend Setup: Virtual Environment

**What a virtual environment is:** an isolated, project-local copy of Python and its package folder. Packages installed inside it don't affect your system-wide Python or other projects.

**Why it matters:** without it, every Python project on your machine would share one global set of packages, and version conflicts between projects become inevitable. A venv keeps SentinelAI's dependencies self-contained and reproducible.

**Where it lives:** `sentinel-ai/backend/venv/` (already in `.gitignore` — it should never be committed).

### Create it

In **VS Code Terminal**, run:

```powershell
cd sentinel-ai\backend
python -m venv venv
```

**Expected output:** no output on success — it just returns to the prompt after a few seconds. A new `venv/` folder appears inside `backend/`.

**Verify:** run `dir venv\Scripts` — you should see `activate`, `Activate.ps1`, `python.exe`, `pip.exe`, etc.

### Activate it

**PowerShell (VS Code's default terminal):**

```powershell
.\venv\Scripts\Activate.ps1
```

**Command Prompt (if you're using `cmd` instead):**

```cmd
venv\Scripts\activate
```

**Expected result:** your prompt line now starts with `(venv)`, e.g.:

```text
(venv) PS C:\...\sentinel-ai\backend>
```

That `(venv)` prefix is how you verify activation worked.

**If PowerShell blocks activation** with a message like *"running scripts is disabled on this system"*, that's PowerShell's execution policy. The safe, standard fix for local development is to allow locally-created scripts for your user only:

```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```

Confirm with `Y` when prompted, then re-run the activation command. (This does not disable security for downloaded/untrusted scripts — it only allows unsigned local scripts like the venv activator.)

### Deactivate it

Whenever you want to leave the virtual environment:

```powershell
deactivate
```

The `(venv)` prefix disappears.

---

## SECTION 5 — Package Installation

With `(venv)` active, install Phase 1's dependencies:

```powershell
pip install fastapi "uvicorn[standard]" psutil python-dotenv
```

**Expected output:** pip resolves and installs each package plus their dependencies, ending in a line like `Successfully installed fastapi-... uvicorn-... psutil-... python-dotenv-...`.

| Package | Why it's here |
|---|---|
| **fastapi** | The web framework that defines our API endpoints and auto-generates the `/docs` page. |
| **uvicorn[standard]** | The ASGI server that actually runs FastAPI and handles HTTP requests. `[standard]` adds performance extras and `--reload` support. |
| **psutil** | Cross-platform library for reading safe, local system stats (CPU %, memory) — the basis of the system status endpoint and, later, the Monitor Agent. |
| **python-dotenv** | Loads variables from `.env` into the environment, so secrets/settings never get hardcoded into source files. |

### Freeze dependencies

```powershell
pip freeze > requirements.txt
```

This overwrites `requirements.txt` with the *exact installed versions*, so the project is reproducible. (A starter `requirements.txt` with unpinned names is already included in this zip — running the command above after your own install will pin it to your exact versions, which is good practice before sharing the project.)

Anyone else (including future-you on another machine) can then recreate your exact environment with:

```powershell
pip install -r requirements.txt
```

---

## SECTION 6 — Backend Structure Explained

```text
backend/
├── app/
│   ├── __init__.py        # marks app/ as a Python package
│   ├── main.py             # creates the FastAPI app, registers routers
│   ├── config.py           # loads .env into a typed Settings object
│   ├── agents/
│   │   ├── __init__.py
│   │   └── base_agent.py   # shared parent class for all future agents
│   ├── routers/
│   │   ├── __init__.py
│   │   ├── health.py       # GET /api/health
│   │   └── system.py       # GET /api/system/status
│   ├── services/
│   │   └── __init__.py     # empty now; future business logic goes here
│   └── utils/
│       ├── __init__.py
│       └── logger.py       # centralized logging setup
├── .env                     # your local config (git-ignored)
├── .env.example             # template safe to commit
├── requirements.txt
└── .gitignore
```

- **`__init__.py` files** turn each folder into an importable Python package (e.g. `from app.routers import health`). They're empty on purpose.
- **`main.py`** is deliberately thin — it wires things together but contains no endpoint logic itself, so it won't become a dumping ground as the project grows.
- **`config.py`** is the *only* place that reads environment variables. Every other file imports `settings` from here.
- **`agents/`** will hold one file per agent in future phases; today it only holds the shared base class.
- **`routers/`** holds one file per group of related endpoints — this pattern scales cleanly as more APIs are added (e.g. a future `agents.py` router to control agents via API).
- **`services/`** is reserved for business logic that routers and agents will both call into later (e.g. threat scoring) — kept separate from routers so logic isn't tied to HTTP.
- **`utils/`** holds small shared helpers; `logger.py` is the first of these.

---

## SECTION 7 — Environment Configuration

`.env` (already created in this zip, at `backend/.env`):

```env
APP_NAME=SentinelAI
APP_ENV=development
LOG_LEVEL=INFO
MONITORED_DIRECTORY=../test_environment
```

- **`.env` is git-ignored** because it's meant to hold values that can differ per machine/deployment (and, later, real secrets like API keys) — committing it risks leaking those and causes merge conflicts between developers' local settings.
- **`.env.example` is committed** so anyone cloning the repo knows exactly which variables to set, without seeing your actual local values.
- **Why this helps future agents:** `MONITORED_DIRECTORY` already points at the sandbox folder — when the Monitor Agent is built, it reads this same setting instead of a hardcoded path, so changing what's monitored is a one-line config change, not a code change.

`config.py` loads these into a typed `Settings` dataclass (full code in `backend/app/config.py`) — see Section 6 for why this pattern is used instead of scattered `os.getenv()` calls.

---

## SECTION 8 — Logging System

`backend/app/utils/logger.py` sets up Python's built-in `logging` module once, with a consistent format:

```text
2026-08-27 12:00:00 | INFO | SentinelAI | Application started
```

That's `timestamp | level | logger name | message`.

**What logging is:** a structured, leveled way to record what a program is doing — unlike `print()`, log lines carry a timestamp, a severity level, and a source, and can be redirected (to a file, a dashboard, etc.) without changing the code that logs them.

**Why it matters for an autonomous agent system specifically:** once multiple agents are running concurrently and making autonomous decisions (flagging files, killing processes, etc.), logs are your only record of *what happened and why*. Good logging from day one means Phase 2+ agents are debuggable and auditable instead of being black boxes.

**Levels used:**
- **DEBUG** — fine-grained detail, useful only while developing.
- **INFO** — normal operational messages (e.g. "Agent started", "Request received").
- **WARNING** — something unexpected but not immediately harmful (e.g. a config value missing, falling back to default).
- **ERROR** — something failed and needs attention (e.g. a file couldn't be read).

Every module gets its own named logger via `get_logger(__name__)`, so log lines always show which part of the system produced them.

---

## SECTION 9 — The Base Agent

`backend/app/agents/base_agent.py` defines `BaseAgent`: name, status (`stopped`/`running`), `start()`, `stop()`, `is_running()`, and built-in logging via the logger from Section 8.

**Why it exists:** so every future agent shares one lifecycle contract instead of each reinventing "how do I start/stop/report status." This is what will let the future Orchestrator Agent manage all agents generically — start them, stop them, check their status — without knowing the internals of each one.

**Why inheritance:** `MonitorAgent(BaseAgent)`, `InvestigationAgent(BaseAgent)`, etc. will each override `start()`/`stop()` with their real behavior, but automatically inherit status tracking and logging for free. This keeps each future agent's code focused only on what makes it unique.

No subclasses are implemented in Phase 1 — this file is intentionally just the foundation.

---

## SECTION 10 — The FastAPI Application

`backend/app/main.py`:
- Creates the `FastAPI()` app with title/description/version metadata (shown on the `/docs` page).
- Registers the health and system routers via `app.include_router(...)`.
- Logs a startup message showing the app name, environment, and log level, using the config and logger from Sections 7–8.
- Exposes a simple `/` root endpoint pointing to `/docs`, `/api/health`, and `/api/system/status`.

All actual endpoint *logic* lives in `app/routers/`, not here — see Section 6 for why.

---

## SECTION 11 — Health Check API

`backend/app/routers/health.py` → `GET /api/health`

```json
{
  "status": "healthy",
  "application": "SentinelAI",
  "environment": "development"
}
```

**What it's for:** a near-instant, dependency-free endpoint that answers "is the process up and responding?" This is a standard pattern used by load balancers, uptime monitors, and orchestration tools. Later, the Orchestrator Agent (or an external monitoring tool) can poll this to confirm the backend itself is alive before checking on individual agents.

**How to test it** (after you start the server in Section 14):
- **Browser:** visit `http://127.0.0.1:8000/api/health`
- **Swagger docs:** visit `http://127.0.0.1:8000/docs`, expand `GET /api/health`, click "Try it out" → "Execute"
- **Terminal (optional):** `curl http://127.0.0.1:8000/api/health`

---

## SECTION 12 — System Status API

`backend/app/routers/system.py` → `GET /api/system/status`

```json
{
  "cpu_usage": 35.2,
  "memory_usage": 61.5,
  "memory_total_gb": 16.0,
  "memory_available_gb": 6.1
}
```

- **`cpu_usage`** — percent of CPU capacity currently in use across all cores, sampled over a short 0.5s window via `psutil.cpu_percent(interval=0.5)` for a meaningful (non-zero) reading.
- **`memory_usage`** — percent of total RAM currently in use.
- **`memory_total_gb` / `memory_available_gb`** — total installed RAM and RAM currently available to new processes, converted from bytes to GB.

**Why this matters for the future Monitor Agent:** unusual, sustained spikes in CPU or memory usage are one basic signal of something worth investigating (e.g. a runaway or malicious process). Phase 1 only *exposes* the raw numbers — no thresholds, alerts, or per-process inspection yet. That logic belongs to a later phase.

---

## SECTION 13 — The Safe Test Environment

`test_environment/README.txt` (already created) explains the purpose: this folder is where future file-monitoring will happen, deliberately isolated from your real filesystem. Nothing watches it yet in Phase 1 — it exists now so the structure and the `MONITORED_DIRECTORY` config value are already correct when monitoring is implemented.

---

## SECTION 14 — Running the Application

With `(venv)` active and packages installed, from `sentinel-ai/backend`:

```powershell
uvicorn app.main:app --reload
```

- **`app.main:app`** — tells uvicorn: import the `app` module inside the `app` package (i.e. `app/main.py`), and use the object named `app` defined there (our `FastAPI()` instance).
- **`--reload`** — watches your source files and automatically restarts the server when you save changes. Great for development; you would drop this flag in production.

**Expected output:**

```text
INFO:     Will watch for changes in these directories: [...]
INFO:     Uvicorn running on http://127.0.0.1:8000 (Press CTRL+C to quit)
INFO:     Started reloader process [...]
2026-08-27 12:00:00 | INFO | SentinelAI | SentinelAI starting up (env=development, log_level=INFO)
INFO:     Application startup complete.
```

**Access it:**
- `http://127.0.0.1:8000` — root endpoint, confirms the app is running and links to the others.
- `http://127.0.0.1:8000/docs` — **Swagger UI**, FastAPI's auto-generated interactive API explorer. Every endpoint is listed; click one, then "Try it out" → "Execute" to send a real request and see the real response, right in the browser — no separate tool needed.

Stop the server anytime with `Ctrl+C` in the terminal.

---

## SECTION 15 — Complete Testing Guide

Run these in order, from `sentinel-ai/backend` with `(venv)` active unless noted.

**Test 1 — Python:** `python --version` → expect `Python 3.x.x`. Failure → see Section 2.

**Test 2 — Virtual environment:** prompt shows `(venv)` prefix after activation. Failure → re-run the activation command from Section 4; check the execution-policy fix if PowerShell blocked it.

**Test 3 — Installed packages:** `pip list` → expect to see `fastapi`, `uvicorn`, `psutil`, `python-dotenv` in the list. Failure → re-run the `pip install` command from Section 5.

**Test 4 — `.env` loading:** `python -c "from app.config import settings; print(settings)"` → expect a `Settings(...)` printout showing `app_name='SentinelAI'` etc. Failure → confirm you're running this from inside `backend/` (so `app` is importable) and that `.env` exists there.

**Test 5 — Start the server:** `uvicorn app.main:app --reload` → expect the startup log block shown in Section 14. Failure → see Section 16 (port in use / import errors).

**Test 6 — Health endpoint:** with the server running, visit `http://127.0.0.1:8000/api/health` → expect the JSON from Section 11.

**Test 7 — System status endpoint:** visit `http://127.0.0.1:8000/api/system/status` → expect JSON matching the shape in Section 12 (your actual numbers will differ).

**Test 8 — Logs visible:** check the terminal running uvicorn → expect the startup log line in the `timestamp | LEVEL | name | message` format from Section 8.

**Test 9 — BaseAgent imports cleanly:** `python -c "from app.agents.base_agent import BaseAgent; a = BaseAgent('TestAgent'); a.start(); print(a); a.stop()"` → expect two log lines (`TestAgent started` / `TestAgent stopped`) and a `<BaseAgent name='TestAgent' status='stopped'>` printout with no traceback. Failure → confirm you're in `backend/` with `(venv)` active.

---

## SECTION 16 — Troubleshooting

| Problem | Likely Cause | Solution | Verify |
|---|---|---|---|
| `python is not recognized` | Python not installed or not on PATH | Reinstall Python, checking "Add to PATH"; restart terminal | `python --version` works |
| `pip is not recognized` | Same as above, or pip missing | Try `python -m pip --version`; if that works, use `python -m pip` throughout | `python -m pip --version` works |
| Venv activation blocked in PowerShell | Execution policy disallows scripts | `Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned`, confirm `Y` | Re-run `.\venv\Scripts\Activate.ps1`, prompt shows `(venv)` |
| `ModuleNotFoundError: No module named 'fastapi'` (etc.) | Packages installed outside the venv, or venv not activated | Activate venv, re-run `pip install -r requirements.txt` | `pip list` shows the package |
| `[Errno 10048] error while attempting to bind on address ... already in use` (port 8000 busy) | Another process (often a previous uvicorn run) is on port 8000 | Stop the old process (`Ctrl+C` in its terminal), or run on another port: `uvicorn app.main:app --reload --port 8001` | Server starts without the bind error |
| `uvicorn is not recognized` | Venv not activated, or installed outside it | Activate venv; re-run `pip install "uvicorn[standard]"` | `uvicorn --version` works inside `(venv)` |
| Wrong Python interpreter in VS Code | VS Code still points at global Python, not the venv | `Ctrl+Shift+P` → "Python: Select Interpreter" → choose the one inside `backend\venv\Scripts\python.exe` | Bottom-right VS Code status bar shows the venv interpreter |
| `.env` values not taking effect | Not running from `backend/`, or `load_dotenv()` didn't find the file | Always run uvicorn/python from inside `backend/`; confirm `.env` sits next to the `app/` folder | Test 4 above prints the expected values |
| Import errors like `attempted relative import` / `No module named 'app'` | Running a file directly (`python app/main.py`) instead of as a module via uvicorn | Always start via `uvicorn app.main:app --reload` from `backend/`, not by executing `main.py` directly | Server starts cleanly |

---

## SECTION 17 — Final Phase 1 Checklist

```text
PHASE 1 COMPLETION CHECKLIST

[ ] Project created
[ ] VS Code opened correctly (opened the sentinel-ai folder)
[ ] Python working (python --version)
[ ] Virtual environment created (backend/venv exists)
[ ] Virtual environment activated ((venv) shown in prompt)
[ ] Packages installed (pip list shows fastapi, uvicorn, psutil, python-dotenv)
[ ] requirements.txt created
[ ] Folder structure completed (matches Section 6)
[ ] .env created
[ ] .env.example created
[ ] .gitignore created
[ ] config.py working (Test 4 passes)
[ ] logger.py working (Test 8 passes)
[ ] BaseAgent created (Test 9 passes)
[ ] FastAPI application running (Test 5 passes)
[ ] Health endpoint tested (Test 6 passes)
[ ] System status endpoint tested (Test 7 passes)
[ ] Test environment created (test_environment/README.txt exists)
[ ] Swagger documentation working (/docs loads and "Try it out" works)
[ ] No import errors
[ ] No server errors
```

---

## SECTION 18 — Expected Final Project State

```text
sentinel-ai/
│
├── backend/
│   ├── venv/                    ← created by you in Section 4 (not in the zip)
│   ├── app/
│   │   ├── __init__.py
│   │   ├── main.py
│   │   ├── config.py
│   │   ├── agents/
│   │   │   ├── __init__.py
│   │   │   └── base_agent.py
│   │   ├── routers/
│   │   │   ├── __init__.py
│   │   │   ├── health.py
│   │   │   └── system.py
│   │   ├── services/
│   │   │   └── __init__.py
│   │   └── utils/
│   │       ├── __init__.py
│   │       └── logger.py
│   ├── .env
│   ├── .env.example
│   ├── requirements.txt
│   └── .gitignore
│
├── frontend/
├── test_environment/
│   └── README.txt
├── README.md
└── .gitignore
```

### Every time you come back to work on the project:

```powershell
cd sentinel-ai\backend
.\venv\Scripts\Activate.ps1
uvicorn app.main:app --reload
```

- `cd sentinel-ai\backend` — moves into the folder containing `venv/` and `app/`.
- `.\venv\Scripts\Activate.ps1` — activates the isolated Python environment so the right packages are used.
- `uvicorn app.main:app --reload` — starts the FastAPI server with auto-reload on save.

---

# PHASE 1 COMPLETE — READY FOR TESTING

Do not proceed to Phase 2 (MonitorAgent, InvestigationAgent, AnalysisAgent, DecisionAgent, ResponseAgent, anomaly/malware detection logic, database, or frontend) until you've run through Section 15's tests yourself and everything checks out.
