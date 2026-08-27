# SentinelAI — Phase 2 Guide: MonitorAgent

**Status: complete, tested, and verified end-to-end.**

This builds directly on the Phase 1 foundation (see `PHASE1_GUIDE.md`) — nothing in Phase 1 was rewritten unnecessarily; Phase 2 only adds new files and three small, additive edits to `app/main.py` (import + two `include_router` lines).

---

## What was added

| File | Purpose |
|---|---|
| `backend/app/services/file_monitor.py` | Low-level wrapper around `watchdog`: starts/stops an `Observer` on one directory and normalizes raw filesystem events into SentinelAI's event shape. Knows nothing about agents, settings, or storage. |
| `backend/app/agents/monitor_agent.py` | `MonitorAgent(BaseAgent)` — the first real agent. Resolves and validates `settings.monitored_directory`, owns a `FileMonitor`, keeps the most recent 100 events in a thread-safe bounded deque, and exposes `get_status()` / `get_events()`. |
| `backend/app/routers/monitor.py` | `GET /api/monitor/status`, `GET /api/monitor/events`, `POST /api/monitor/start`, `POST /api/monitor/stop`. Owns a single module-level `MonitorAgent` instance. |
| `backend/tests/test_monitor_agent.py` | 11 automated tests covering lifecycle, all four event types, and edge cases (see below). |
| `backend/requirements.txt` | Added `watchdog==6.0.0` (pinned, the version actually installed and tested against). |

**Edited (additive only):** `backend/app/main.py` now imports and registers `monitor.router`, and the root `/` endpoint's response lists the two new monitor URLs alongside the existing ones. `base_agent.py`, `config.py`, `logger.py`, `health.py`, `system.py` are all untouched.

---

## Design decisions worth knowing

- **Responsibility split.** `file_monitor.py` only knows how to watch a folder and describe what changed — it has no idea what a "monitored_directory" setting is or what an agent is. `monitor_agent.py` owns the policy (which directory, what to keep, lifecycle rules). This mirrors the separation the Phase 2 spec asked for.
- **The watched directory is not client-controllable.** `settings.monitored_directory` (from `.env`) is the only source of the watched path. The `/api/monitor/start` endpoint starts monitoring *that* configured directory — there is no parameter to redirect it elsewhere, so a client can't silently point MonitorAgent at a different (e.g. real) folder.
- **No database.** Events live in a `collections.deque(maxlen=100)` in memory, guarded by a lock. Restarting the FastAPI process clears history — expected and acceptable for Phase 2.
- **Duplicate-start safety.** `MonitorAgent.start()` checks `is_running()` first and no-ops if already running, so calling `/api/monitor/start` twice never creates a second `watchdog.Observer`. Verified by test and by manual API calls (see Testing below).
- **Clean shutdown.** `stop()` always calls `FileMonitor.stop()` (which joins the observer thread with a timeout) before flipping `BaseAgent` status, so the thread is actually released, not just marked stopped.
- **Directory-level "modified" events.** Because monitoring is recursive, `watchdog` also reports the *containing folder* itself as "modified" whenever its contents change (in addition to the file-level event). These appear in `/api/monitor/events` with `"is_directory": true` — this is normal `watchdog` behavior, not a bug. If a future phase wants file-only events, that's a one-line filter in `file_monitor.py` or in a consumer.
- **Tests use a temp sandbox, not the committed `test_environment/` folder.** Each test points a fresh `MonitorAgent` at a pytest `tmp_path` (via monkeypatching `settings.monitored_directory`) instead of writing into the real `test_environment/` folder. This is strictly more isolated (nothing is left behind across test runs) while satisfying the same safety goal — only a disposable sandbox is ever touched, never real files. `test_environment/` is still exactly what gets watched when you run the actual server (see Manual Testing below).

---

## API Reference

### `GET /api/monitor/status`
```json
{
  "running": true,
  "watching": "/absolute/path/to/sentinel-ai/test_environment",
  "event_count": 3
}
```

### `GET /api/monitor/events?limit=50`
`limit` is optional (1–100). Returns the most recent retained events, oldest first:
```json
{
  "events": [
    {
      "event_type": "created",
      "path": "/.../test_environment/demo.txt",
      "timestamp": "2026-08-27T08:33:08.226503+00:00",
      "is_directory": false,
      "destination_path": null
    },
    {
      "event_type": "moved",
      "path": "/.../test_environment/demo.txt",
      "timestamp": "2026-08-27T08:33:10.231574+00:00",
      "is_directory": false,
      "destination_path": "/.../test_environment/demo_renamed.txt"
    }
  ]
}
```

### `POST /api/monitor/start`
Starts MonitorAgent if not already running (no-op otherwise). Returns the resulting status object. Returns HTTP 500 with a clear message if `settings.monitored_directory` doesn't exist or isn't a directory.

### `POST /api/monitor/stop`
Stops MonitorAgent cleanly (no-op if already stopped). Returns the resulting status object.

All four endpoints appear under the **Monitor** tag in Swagger at `/docs`.

---

## Automated Tests

Run from `backend/` with the virtual environment active:

```powershell
pip install -r requirements.txt
pytest tests/test_monitor_agent.py -v
```

**11 tests, all passing** (verified in this environment):

1. `test_agent_inherits_base_agent_and_starts` — confirms `MonitorAgent` is a `BaseAgent` and starts cleanly
2. `test_uses_configured_directory_not_hardcoded` — confirms it reads `settings.monitored_directory`, not a hardcoded path
3. `test_missing_directory_raises_clear_error` — invalid directory raises `MonitorDirectoryError` instead of crashing
4. `test_created_event_detected`
5. `test_modified_event_detected`
6. `test_moved_event_detected`
7. `test_deleted_event_detected`
8. `test_events_have_required_fields` — every event has `event_type`, `path`, `timestamp`, `is_directory`, `destination_path`
9. `test_stop_releases_observer` — observer reference is cleared after `stop()`
10. `test_duplicate_start_does_not_create_second_observer`
11. `test_restart_after_stop_resumes_monitoring`

---

## Manual Testing (what to do yourself)

1. Start the server as usual:
   ```powershell
   cd sentinel-ai\backend
   .\venv\Scripts\Activate.ps1
   uvicorn app.main:app --reload
   ```
2. Open `http://127.0.0.1:8000/docs` — confirm the **Monitor** section appears alongside **Health** and **System**.
3. `POST /api/monitor/start` → confirm `"running": true` and `"watching"` points at your `test_environment` folder.
4. In `test_environment/`, create a new `.txt` file → `GET /api/monitor/events` → confirm a `"created"` entry.
5. Edit and save that file → confirm a `"modified"` entry.
6. Rename it → confirm a `"moved"` entry with the old path in `"path"` and the new one in `"destination_path"`.
7. Delete it → confirm a `"deleted"` entry.
8. `POST /api/monitor/stop`, then `GET /api/monitor/status` → confirm `"running": false`.
9. `POST /api/monitor/start` twice in a row → confirm no error and no duplicate events start appearing.
10. Re-check `GET /api/health` and `GET /api/system/status` → confirm both Phase 1 endpoints are unaffected.

This exact sequence was run against a live server during development (using a Linux equivalent of `test_environment/`) and produced the expected `created` → `modified` → `moved` → `deleted` sequence, clean start/stop/restart with no duplicate observers, and unaffected Phase 1 endpoints throughout.

---

## Explicitly out of scope for Phase 2 (unchanged from the plan)

No malware scanning, no ML model, no anomaly/threat scoring, no quarantine, no process killing, no automatic modification/deletion of anything outside test files you create yourself, no InvestigationAgent/AnalysisAgent/DecisionAgent/ResponseAgent/Orchestrator, and no database. MonitorAgent only observes and records.

---

# PHASE 2 COMPLETE — READY FOR TESTING

Do not proceed to InvestigationAgent until you've verified Phase 2 yourself using the steps above.
