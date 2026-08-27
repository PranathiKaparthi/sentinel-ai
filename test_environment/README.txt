This folder is a safe, isolated sandbox for SentinelAI.

In future phases, the Monitor Agent will watch ONLY this folder (not your
entire computer) for file changes, so you can safely test detection logic
by creating, editing, or deleting files here without any risk to real
system files.

Phase 1 does not monitor this folder yet — it is created now so the
project structure and configuration (MONITORED_DIRECTORY in .env) are
already in place for when monitoring is implemented.
