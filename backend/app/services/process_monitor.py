"""
process_monitor.py

Read-only process inspection for SentinelAI (Phase 11).

Uses psutil to list running processes and flag ones that look unusual,
using simple, explainable rules. Like the rest of SentinelAI it only
observes and reports: it never kills, suspends, or modifies a process.

Rules (each adds points to a 0-100 risk score):
    - High CPU usage                         +30
    - High memory usage                      +20
    - Executable running from a temp,
      downloads, or public folder            +35
    - Name imitates a Windows system process
      (e.g. "svch0st.exe" vs "svchost.exe")  +40
    - Script host running (powershell, wscript, etc.) +10

Score -> level uses the same bands as the file analysis:
    0-30 LOW, 31-60 MEDIUM, 61-85 HIGH, 86-100 CRITICAL.
"""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from difflib import SequenceMatcher
from typing import Iterable, Optional

import psutil

from app.utils.logger import get_logger

logger = get_logger("SentinelAI.ProcessMonitor")

# Thresholds (percent).
CPU_THRESHOLD = 80.0
MEMORY_THRESHOLD = 25.0

# Folders where legitimate programs rarely run from.
_RISKY_DIR_MARKERS = (
    "\\temp\\",
    "\\tmp\\",
    "\\appdata\\local\\temp\\",
    "\\downloads\\",
    "\\users\\public\\",
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
    "/downloads/",
)

# Well-known Windows system process names that malware often imitates.
_SYSTEM_PROCESS_NAMES = (
    "svchost.exe",
    "lsass.exe",
    "csrss.exe",
    "winlogon.exe",
    "explorer.exe",
    "services.exe",
    "smss.exe",
)

# Genuine Windows processes whose names happen to look like the names above
# (e.g. sihost.exe vs svchost.exe). They are not disguises.
_KNOWN_WINDOWS_PROCESSES = {
    "sihost.exe", "dllhost.exe", "conhost.exe", "taskhostw.exe", "fontdrvhost.exe",
    "dwm.exe", "ctfmon.exe", "runtimebroker.exe", "searchhost.exe", "wininit.exe",
    "spoolsv.exe", "audiodg.exe", "lsaiso.exe", "smartscreen.exe",
    "startmenuexperiencehost.exe", "shellexperiencehost.exe",
}

# Folders that genuine Windows system programs run from.
_TRUSTED_SYSTEM_DIRS = ("\\windows\\system32\\", "\\windows\\syswow64\\")

# Not real programs: Windows' idle-time counter and kernel placeholder.
_PSEUDO_PROCESSES = {"system idle process", "idle"}

_SCRIPT_HOSTS = ("powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe")


@dataclass
class ProcessInfo:
    """A snapshot of one running process plus any risk findings."""

    pid: int
    name: str
    exe: Optional[str]
    username: Optional[str]
    cpu_percent: float
    memory_percent: float
    risk_score: int = 0
    risk_level: str = "LOW"
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def score_to_level(score: int) -> str:
    """Convert a 0-100 score to LOW / MEDIUM / HIGH / CRITICAL."""
    if score <= 30:
        return "LOW"
    if score <= 60:
        return "MEDIUM"
    if score <= 85:
        return "HIGH"
    return "CRITICAL"


def _looks_like_system_name(name: str) -> Optional[str]:
    """
    Return the system name being imitated, or None.

    A name that is very similar (but not equal) to a system process name
    is a classic disguise, e.g. "scvhost.exe" or "svch0st.exe".
    """
    lowered = name.lower()
    if lowered in _KNOWN_WINDOWS_PROCESSES:
        return None
    for real in _SYSTEM_PROCESS_NAMES:
        if lowered == real:
            return None
        if SequenceMatcher(None, lowered, real).ratio() >= 0.85:
            return real
    return None


def assess(info: ProcessInfo) -> ProcessInfo:
    """Apply the risk rules to one process snapshot (pure function, easy to test)."""
    score = 0
    reasons: list[str] = []

    if info.cpu_percent >= CPU_THRESHOLD:
        score += 30
        reasons.append(f"High CPU usage: {info.cpu_percent:.1f}%")

    if info.memory_percent >= MEMORY_THRESHOLD:
        score += 20
        reasons.append(f"High memory usage: {info.memory_percent:.1f}%")

    exe = (info.exe or "").lower()
    if any(marker in exe for marker in _RISKY_DIR_MARKERS):
        score += 35
        reasons.append(f"Running from a temporary or downloads folder: {info.exe}")

    imitated = _looks_like_system_name(info.name or "")
    in_trusted_dir = any(d in exe for d in _TRUSTED_SYSTEM_DIRS)
    if imitated and not in_trusted_dir:
        score += 40
        where = f" (running from {info.exe})" if info.exe else " (location hidden; check it in Task Manager)"
        reasons.append(f"Name imitates system process {imitated}: {info.name}{where}")

    if (info.name or "").lower() in _SCRIPT_HOSTS:
        score += 10
        reasons.append(f"Script host running: {info.name}")

    info.risk_score = max(0, min(100, score))
    info.risk_level = score_to_level(info.risk_score)
    info.reasons = reasons
    return info


class ProcessMonitor:
    """Takes snapshots of running processes and flags suspicious ones."""

    @staticmethod
    def snapshot(sample_seconds: float = 0.5) -> list[ProcessInfo]:
        """
        Return a list of ProcessInfo for all accessible processes.

        CPU percent needs two readings, so we prime every process, wait
        `sample_seconds`, then read again. Processes that exit or deny
        access in between are skipped.
        """
        procs = [
            p for p in psutil.process_iter(["pid", "name", "exe", "username"])
            if p.info.get("pid") != 0
            and (p.info.get("name") or "").lower() not in _PSEUDO_PROCESSES
        ]
        # psutil reports CPU per core (a busy process can show 400% on a
        # 4-core machine). Divide by the core count so 100% = whole machine,
        # matching Task Manager.
        cores = psutil.cpu_count() or 1
        for proc in procs:
            try:
                proc.cpu_percent(None)  # first call primes the counter
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        time.sleep(sample_seconds)

        results: list[ProcessInfo] = []
        for proc in procs:
            try:
                results.append(
                    ProcessInfo(
                        pid=proc.info["pid"],
                        name=proc.info.get("name") or "",
                        exe=proc.info.get("exe"),
                        username=proc.info.get("username"),
                        cpu_percent=round(proc.cpu_percent(None) / cores, 1),
                        memory_percent=round(proc.memory_percent(), 2),
                    )
                )
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        return results

    @staticmethod
    def find_suspicious(
        processes: Optional[Iterable[ProcessInfo]] = None,
        min_score: int = 31,
    ) -> list[ProcessInfo]:
        """
        Assess processes and return those scoring at least `min_score`
        (default 31 = MEDIUM or above), highest risk first.

        `processes` can be passed in directly, which keeps tests fast and
        independent of what is running on the test machine.
        """
        if processes is None:
            processes = ProcessMonitor.snapshot()

        flagged = [p for p in (assess(p) for p in processes) if p.risk_score >= min_score]
        flagged.sort(key=lambda p: p.risk_score, reverse=True)
        logger.info("Process scan flagged %d process(es)", len(flagged))
        return flagged

    @staticmethod
    def top_processes(limit: int = 10, by: str = "cpu") -> list[ProcessInfo]:
        """Return the top `limit` processes by CPU or memory usage."""
        processes = [assess(p) for p in ProcessMonitor.snapshot()]
        key = (lambda p: p.memory_percent) if by == "memory" else (lambda p: p.cpu_percent)
        return sorted(processes, key=key, reverse=True)[:limit]
