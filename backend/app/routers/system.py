"""
system.py

GET /api/system/status

Reports basic, safe system resource information (CPU and memory usage)
using psutil. This is read-only, local machine telemetry — no process
inspection, no file scanning, no network activity. In future phases, the
Monitor Agent will build on top of psutil to watch for suspicious resource
spikes, but Phase 1 only exposes the raw numbers.
"""

import psutil
from fastapi import APIRouter

router = APIRouter(prefix="/api/system", tags=["System"])


def _bytes_to_gb(value_bytes: int) -> float:
    """Convert a byte count into gigabytes, rounded to 1 decimal place."""
    return round(value_bytes / (1024 ** 3), 1)


@router.get("/status")
def system_status() -> dict:
    """
    Return current CPU and memory usage.

    - cpu_usage: percentage of CPU currently in use (averaged over a short
      sampling interval).
    - memory_usage: percentage of total RAM currently in use.
    - memory_total_gb: total installed RAM, in GB.
    - memory_available_gb: RAM currently available to new processes, in GB.

    Example response:
        {
          "cpu_usage": 35.2,
          "memory_usage": 61.5,
          "memory_total_gb": 16.0,
          "memory_available_gb": 6.1
        }
    """
    # interval=0.5 makes psutil sample CPU usage over half a second,
    # which gives a much more meaningful reading than an instantaneous
    # (and often 0.0%) snapshot.
    cpu_usage = psutil.cpu_percent(interval=0.5)

    memory = psutil.virtual_memory()

    return {
        "cpu_usage": cpu_usage,
        "memory_usage": memory.percent,
        "memory_total_gb": _bytes_to_gb(memory.total),
        "memory_available_gb": _bytes_to_gb(memory.available),
    }
