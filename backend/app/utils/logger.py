"""
logger.py

Centralized logging setup for SentinelAI.

Every part of the system (routers, config, and eventually every agent)
should call get_logger(__name__) rather than creating its own logger or
using print(). This keeps log formatting consistent and makes it possible
to later redirect logs to a file, a dashboard, or the Security Memory
component without touching every file that logs something.

Example output:
    2026-08-27 12:00:00 | INFO | SentinelAI | Application started
"""

import logging
import sys

from app.config import settings

# Human-readable log format:
# timestamp | level | logger name | message
LOG_FORMAT = "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


def _configure_root_logger() -> None:
    """
    Configure the root logging handler exactly once.

    This sends log output to stdout (visible in the VS Code / terminal
    window running uvicorn) using the log level defined in .env
    (e.g. INFO, DEBUG, WARNING, ERROR).
    """
    level = getattr(logging, settings.log_level.upper(), logging.INFO)

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter(LOG_FORMAT, datefmt=DATE_FORMAT))

    root_logger = logging.getLogger()
    root_logger.setLevel(level)

    # Avoid attaching duplicate handlers if this module gets imported
    # more than once (e.g. during --reload restarts).
    if not root_logger.handlers:
        root_logger.addHandler(handler)


def get_logger(name: str) -> logging.Logger:
    """
    Return a named logger, e.g. get_logger(__name__) or get_logger("SentinelAI").

    Using a name (rather than the root logger directly) means every log
    line shows exactly which module or agent produced it, which will be
    essential once multiple agents are logging concurrently.
    """
    _configure_root_logger()
    return logging.getLogger(name)
