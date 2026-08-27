"""
base_agent.py

Defines BaseAgent: the shared parent class for every agent in SentinelAI.

Future architecture:

    BaseAgent
        │
        ├── MonitorAgent
        ├── InvestigationAgent
        ├── AnalysisAgent
        ├── DecisionAgent
        └── ResponseAgent

None of those subclasses are implemented yet — this is Phase 1, and this
file exists purely to establish the shared contract every agent will
follow: a name, a status, a start() method, a stop() method, and built-in
logging. Putting this in one base class means future agents don't each
reinvent lifecycle management or logging, and the Orchestrator Agent will
be able to treat every agent the same way regardless of what it does
internally.
"""

from enum import Enum

from app.utils.logger import get_logger


class AgentStatus(str, Enum):
    """Possible lifecycle states for any agent."""

    STOPPED = "stopped"
    RUNNING = "running"


class BaseAgent:
    """
    Base class for all SentinelAI agents.

    Subclasses (in future phases) will override `start()` and `stop()`
    to add real behavior (e.g. MonitorAgent watching test_environment/
    for file changes), but every agent will still go through this same
    status tracking and logging.
    """

    def __init__(self, name: str):
        self.name = name
        self.status = AgentStatus.STOPPED
        self.logger = get_logger(f"SentinelAI.{name}")

    def start(self) -> None:
        """
        Mark the agent as running and log it.

        Subclasses should call super().start() first, then add their own
        startup logic (e.g. beginning a file watch, opening a connection).
        """
        self.status = AgentStatus.RUNNING
        self.logger.info("%s started", self.name)

    def stop(self) -> None:
        """
        Mark the agent as stopped and log it.

        Subclasses should add their own cleanup logic, then call
        super().stop() (or vice versa, depending on what needs to
        happen first).
        """
        self.status = AgentStatus.STOPPED
        self.logger.info("%s stopped", self.name)

    def is_running(self) -> bool:
        """Convenience helper for checking agent state."""
        return self.status == AgentStatus.RUNNING

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} name={self.name!r} status={self.status.value}>"
