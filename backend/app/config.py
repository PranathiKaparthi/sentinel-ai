"""
config.py

Centralized application configuration.

This module reads values from the .env file (using python-dotenv) and
exposes them as a single, typed `settings` object that the rest of the
application imports from. Every future agent and router should pull
configuration from here rather than reading environment variables directly,
so there is exactly one source of truth for settings.
"""

import os
from dataclasses import dataclass

from dotenv import load_dotenv

# Load variables from the .env file into the process environment.
# This must happen before we read any os.environ values below.
load_dotenv()


@dataclass
class Settings:
    """
    Typed container for application settings.

    Using a dataclass gives us autocompletion and type hints when accessing
    settings elsewhere in the code (e.g. settings.app_name), instead of
    scattering os.getenv() calls throughout the codebase.
    """

    app_name: str
    app_env: str
    log_level: str
    monitored_directory: str


def get_settings() -> Settings:
    """
    Build and return a Settings instance from the current environment.

    Defaults are provided for every value so the application can still
    start (in a safe, obvious way) even if a variable is missing from .env.
    """
    return Settings(
        app_name=os.getenv("APP_NAME", "SentinelAI"),
        app_env=os.getenv("APP_ENV", "development"),
        log_level=os.getenv("LOG_LEVEL", "INFO"),
        monitored_directory=os.getenv("MONITORED_DIRECTORY", "../test_environment"),
    )


# A single shared settings instance, imported by the rest of the app.
settings = get_settings()
