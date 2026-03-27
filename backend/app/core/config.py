"""
Unweaver application configuration.

Uses pydantic-settings to load from environment variables and .env files.
All thresholds and limits for the iterative deobfuscation loop live here.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Central configuration loaded from env vars / .env file."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_prefix="UNWEAVER_",
        case_sensitive=False,
    )

    # ── Database ────────────────────────────────────────────────────────
    DATABASE_URL: str = "sqlite+aiosqlite:///./unweaver.db"

    # ── File handling ───────────────────────────────────────────────────
    UPLOAD_DIR: str = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        "uploads",
    )
    MAX_FILE_SIZE: int = 5 * 1024 * 1024  # 5 MB
    MAX_ARCHIVE_FILE_SIZE: int = 25 * 1024 * 1024  # 25 MB compressed upload
    MAX_ARCHIVE_MEMBER_SIZE: int = 768 * 1024  # 768 KB per extracted text file
    MAX_BUNDLED_SOURCE_SIZE: int = 8 * 1024 * 1024  # 8 MB synthetic workspace text
    MAX_ARCHIVE_FILES: int = 80

    # ── Iterative analysis loop ─────────────────────────────────────────
    MAX_ITERATIONS: int = 20
    AUTO_APPROVE_THRESHOLD: float = 0.85
    MIN_CONFIDENCE_THRESHOLD: float = 0.3
    STALL_THRESHOLD: int = 3  # consecutive iterations without progress

    # ── Misc ────────────────────────────────────────────────────────────
    APP_NAME: str = "Unweaver"
    DEBUG: bool = False
    LOG_LEVEL: str = "INFO"

    # ── CORS ─────────────────────────────────────────────────────────────
    CORS_ORIGINS: str = ""  # comma-separated list; empty = default localhost set

    # ── LLM defaults (can be overridden per-provider in DB) ─────────────
    DEFAULT_LLM_MAX_TOKENS: int = 4096

    # ── Embedded JS tooling bootstrap ────────────────────────────────────
    JS_TOOLING_AUTO_INSTALL: bool = True
    JS_TOOLING_OFFLINE: bool = False
    JS_TOOLING_NPM_CACHE_DIR: str = ""
    JS_TOOLING_INSTALL_TIMEOUT_SECONDS: int = 180

    def ensure_upload_dir(self) -> Path:
        """Create the upload directory if it does not exist and return its Path."""
        p = Path(self.UPLOAD_DIR)
        p.mkdir(parents=True, exist_ok=True)
        return p


settings = Settings()
