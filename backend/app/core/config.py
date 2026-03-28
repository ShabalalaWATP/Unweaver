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
    MAX_FILE_SIZE: int = 20 * 1024 * 1024  # 20 MB
    MAX_ARCHIVE_FILE_SIZE: int = 128 * 1024 * 1024  # 128 MB compressed upload
    MAX_ARCHIVE_MEMBER_SIZE: int = 4 * 1024 * 1024  # 4 MB per extracted text file
    MAX_BUNDLED_SOURCE_SIZE: int = 48 * 1024 * 1024  # 48 MB synthetic workspace text
    MAX_ARCHIVE_FILES: int = 224
    MAX_ARCHIVE_SCAN_FILES: int = 1500
    MAX_WORKSPACE_TARGET_FILES: int = 28
    MAX_WORKSPACE_BUNDLE_ADDITIONS: int = 24
    MAX_WORKSPACE_LLM_FOCUS_FILES: int = 8
    MAX_WORKSPACE_ACTION_ATTEMPTS: int = 128

    # ── Iterative analysis loop ─────────────────────────────────────────
    MAX_ITERATIONS: int = 36
    MAX_WORKSPACE_ITERATIONS: int = 128
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
    LLM_GENERATOR_CRITIC_ENABLED: bool = True
    LLM_DEOBFUSCATE_CANDIDATES: int = 2
    LLM_MULTILAYER_CANDIDATES: int = 2
    LLM_CRITIC_MAX_CODE_CHARS: int = 1800
    LLM_SHADOW_RECOVERY_ENABLED: bool = True
    LLM_SHADOW_RECOVERY_MAX_CODE_CHARS: int = 120_000
    LLM_SHADOW_RECOVERY_MAX_WORKSPACE_FILES: int = 48
    LLM_SHADOW_RECOVERY_MIN_SCORE_GAIN: float = 0.04
    LLM_SHADOW_RECOVERY_MAX_SCORE_DEFICIT: float = 0.08

    # ── Automated benchmark corpus / scoring ───────────────────────────
    BENCHMARK_AUTO_RUN_ON_STARTUP: bool = True
    BENCHMARK_AUTO_RUN_ON_PROVIDER_TEST: bool = True
    BENCHMARK_MIN_RERUN_HOURS: int = 24
    BENCHMARK_MAX_CASES: int = 4
    BENCHMARK_MAX_ITERATIONS: int = 10
    BENCHMARK_MAX_WORKSPACE_ITERATIONS: int = 12

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
