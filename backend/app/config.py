import os
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Optional

class Settings(BaseSettings):
    PROJECT_NAME: str = "AI-Powered Email Threat Investigation Platform"
    API_V1_STR: str = "/api"
    
    # Database Configuration
    # Defaults to SQLite in the local directory for ease of setup.
    # Can be overridden with a PostgreSQL URL (e.g. postgresql+asyncpg://user:pass@localhost/dbname)
    DATABASE_URL: str = "sqlite+aiosqlite:///./email_investigator.db"
    
    # Threat Intelligence API Keys (optional, system degrades gracefully if empty)
    VIRUSTOTAL_API_KEY: Optional[str] = None
    ABUSEIPDB_API_KEY: Optional[str] = None
    URLSCAN_API_KEY: Optional[str] = None
    
    # AI/LLM Provider Keys
    OPENAI_API_KEY: Optional[str] = None
    GEMINI_API_KEY: Optional[str] = None
    
    # Chosen AI Provider: "gemini" or "openai"
    # Default is gemini since the environment might have it or user may prefer it
    AI_PROVIDER: str = "gemini"
    
    # Organization Settings for BEC and Impersonation Detection
    # List of high-profile target names in the organization (e.g. CEO, CFO)
    ORG_VIP_NAMES: list[str] = ["John Doe", "Jane Smith", "Alice Chief"]
    # Internal domains to detect spoofing / lookalikes
    ORG_INTERNAL_DOMAINS: list[str] = ["mycompany.com", "mycorp.org"]

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

settings = Settings()
