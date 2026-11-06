"""Application settings, read from environment variables / backend/.env."""

from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

REPO_ROOT = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # MySQL in production, e.g. mysql+pymysql://user:pass@localhost:3306/threatdb
    # Falls back to a local SQLite file so the project runs with zero setup.
    database_url: str = f"sqlite:///{REPO_ROOT / 'backend' / 'threats.db'}"
    models_dir: Path = REPO_ROOT / "ml" / "models"
    cors_origins: list[str] = ["http://localhost:5173", "http://127.0.0.1:5173"]
    auto_block_enabled: bool = True


@lru_cache
def get_settings() -> Settings:
    return Settings()
