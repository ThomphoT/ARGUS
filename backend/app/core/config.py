"""Runtime configuration for the ARGUS FastAPI backend."""

from functools import lru_cache
from typing import List

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Environment-backed settings.

    Bright Data MCP, Web Unlocker, and SERP API values are configurable so the
    hackathon demo can run locally with mock data or against live infrastructure.
    """

    app_name: str = "ARGUS"
    environment: str = "development"
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    cors_origins: List[str] = Field(default_factory=lambda: ["*"])

    bright_data_mcp_url: str = "https://mcp.brightdata.com/mcp"
    bright_data_api_token: str = ""
    bright_data_serp_endpoint: str = "https://api.brightdata.com/request"
    bright_data_serp_zone: str = ""
    bright_data_web_unlocker_zone: str = ""
    bright_data_country: str = "us"
    max_serp_queries: int = 6
    max_results_per_query: int = 5
    request_timeout_seconds: float = 25.0

    ollama_host: str = "http://localhost:11434"
    ollama_model: str = "chevalblanc/gpt-4o-mini"

    cognee_enabled: bool = True
    cognee_dataset: str = "argus-threat-memory"
    local_memory_path: str = "backend/data/threat_memory.jsonl"

    triggerware_webhook_url: str = ""
    triggerware_secret: str = ""

    model_config = SettingsConfigDict(
        env_file=("backend/.env", ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    @property
    def bright_data_mcp_unlocker_url(self) -> str:
        """Return Bright Data MCP URL with Web Unlocker enabled via unlock=1."""

        separator = "&" if "?" in self.bright_data_mcp_url else "?"
        if "unlock=1" in self.bright_data_mcp_url:
            return self.bright_data_mcp_url
        return f"{self.bright_data_mcp_url}{separator}unlock=1"


@lru_cache
def get_settings() -> Settings:
    return Settings()
