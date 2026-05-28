"""Runtime configuration for the ARGUS FastAPI backend."""

from functools import lru_cache
from typing import List
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

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
    bright_data_web_unlocker_zone: str = "mcp_unlocker"
    bright_data_mcp_search_tool: str = "search_engine"
    bright_data_country: str = "us"
    max_serp_queries: int = 6
    max_results_per_query: int = 5
    request_timeout_seconds: float = 25.0
    enable_mock_data: bool = True
    cache_ttl_seconds: int = 900
    max_requests_per_minute: int = 30

    llm_provider: str = "auto"
    openai_api_key: str = ""
    openai_model: str = "gpt-4o-mini"
    llm_failure_cooldown_seconds: int = 60
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
        """Return Bright Data remote MCP URL configured with the Web Unlocker zone."""

        mcp_url = self.bright_data_mcp_url.strip().strip("\"'")
        parts = urlsplit(mcp_url)
        query_items = dict(parse_qsl(parts.query, keep_blank_values=True))

        query_items.pop("unlocker", None)
        if self.bright_data_api_token and not query_items.get("token"):
            query_items["token"] = self.bright_data_api_token.strip().strip("\"'")
        unlocker_zone = (
            self.bright_data_web_unlocker_zone.strip().strip("\"'") or "mcp_unlocker"
        )
        if query_items.get("unlock") in (None, "", "1"):
            query_items["unlock"] = unlocker_zone
        if not query_items.get("pro"):
            query_items["pro"] = "1"

        return urlunsplit(
            (
                parts.scheme,
                parts.netloc,
                parts.path,
                urlencode(query_items),
                parts.fragment,
            )
        )


@lru_cache
def get_settings() -> Settings:
    return Settings()
