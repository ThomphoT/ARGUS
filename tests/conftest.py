"""Test fixtures for the ARGUS backend."""

from collections.abc import Iterator

import pytest

from backend.app.core.config import Settings, get_settings
from backend.app.main import app


@pytest.fixture
def test_settings(tmp_path) -> Settings:
    return Settings(
        bright_data_api_token="",
        bright_data_serp_zone="",
        enable_mock_data=True,
        max_serp_queries=1,
        max_results_per_query=1,
        cognee_enabled=False,
        llm_provider="ollama",
        local_memory_path=str(tmp_path / "memory.jsonl"),
    )


@pytest.fixture
def test_app(test_settings: Settings) -> Iterator:
    app.dependency_overrides.clear()
    get_settings.cache_clear()
    yield app
    app.dependency_overrides.clear()
    get_settings.cache_clear()
