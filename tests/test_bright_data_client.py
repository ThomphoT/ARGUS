"""Tests for Bright Data MCP, Web Unlocker, and SERP behavior."""

import pytest

from backend.app.clients.bright_data import BrightDataClient


@pytest.mark.asyncio
async def test_web_search_prefers_mcp_results(test_settings):
    client = BrightDataClient(
        test_settings.model_copy(update={"bright_data_api_token": "token"})
    )

    async def fake_mcp(tool_name, arguments):
        return {
            "result": {
                "content": {
                    "organic": [
                        {
                            "title": "MCP hit",
                            "link": "https://example.com/mcp",
                            "snippet": "from mcp",
                        }
                    ]
                }
            }
        }

    client.mcp_tool_call = fake_mcp

    results = await client.web_search("example", 1)

    assert results[0]["title"] == "MCP hit"
    assert results[0]["via"] == "Bright Data MCP Web Unlocker"


@pytest.mark.asyncio
async def test_web_search_falls_back_to_serp_after_mcp_failure(test_settings):
    settings = test_settings.model_copy(
        update={"bright_data_api_token": "token", "bright_data_serp_zone": ""}
    )
    client = BrightDataClient(settings)
    mcp_calls = 0

    async def failing_mcp(tool_name, arguments):
        nonlocal mcp_calls
        mcp_calls += 1
        raise RuntimeError("No valid session ID")

    client.mcp_tool_call = failing_mcp

    first = await client.web_search("example", 1)
    second = await client.web_search("different", 1)

    assert first[0]["via"] == "mock_serp"
    assert second[0]["via"] == "mock_serp"
    assert client.mcp_disabled_for_scan is True
    assert mcp_calls == 1


def test_mcp_url_uses_configured_unlocker_zone(test_settings):
    configured = test_settings.model_copy(update={"bright_data_api_token": "abc"})

    assert configured.bright_data_mcp_unlocker_url == (
        "https://mcp.brightdata.com/mcp?token=abc&unlocker=mcp_unlocker&pro=1"
    )


def test_mcp_url_replaces_legacy_unlock_flag(test_settings):
    configured = test_settings.model_copy(
        update={
            "bright_data_api_token": "abc",
            "bright_data_mcp_url": "https://mcp.brightdata.com/mcp?unlock=1",
        }
    )

    assert "unlock=1" not in configured.bright_data_mcp_unlocker_url
    assert "unlocker=mcp_unlocker" in configured.bright_data_mcp_unlocker_url


def test_unlocker_url_strips_shell_quotes(test_settings):
    configured = test_settings.model_copy(
        update={
            "bright_data_mcp_url": '"https://mcp.brightdata.com/mcp?token=abc&pro=1"'
        }
    )

    assert configured.bright_data_mcp_unlocker_url == (
        "https://mcp.brightdata.com/mcp?token=abc&pro=1&unlocker=mcp_unlocker"
    )
