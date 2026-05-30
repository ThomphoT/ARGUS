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
async def test_web_search_does_not_mock_when_live_credentials_fail(test_settings):
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

    assert first == []
    assert second == []
    assert client.mcp_disabled_for_scan is True
    assert mcp_calls == 1


def test_mcp_text_results_are_normalized(test_settings):
    client = BrightDataClient(test_settings)

    results = client._normalize_mcp_results(
        {
            "result": {
                "content": (
                    "# Supabase Docs\n"
                    "https://supabase.com/docs\n"
                    "Open source Firebase alternative documentation."
                )
            }
        },
        "supabase",
        1,
    )

    assert results[0]["title"] == "Supabase Docs"
    assert results[0]["url"] == "https://supabase.com/docs"
    assert results[0]["via"] == "Bright Data MCP Web Unlocker"


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


def test_mcp_url_replaces_unlock_param_with_unlocker_zone(test_settings):
    configured = test_settings.model_copy(
        update={
            "bright_data_api_token": "abc",
            "bright_data_mcp_url": "https://mcp.brightdata.com/mcp?unlock=old",
        }
    )

    assert "unlock=old" not in configured.bright_data_mcp_unlocker_url
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
