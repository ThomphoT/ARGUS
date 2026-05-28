"""Threat intelligence collector for forums, paste sites, and leak chatter."""

from typing import AsyncIterator

from backend.app.collectors.base import BaseCollector
from backend.app.models import CollectorName, RawFinding


class ThreatIntel(BaseCollector):
    """Monitor public paste/forum signals through Bright Data MCP and SERP API."""

    async def collect(self, company_domain: str) -> AsyncIterator[RawFinding]:
        queries = [
            f'"{company_domain}" "pastebin" "password"',
            f'"{company_domain}" "leaked" "credentials"',
            f'"{company_domain}" "breach" "token"',
            f'"{company_domain}" "dark web" "database"',
        ][: self.bright_data.settings.max_serp_queries]

        for query in queries:
            results = await self.bright_data.web_search(
                query, self.bright_data.settings.max_results_per_query
            )
            for result in results:
                yield RawFinding(
                    company_domain=company_domain,
                    collector=CollectorName.THREAT_INTEL,
                    title=result["title"],
                    description=result["snippet"],
                    source=result.get("via") or "Bright Data SERP API",
                    url=result.get("url"),
                    evidence={
                        "query": query,
                        "serp_result": result,
                        "monitoring": "paste_forum_threat_intel",
                    },
                )
