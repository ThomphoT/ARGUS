"""Leak scanner using Bright Data SERP API for exposed secrets."""

from typing import AsyncIterator

from backend.app.collectors.base import BaseCollector
from backend.app.models import CollectorName, RawFinding


class LeakScanner(BaseCollector):
    """Find leaked .env files and API keys through Bright Data SERP API queries."""

    async def collect(self, company_domain: str) -> AsyncIterator[RawFinding]:
        queries = [
            f'site:{company_domain} ext:env "API_KEY"',
            f'"{company_domain}" ".env" "SECRET_KEY"',
            f'"{company_domain}" "BEGIN PRIVATE KEY"',
            f'"{company_domain}" "password" "config"',
            f'"{company_domain}" "token" "github"',
        ][: self.bright_data.settings.max_serp_queries]

        for query in queries:
            results = await self.bright_data.web_search(
                query, self.bright_data.settings.max_results_per_query
            )
            for result in results:
                yield RawFinding(
                    company_domain=company_domain,
                    collector=CollectorName.LEAK_SCANNER,
                    title=result["title"],
                    description=result["snippet"],
                    source=result.get("via") or "Bright Data SERP API",
                    url=result.get("url"),
                    evidence={"query": query, "serp_result": result},
                )
