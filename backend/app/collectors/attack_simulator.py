"""Attacker reconnaissance simulator using Bright Data SERP API."""

from typing import AsyncIterator

from backend.app.collectors.base import BaseCollector
from backend.app.models import CollectorName, RawFinding


class AttackSimulator(BaseCollector):
    """Simulate attacker searches for subdomains, cloud buckets, and exposed panels."""

    async def collect(self, company_domain: str) -> AsyncIterator[RawFinding]:
        stem = company_domain.split(".")[0]
        queries = [
            f"site:*.{company_domain} -www",
            f'"{company_domain}" "s3.amazonaws.com"',
            f'"{stem}" "storage.googleapis.com" OR "blob.core.windows.net"',
            f'"{company_domain}" "admin" "login"',
        ][: self.bright_data.settings.max_serp_queries]

        for query in queries:
            results = await self.bright_data.web_search(
                query, self.bright_data.settings.max_results_per_query
            )
            for result in results:
                yield RawFinding(
                    company_domain=company_domain,
                    collector=CollectorName.ATTACK_SIMULATOR,
                    title=result["title"],
                    description=result["snippet"],
                    source=result.get("via") or "Bright Data SERP API",
                    url=result.get("url"),
                    evidence={
                        "query": query,
                        "serp_result": result,
                        "simulation": "attacker_recon",
                    },
                )
