"""Typosquatting monitor backed by Bright Data SERP API."""

from typing import AsyncIterator

from backend.app.collectors.base import BaseCollector
from backend.app.models import CollectorName, RawFinding
from backend.app.utils.domain import typosquat_variants


class DomainMonitor(BaseCollector):
    """Scan typosquatting variations of a brand with Bright Data SERP API."""

    async def collect(self, company_domain: str) -> AsyncIterator[RawFinding]:
        variants = typosquat_variants(
            company_domain, self.bright_data.settings.max_serp_queries
        )
        for variant in variants:
            query = f'"{variant}" OR site:{variant}'
            results = await self.bright_data.serp_search(
                query, self.bright_data.settings.max_results_per_query
            )
            for result in results:
                yield RawFinding(
                    company_domain=company_domain,
                    collector=CollectorName.DOMAIN_MONITOR,
                    title=f"Brand-adjacent domain signal: {variant}",
                    description=result["snippet"],
                    url=result.get("url"),
                    evidence={
                        "variant": variant,
                        "query": query,
                        "serp_result": result,
                    },
                )
