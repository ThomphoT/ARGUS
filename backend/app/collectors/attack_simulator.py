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
            f"site:*.{company_domain} intitle:index.of",
            f"site:dev.{company_domain} OR site:staging.{company_domain} OR site:test.{company_domain}",
            f"site:api.{company_domain} OR site:admin.{company_domain} OR site:portal.{company_domain}",
            f'site:{company_domain} (ext:env OR ext:conf OR filetype:env OR filetype:conf)',
            f'"{company_domain}" ".git/config"',
            f'"{company_domain}" "s3.amazonaws.com" OR "{stem}" "s3 bucket"',
            f'"{stem}" "storage.googleapis.com" OR "{stem}" "blob.core.windows.net"',
            f'"{company_domain}" "api_key" OR "{company_domain}" "secret"',
            f'"{company_domain}" "jira" OR "{company_domain}" "jenkins"',
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
                        "defense_recommendation": self._defense_recommendation(query),
                    },
                )

    def _defense_recommendation(self, query: str) -> str:
        if ".git/config" in query:
            return "Block public access to VCS metadata, purge indexed repository paths, and rotate credentials found in commit history."
        if "ext:env" in query or "filetype:env" in query or "conf" in query:
            return "Remove exposed configuration files, rotate secrets, and add server rules that deny dotfiles and config extensions."
        if "s3" in query or "storage.googleapis.com" in query or "blob.core.windows.net" in query:
            return "Audit bucket policies, disable public listing, and enforce least-privilege IAM on cloud storage."
        if "site:*." in query:
            return "Inventory exposed subdomains, close abandoned hosts, and restrict sensitive services behind SSO or VPN."
        return "Review exposed admin surfaces, enforce MFA, and rate-limit suspicious reconnaissance traffic."
