"""Run ARGUS collectors without the frontend for quick Bright Data validation."""

import argparse
import asyncio

from backend.app.clients.bright_data import BrightDataClient
from backend.app.collectors.attack_simulator import AttackSimulator
from backend.app.collectors.domain_monitor import DomainMonitor
from backend.app.collectors.leak_scanner import LeakScanner
from backend.app.collectors.threat_intel import ThreatIntel
from backend.app.core.config import get_settings
from backend.app.utils.domain import normalize_domain


async def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("domain", help="Target company domain, for example example.com")
    parser.add_argument("--attack-mode", action="store_true")
    args = parser.parse_args()

    settings = get_settings()
    domain = normalize_domain(args.domain)
    bright_data = BrightDataClient(settings)
    collectors = [
        LeakScanner(bright_data),
        DomainMonitor(bright_data),
        ThreatIntel(bright_data),
    ]
    if args.attack_mode:
        collectors.append(AttackSimulator(bright_data))

    total = 0
    for collector in collectors:
        print(f"\n[{collector.__class__.__name__}]")
        async for finding in collector.collect(domain):
            total += 1
            print(f"- {finding.title} | {finding.source} | {finding.url or 'no-url'}")

    print(f"\nTotal findings: {total}")
    print(f"Bright Data status: {bright_data.status()}")


if __name__ == "__main__":
    asyncio.run(main())
