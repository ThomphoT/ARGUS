"""Base collector interfaces."""

from abc import ABC, abstractmethod
from typing import AsyncIterator

from backend.app.clients.bright_data import BrightDataClient
from backend.app.models import RawFinding


class BaseCollector(ABC):
    def __init__(self, bright_data: BrightDataClient):
        self.bright_data = bright_data

    @abstractmethod
    async def collect(self, company_domain: str) -> AsyncIterator[RawFinding]:
        raise NotImplementedError
