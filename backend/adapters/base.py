"""
Vektor AI — Abstract Base Adapter

All identity source adapters inherit from BaseAdapter.
Adapters are read-only — they never mutate the source system during extraction.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

import structlog

from .models import GraphSnapshot

logger = structlog.get_logger(__name__)


class BaseAdapter(ABC):
    """
    Abstract base for all identity source adapters.

    Contract:
      1. ``connect()`` validates credentials and establishes a session.
      2. ``extract()`` performs a full read-only extraction, returning a
         ``GraphSnapshot`` containing all subjects, permissions, resources,
         assignments, and detected escalation paths.
      3. ``test_connection()`` is a lightweight reachability check.
      4. ``disconnect()`` tears down sessions/connections.

    All methods are async because source APIs may be slow and we want
    concurrent extraction across adapters.
    """

    source_name: str  # e.g., "aws_iam", "okta", "entra", "netsuite"

    @abstractmethod
    async def connect(self, credentials: dict) -> None:
        """Validate credentials and establish connection. Raise on failure."""
        ...

    @abstractmethod
    async def extract(self) -> GraphSnapshot:
        """
        Full extraction: pull all subjects, permissions, resources, assignments.
        Detect escalation paths during extraction where possible.
        Return a complete GraphSnapshot.
        """
        ...

    @abstractmethod
    async def test_connection(self) -> bool:
        """Lightweight connectivity check. Returns True if source is reachable."""
        ...

    async def disconnect(self) -> None:
        """Clean up connections/sessions. Override if needed."""
        logger.info("adapter.disconnect", source=self.source_name)
