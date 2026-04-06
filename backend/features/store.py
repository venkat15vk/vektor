"""
Vektor AI — Feature Store

Stores and retrieves computed feature vectors.
Phase 1: In-memory dict with historical snapshot archiving.
Phase 2: Redis for hot features, PostgreSQL for historical.
"""

from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
from typing import Any

import numpy as np
import structlog

from .compute import FeatureVector

logger = structlog.get_logger(__name__)


class FeatureStore:
    """
    Stores and retrieves computed feature vectors.

    Phase 1: In-memory dict.
    Phase 2: Redis for hot features, PostgreSQL for historical feature snapshots.
    """

    def __init__(self) -> None:
        self._store: dict[str, FeatureVector] = {}
        self._history: list[dict[str, FeatureVector]] = []  # archived snapshots

    def store(self, features: dict[str, FeatureVector]) -> None:
        """Store latest feature vectors. Archive the previous snapshot as history."""
        if self._store:
            self._history.append(copy.deepcopy(self._store))
            # Keep at most 100 historical snapshots
            if len(self._history) > 100:
                self._history = self._history[-100:]

        self._store = features
        logger.info("feature_store.stored", subjects=len(features), history_depth=len(self._history))

    def get(self, subject_id: str) -> FeatureVector | None:
        """Get the latest feature vector for a subject."""
        return self._store.get(subject_id)

    def get_all(self) -> dict[str, FeatureVector]:
        """Get all latest feature vectors."""
        return dict(self._store)

    def get_feature_matrix(self) -> tuple[list[str], np.ndarray]:
        """
        Returns (subject_ids, feature_matrix) where feature_matrix is
        a numpy array of shape (n_subjects, n_features) for batch model inference.
        """
        if not self._store:
            return [], np.array([])

        subject_ids: list[str] = []
        rows: list[np.ndarray] = []

        for sid, fv in self._store.items():
            subject_ids.append(sid)
            rows.append(fv.to_flat_array())

        feature_matrix = np.vstack(rows)
        logger.info(
            "feature_store.matrix",
            shape=feature_matrix.shape,
        )
        return subject_ids, feature_matrix

    def get_historical(
        self, subject_id: str, lookback_days: int = 90
    ) -> list[FeatureVector]:
        """Get historical feature vectors for a subject within lookback window."""
        cutoff = datetime.now(timezone.utc) - timedelta(days=lookback_days)
        results: list[FeatureVector] = []

        for snapshot in self._history:
            fv = snapshot.get(subject_id)
            if fv and fv.computed_at >= cutoff:
                results.append(fv)

        # Add current if available
        current = self._store.get(subject_id)
        if current:
            results.append(current)

        return results

    def get_subject_ids(self) -> list[str]:
        """Get all subject IDs with stored features."""
        return list(self._store.keys())

    def count(self) -> int:
        """Number of subjects with stored features."""
        return len(self._store)

    def clear(self) -> None:
        """Clear all stored features (current and historical)."""
        self._store.clear()
        self._history.clear()
        logger.info("feature_store.cleared")
