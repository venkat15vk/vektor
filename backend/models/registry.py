"""
Vektor AI — Model Registry

Manages registration, loading, versioning, and batch scoring of all Tier 1
and Tier 2 models.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

import numpy as np
import structlog

from backend.features.store import FeatureStore

from .base import BaseModel, Signal

logger = structlog.get_logger(__name__)


class ModelRegistry:
    """
    Registry of all Tier 1 and Tier 2 models.
    Manages model lifecycle: register, load, version, score.
    """

    def __init__(self) -> None:
        self._models: dict[str, BaseModel] = {}

    def register(self, model: BaseModel) -> None:
        """Register a model. Overwrites any existing model with the same ID."""
        self._models[model.model_id] = model
        logger.info(
            "registry.register",
            model_id=model.model_id,
            name=model.model_name,
            category=model.category,
            version=model.version,
        )

    def get(self, model_id: str) -> BaseModel | None:
        return self._models.get(model_id)

    def list_models(self) -> list[dict[str, Any]]:
        return [
            {
                "model_id": m.model_id,
                "model_name": m.model_name,
                "category": m.category,
                "version": m.version,
                "violation_class": m.violation_class,
            }
            for m in self._models.values()
        ]

    def score_all(self, feature_store: FeatureStore) -> list[Signal]:
        """
        Run ALL registered models against ALL subjects in the feature store.
        Returns aggregated, deduplicated, ranked list of signals.
        """
        if not self._models:
            logger.warning("registry.score_all.no_models")
            return []

        all_features = feature_store.get_all()
        if not all_features:
            logger.warning("registry.score_all.no_features")
            return []

        logger.info(
            "registry.score_all.start",
            models=len(self._models),
            subjects=len(all_features),
        )

        all_signals: list[Signal] = []

        for model_id, model in self._models.items():
            model_signals: list[Signal] = []
            for subject_id, fv in all_features.items():
                try:
                    signals = model.predict(fv)
                    model_signals.extend(signals)
                except Exception as exc:
                    logger.error(
                        "registry.predict_failed",
                        model_id=model_id,
                        subject_id=subject_id,
                        error=str(exc),
                    )

            logger.info(
                "registry.model_scored",
                model_id=model_id,
                signals=len(model_signals),
            )
            all_signals.extend(model_signals)

        # Deduplicate: same model + same entity = keep highest confidence
        deduped = self._deduplicate_signals(all_signals)

        # Rank: critical first, then high, medium, low; within severity by confidence desc
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        deduped.sort(
            key=lambda s: (severity_order.get(s.severity, 4), -s.confidence)
        )

        logger.info("registry.score_all.done", total_signals=len(deduped))
        return deduped

    def register_tier2(self, policy_id: str, model: BaseModel) -> None:
        """Register a Tier 2 customer-specific model."""
        model.model_id = f"T2-{policy_id}"
        self.register(model)

    @staticmethod
    def _deduplicate_signals(signals: list[Signal]) -> list[Signal]:
        """Keep highest-confidence signal per (model_id, entity_id) pair."""
        best: dict[tuple[str, str], Signal] = {}
        for s in signals:
            key = (s.model_id, s.entity_id)
            existing = best.get(key)
            if existing is None or s.confidence > existing.confidence:
                best[key] = s
        return list(best.values())
