"""
Vektor AI — Base Model Interface & Signal Schema

Defines the ``Signal`` output schema and the ``BaseModel`` abstract class
that all Tier 1 and Tier 2 models inherit from.
"""

from __future__ import annotations

import pickle
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import numpy as np

from backend.adapters.models import new_id
from backend.features.compute import FeatureVector


@dataclass
class Signal:
    """A detection emitted by a model — the core output of the scoring loop."""

    signal_id: str = field(default_factory=new_id)
    model_id: str = ""                  # e.g., "SOX-01", "ZT-03"
    entity_id: str = ""                 # subject_id that triggered the signal
    entity_name: str = ""               # display_name for UI
    entity_type: str = ""               # SubjectType value
    source: str = ""                    # which source system(s) involved
    confidence: float = 0.0             # 0.00–1.00
    severity: str = "low"               # critical | high | medium | low
    action: str = ""                    # "revoke_permission", "flag_for_review", etc.
    blast_radius: dict = field(default_factory=dict)
    rollback: str = "staged"            # staged | immediate | manual
    requires_human: bool = True
    explanation: str = ""
    remediation_steps: list[dict] = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    status: str = "pending"             # pending | approved | executed | rolled_back | dismissed


class BaseModel(ABC):
    """
    Base class for all Vektor ML models (Tier 1 and Tier 2).
    """

    model_id: str = ""
    model_name: str = ""
    category: str = ""       # sox | zero_trust | anomaly | agent_gov | cross_boundary
    version: str = "0.1.0"
    violation_class: int = 0  # 1-15

    @abstractmethod
    def predict(self, features: FeatureVector) -> list[Signal]:
        """Run inference on a single subject's feature vector. Returns 0+ Signals."""
        ...

    @abstractmethod
    def predict_batch(
        self, feature_matrix: np.ndarray, subject_ids: list[str]
    ) -> list[Signal]:
        """Batch inference for efficiency."""
        ...

    @abstractmethod
    def train(self, X: np.ndarray, y: np.ndarray, **kwargs: Any) -> dict[str, float]:
        """
        Train or retrain the model.
        Returns metrics: { "accuracy", "precision", "recall", "f1" }
        """
        ...

    @abstractmethod
    def save(self, path: str) -> None:
        ...

    @classmethod
    @abstractmethod
    def load(cls, path: str) -> "BaseModel":
        ...

    def get_confidence_threshold(self) -> float:
        """Below this threshold, signal requires_human=True."""
        return 0.7

    def get_severity(self, confidence: float, blast_radius: dict) -> str:
        """
        Compute severity from confidence + blast radius.
        """
        critical_count = len(blast_radius.get("critical_resources", []))
        total_reach = blast_radius.get("total_reach", 0)

        if confidence > 0.9 and critical_count > 0:
            return "critical"
        if confidence > 0.8 or total_reach > 10:
            return "high"
        if confidence > 0.6:
            return "medium"
        return "low"

    def _make_signal(
        self,
        entity_id: str,
        confidence: float,
        explanation: str,
        action: str = "flag_for_review",
        blast_radius: dict | None = None,
        source: str = "",
        entity_name: str = "",
        entity_type: str = "",
        remediation_steps: list[dict] | None = None,
    ) -> Signal:
        """Helper to construct a Signal with computed severity and human gate."""
        br = blast_radius or {}
        severity = self.get_severity(confidence, br)
        requires_human = confidence < self.get_confidence_threshold() or severity in ("critical", "high")

        return Signal(
            model_id=self.model_id,
            entity_id=entity_id,
            entity_name=entity_name,
            entity_type=entity_type,
            source=source,
            confidence=round(confidence, 4),
            severity=severity,
            action=action,
            blast_radius=br,
            rollback="staged" if severity in ("critical", "high") else "immediate",
            requires_human=requires_human,
            explanation=explanation,
            remediation_steps=remediation_steps or [],
        )
