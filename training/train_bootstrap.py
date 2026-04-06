"""
Vektor AI — Bootstrap Training Pipeline

Pre-trains base models using synthetic data before any customer connects.

Pipeline:
  1. Generate N synthetic environments
  2. For each: generate graph → compute features → label with bootstrap rules
  3. Aggregate into training set
  4. Train one XGBoost model per violation class
  5. Evaluate on held-out environments
  6. Save trained models

Usage:
    python -m training.train_bootstrap --num-environments 50 --output-dir models/v0/
"""

from __future__ import annotations

import argparse
import json
import os
import pickle
import sys
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np
import structlog
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split

logger = structlog.get_logger(__name__)

# Number of violation classes
NUM_CLASSES = 15


def build_training_data(
    num_environments: int = 50,
    seed: int = 42,
) -> tuple[np.ndarray, dict[int, np.ndarray]]:
    """
    Generate training data from synthetic environments.

    Returns:
        X: feature matrix (n_samples, n_features)
        y_by_class: { violation_class: binary_labels_array }
    """
    from data.synthetic.generator import SyntheticConfig, SyntheticDataGenerator
    from backend.features.compute import FeatureComputer
    from backend.features.store import FeatureStore
    from backend.models.bootstrap import BootstrapLabeler

    all_X: list[np.ndarray] = []
    all_labels: dict[int, list[int]] = {c: [] for c in range(1, NUM_CLASSES + 1)}

    for env_idx in range(num_environments):
        logger.info("train.generate_env", env=env_idx + 1, total=num_environments)

        config = SyntheticConfig(
            seed=seed + env_idx,
            num_humans=max(50, 200 + (env_idx * 10) % 100),
            num_service_accounts=max(10, 50 + (env_idx * 3) % 30),
        )

        generator = SyntheticDataGenerator(config)
        graph, ground_truth = generator.generate(config)

        # Compute features
        feature_store = FeatureStore()
        computer = FeatureComputer(graph)
        features = computer.compute_all()
        feature_store.store(features)

        # Get feature matrix
        subject_ids, X_env = feature_store.get_feature_matrix()
        if X_env.size == 0:
            continue

        all_X.append(X_env)

        # Build label vectors from ground truth
        gt_by_subject: dict[str, set[int]] = {}
        for sid, labels in ground_truth.items():
            for lbl in labels:
                if lbl.label == 1:
                    gt_by_subject.setdefault(sid, set()).add(lbl.violation_class)

        for vc in range(1, NUM_CLASSES + 1):
            labels_for_class = []
            for sid in subject_ids:
                violations = gt_by_subject.get(sid, set())
                labels_for_class.append(1 if vc in violations else 0)
            all_labels[vc].extend(labels_for_class)

    X = np.vstack(all_X) if all_X else np.array([])
    y_by_class = {c: np.array(labels) for c, labels in all_labels.items()}

    logger.info(
        "train.data_ready",
        samples=X.shape[0] if X.size > 0 else 0,
        features=X.shape[1] if X.ndim == 2 else 0,
    )
    return X, y_by_class


def train_models(
    X: np.ndarray,
    y_by_class: dict[int, np.ndarray],
    output_dir: str = "models/v0",
) -> dict[str, dict[str, float]]:
    """
    Train one XGBoost model per violation class.

    Returns: { model_id: { accuracy, precision, recall, f1 } }
    """
    try:
        import xgboost as xgb
    except ImportError:
        from sklearn.ensemble import GradientBoostingClassifier as xgb
        logger.warning("train.xgboost_not_available, falling back to sklearn GBM")

    os.makedirs(output_dir, exist_ok=True)

    model_ids = {
        1: "SOX-01", 2: "SOX-02", 3: "ZT-01", 4: "ZT-02",
        5: "ZT-03", 6: "ZT-04", 7: "ZT-05", 8: "ZT-06",
        9: "CB-01", 10: "ZT-07", 11: "SOX-03", 12: "SOX-04",
        13: "SOX-05", 14: "SOX-06", 15: "CB-02",
    }

    results: dict[str, dict[str, float]] = {}

    for vc in range(1, NUM_CLASSES + 1):
        model_id = model_ids.get(vc, f"VC-{vc:02d}")
        y = y_by_class[vc]

        if X.shape[0] == 0 or y.sum() == 0:
            logger.warning("train.skip_class", violation_class=vc, reason="no positive samples")
            continue

        logger.info(
            "train.model",
            model_id=model_id,
            violation_class=vc,
            positive_rate=f"{y.mean():.3f}",
            samples=len(y),
        )

        # Train/test split (stratified)
        try:
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.2, random_state=42, stratify=y
            )
        except ValueError:
            # Not enough samples in minority class for stratification
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.2, random_state=42
            )

        # Handle class imbalance
        n_pos = y_train.sum()
        n_neg = len(y_train) - n_pos
        scale_pos = n_neg / max(n_pos, 1)

        try:
            clf = xgb.XGBClassifier(
                n_estimators=200,
                max_depth=6,
                learning_rate=0.1,
                scale_pos_weight=scale_pos,
                eval_metric="logloss",
                use_label_encoder=False,
                random_state=42,
            )
            clf.fit(X_train, y_train, eval_set=[(X_test, y_test)], verbose=False)
        except Exception:
            # Fallback to sklearn
            from sklearn.ensemble import GradientBoostingClassifier
            clf = GradientBoostingClassifier(
                n_estimators=200, max_depth=6, learning_rate=0.1, random_state=42
            )
            clf.fit(X_train, y_train)

        y_pred = clf.predict(X_test)

        metrics = {
            "accuracy": round(accuracy_score(y_test, y_pred), 4),
            "precision": round(precision_score(y_test, y_pred, zero_division=0), 4),
            "recall": round(recall_score(y_test, y_pred, zero_division=0), 4),
            "f1": round(f1_score(y_test, y_pred, zero_division=0), 4),
        }

        results[model_id] = metrics
        logger.info("train.model_done", model_id=model_id, **metrics)

        # Save model
        model_path = os.path.join(output_dir, f"{model_id}.pkl")
        with open(model_path, "wb") as f:
            pickle.dump({"model": clf, "violation_class": vc, "model_id": model_id, "metrics": metrics}, f)

    # Save summary
    summary_path = os.path.join(output_dir, "training_summary.json")
    with open(summary_path, "w") as f:
        json.dump({
            "trained_at": datetime.now(timezone.utc).isoformat(),
            "models": results,
            "total_samples": X.shape[0] if X.size > 0 else 0,
        }, f, indent=2)

    logger.info("train.complete", models_trained=len(results), output_dir=output_dir)
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="Vektor AI — Bootstrap Model Training")
    parser.add_argument("--num-environments", type=int, default=50)
    parser.add_argument("--output-dir", type=str, default="models/v0")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    structlog.configure(
        processors=[
            structlog.dev.ConsoleRenderer(),
        ],
    )

    logger.info("train.start", environments=args.num_environments, output=args.output_dir)

    X, y_by_class = build_training_data(
        num_environments=args.num_environments,
        seed=args.seed,
    )

    if X.size == 0:
        logger.error("train.no_data")
        sys.exit(1)

    results = train_models(X, y_by_class, output_dir=args.output_dir)

    logger.info("train.summary")
    for model_id, metrics in results.items():
        logger.info(f"  {model_id}: {metrics}")


if __name__ == "__main__":
    main()
