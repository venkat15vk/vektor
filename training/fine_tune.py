"""
Vektor AI — Customer Fine-Tuning Pipeline

Fine-tunes base models on a specific customer's data using:
  - Bootstrap labels (from BootstrapLabeler)
  - Human labels (from active learning / signal review)
  - Implicit labels (executed signal = positive, dismissed = negative)

Usage:
    python -m training.fine_tune \
        --base-model models/v0/SOX-01.pkl \
        --customer-id acme \
        --features features/acme/ \
        --labels labels/acme/ \
        --output models/acme/SOX-01.pkl
"""

from __future__ import annotations

import argparse
import json
import os
import pickle
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np
import structlog
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split

logger = structlog.get_logger(__name__)


def load_base_model(path: str) -> dict[str, Any]:
    """Load a pre-trained base model from disk."""
    with open(path, "rb") as f:
        data = pickle.load(f)
    logger.info(
        "fine_tune.load_base",
        model_id=data.get("model_id"),
        violation_class=data.get("violation_class"),
        base_metrics=data.get("metrics"),
    )
    return data


def load_labels(
    labels_dir: str, violation_class: int
) -> tuple[dict[str, int], dict[str, float]]:
    """
    Load all label sources for a violation class.

    Looks for:
      - bootstrap_labels.json  (from BootstrapLabeler)
      - human_labels.json      (from active learning / analyst review)
      - implicit_labels.json   (executed=positive, dismissed=negative)

    Returns:
        labels: { subject_id: 0 or 1 }
        weights: { subject_id: sample_weight }
    """
    labels: dict[str, int] = {}
    weights: dict[str, float] = {}

    # Bootstrap labels (silver — lowest weight)
    bootstrap_path = os.path.join(labels_dir, "bootstrap_labels.json")
    if os.path.exists(bootstrap_path):
        with open(bootstrap_path) as f:
            raw = json.load(f)
        for sid, label_list in raw.items():
            for lbl in label_list:
                if lbl.get("violation_class") == violation_class:
                    labels[sid] = lbl.get("label", 0)
                    weights[sid] = lbl.get("confidence", 0.5) * 0.6  # discounted
        logger.info("fine_tune.bootstrap_labels", count=len(labels))

    # Human labels (gold — highest weight)
    human_path = os.path.join(labels_dir, "human_labels.json")
    if os.path.exists(human_path):
        with open(human_path) as f:
            raw = json.load(f)
        for sid, label_list in raw.items():
            for lbl in label_list:
                if lbl.get("violation_class") == violation_class:
                    labels[sid] = lbl.get("label", 0)
                    weights[sid] = 1.0  # full weight
        logger.info("fine_tune.human_labels_loaded")

    # Implicit labels (from signal feedback — medium weight)
    implicit_path = os.path.join(labels_dir, "implicit_labels.json")
    if os.path.exists(implicit_path):
        with open(implicit_path) as f:
            raw = json.load(f)
        for sid, label_list in raw.items():
            for lbl in label_list:
                if lbl.get("violation_class") == violation_class:
                    labels[sid] = lbl.get("label", 0)
                    weights[sid] = 0.8
        logger.info("fine_tune.implicit_labels_loaded")

    return labels, weights


def load_features(features_dir: str) -> tuple[list[str], np.ndarray]:
    """
    Load customer feature vectors from disk.

    Expects: features.npz with 'subject_ids' and 'matrix' arrays.
    """
    fpath = os.path.join(features_dir, "features.npz")
    if not os.path.exists(fpath):
        logger.error("fine_tune.features_not_found", path=fpath)
        return [], np.array([])

    data = np.load(fpath, allow_pickle=True)
    subject_ids = list(data["subject_ids"])
    matrix = data["matrix"]

    logger.info("fine_tune.features_loaded", subjects=len(subject_ids), shape=matrix.shape)
    return subject_ids, matrix


def fine_tune(
    base_model_path: str,
    customer_id: str,
    features_dir: str,
    labels_dir: str,
    output_path: str,
    learning_rate: float = 0.01,
    n_estimators: int = 100,
    early_stopping_rounds: int = 10,
) -> dict[str, float]:
    """
    Fine-tune a base model on customer data.

    Returns training metrics.
    """
    # 1. Load base model
    base_data = load_base_model(base_model_path)
    base_clf = base_data["model"]
    violation_class = base_data["violation_class"]
    model_id = base_data["model_id"]

    # 2. Load customer features
    subject_ids, X = load_features(features_dir)
    if X.size == 0:
        logger.error("fine_tune.no_features")
        return {}

    # 3. Load labels
    labels, sample_weights = load_labels(labels_dir, violation_class)

    if not labels:
        logger.warning("fine_tune.no_labels", violation_class=violation_class)
        return {}

    # 4. Build aligned training data
    X_train_rows: list[np.ndarray] = []
    y_train: list[int] = []
    w_train: list[float] = []

    sid_to_idx = {sid: i for i, sid in enumerate(subject_ids)}
    for sid, label in labels.items():
        idx = sid_to_idx.get(sid)
        if idx is not None:
            X_train_rows.append(X[idx])
            y_train.append(label)
            w_train.append(sample_weights.get(sid, 0.5))

    if not X_train_rows:
        logger.warning("fine_tune.no_aligned_data")
        return {}

    X_ft = np.vstack(X_train_rows)
    y_ft = np.array(y_train)
    w_ft = np.array(w_train)

    logger.info(
        "fine_tune.data_ready",
        samples=len(y_ft),
        positive_rate=f"{y_ft.mean():.3f}",
        model_id=model_id,
    )

    # 5. Train/test split
    try:
        X_tr, X_te, y_tr, y_te, w_tr, w_te = train_test_split(
            X_ft, y_ft, w_ft, test_size=0.2, random_state=42, stratify=y_ft
        )
    except ValueError:
        X_tr, X_te, y_tr, y_te, w_tr, w_te = train_test_split(
            X_ft, y_ft, w_ft, test_size=0.2, random_state=42
        )

    # 6. Fine-tune with warm start from base model
    n_pos = y_tr.sum()
    n_neg = len(y_tr) - n_pos
    scale_pos = n_neg / max(n_pos, 1)

    try:
        import xgboost as xgb

        clf = xgb.XGBClassifier(
            n_estimators=n_estimators,
            max_depth=6,
            learning_rate=learning_rate,
            scale_pos_weight=scale_pos,
            eval_metric="logloss",
            use_label_encoder=False,
            random_state=42,
        )

        # If base model is XGBoost, use xgb_model for warm start
        if hasattr(base_clf, "get_booster"):
            base_model_file = output_path + ".base_temp.json"
            base_clf.save_model(base_model_file)
            clf.fit(
                X_tr, y_tr,
                sample_weight=w_tr,
                eval_set=[(X_te, y_te)],
                verbose=False,
                xgb_model=base_model_file,
            )
            os.remove(base_model_file)
        else:
            clf.fit(X_tr, y_tr, sample_weight=w_tr, eval_set=[(X_te, y_te)], verbose=False)

    except (ImportError, Exception) as exc:
        logger.warning("fine_tune.xgb_fallback", error=str(exc))
        from sklearn.ensemble import GradientBoostingClassifier
        clf = GradientBoostingClassifier(
            n_estimators=n_estimators, max_depth=6,
            learning_rate=learning_rate, random_state=42,
        )
        clf.fit(X_tr, y_tr, sample_weight=w_tr)

    # 7. Evaluate
    y_pred = clf.predict(X_te)
    metrics = {
        "accuracy": round(accuracy_score(y_te, y_pred), 4),
        "precision": round(precision_score(y_te, y_pred, zero_division=0), 4),
        "recall": round(recall_score(y_te, y_pred, zero_division=0), 4),
        "f1": round(f1_score(y_te, y_pred, zero_division=0), 4),
    }

    logger.info("fine_tune.metrics", model_id=model_id, customer=customer_id, **metrics)

    # Compare with base metrics
    base_metrics = base_data.get("metrics", {})
    for k in ("accuracy", "precision", "recall", "f1"):
        base_val = base_metrics.get(k, 0)
        delta = metrics[k] - base_val
        logger.info(f"fine_tune.delta.{k}", base=base_val, fine_tuned=metrics[k], delta=round(delta, 4))

    # 8. Save fine-tuned model
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "wb") as f:
        pickle.dump({
            "model": clf,
            "violation_class": violation_class,
            "model_id": model_id,
            "customer_id": customer_id,
            "base_model_path": base_model_path,
            "metrics": metrics,
            "base_metrics": base_metrics,
            "fine_tuned_at": datetime.now(timezone.utc).isoformat(),
            "training_samples": len(y_ft),
            "positive_rate": float(y_ft.mean()),
        }, f)

    logger.info("fine_tune.saved", path=output_path)
    return metrics


def main() -> None:
    parser = argparse.ArgumentParser(description="Vektor AI — Customer Fine-Tuning")
    parser.add_argument("--base-model", required=True, help="Path to base model .pkl")
    parser.add_argument("--customer-id", required=True, help="Customer identifier")
    parser.add_argument("--features", required=True, help="Directory with features.npz")
    parser.add_argument("--labels", required=True, help="Directory with label JSON files")
    parser.add_argument("--output", required=True, help="Output path for fine-tuned model")
    parser.add_argument("--learning-rate", type=float, default=0.01)
    parser.add_argument("--n-estimators", type=int, default=100)
    args = parser.parse_args()

    structlog.configure(
        processors=[structlog.dev.ConsoleRenderer()],
    )

    metrics = fine_tune(
        base_model_path=args.base_model,
        customer_id=args.customer_id,
        features_dir=args.features,
        labels_dir=args.labels,
        output_path=args.output,
        learning_rate=args.learning_rate,
        n_estimators=args.n_estimators,
    )

    if not metrics:
        logger.error("fine_tune.failed")
        sys.exit(1)


if __name__ == "__main__":
    main()
