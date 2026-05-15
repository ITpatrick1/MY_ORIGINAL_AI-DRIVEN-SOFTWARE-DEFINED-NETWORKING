#!/usr/bin/env python3
"""Small scikit-learn training helpers for Tumba College SDN datasets."""

from __future__ import annotations

import csv
import json
import os
import time
from collections import Counter
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
DATASET_ROOT = Path(os.environ.get("CAMPUS_DATASET_ROOT", REPO_ROOT / "datasets"))


def _load_sklearn():
    try:
        import joblib
        import numpy as np
        from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
        from sklearn.linear_model import LogisticRegression
        from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
        from sklearn.model_selection import train_test_split
    except Exception as exc:  # pragma: no cover - depends on local env
        raise RuntimeError(
            "scikit-learn/joblib/numpy are required. Install with: "
            "pip install scikit-learn joblib numpy"
        ) from exc
    return {
        "joblib": joblib,
        "np": np,
        "RandomForestClassifier": RandomForestClassifier,
        "GradientBoostingClassifier": GradientBoostingClassifier,
        "LogisticRegression": LogisticRegression,
        "accuracy_score": accuracy_score,
        "classification_report": classification_report,
        "confusion_matrix": confusion_matrix,
        "train_test_split": train_test_split,
    }


def _read_rows(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        raise FileNotFoundError(path)
    with path.open(newline="", encoding="utf-8", errors="replace") as handle:
        return [dict(row) for row in csv.DictReader(handle)]


def _to_float(value: Any) -> tuple[bool, float]:
    try:
        text = str(value).strip()
        if text == "":
            return True, 0.0
        return True, float(text)
    except (TypeError, ValueError):
        return False, 0.0


def _encode_rows(rows: list[dict[str, Any]], target_col: str = "label", feature_columns: list[str] | None = None, encoders: dict[str, dict[str, int]] | None = None) -> tuple[list[list[float]], list[str], list[str], dict[str, dict[str, int]]]:
    if not rows:
        raise ValueError("training dataset is empty")
    feature_columns = feature_columns or [key for key in rows[0].keys() if key != target_col]
    encoders = encoders or {}
    matrix: list[list[float]] = []
    labels: list[str] = []
    for row in rows:
        labels.append(str(row.get(target_col, "normal") or "normal"))
        values: list[float] = []
        for column in feature_columns:
            ok, number = _to_float(row.get(column, ""))
            if ok:
                values.append(number)
                continue
            mapping = encoders.setdefault(column, {})
            token = str(row.get(column, "unknown") or "unknown")
            if token not in mapping:
                mapping[token] = len(mapping) + 1
            values.append(float(mapping[token]))
        matrix.append(values)
    return matrix, labels, feature_columns, encoders


def _choose_model(kind: str, model_name: str, sklearn: dict[str, Any]):
    model_name = (model_name or "random_forest").lower()
    if model_name == "gradient_boosting":
        return sklearn["GradientBoostingClassifier"](random_state=42)
    if model_name == "logistic_regression":
        return sklearn["LogisticRegression"](max_iter=1000)
    return sklearn["RandomForestClassifier"](n_estimators=160, random_state=42, class_weight="balanced" if kind == "security" else None)


def train_classifier(
    *,
    kind: str,
    train_path: Path,
    model_path: Path,
    report_path: Path | None = None,
    test_path: Path | None = None,
    target_col: str = "label",
    model_name: str = "random_forest",
) -> dict[str, Any]:
    sklearn = _load_sklearn()
    np = sklearn["np"]
    start = time.time()
    train_rows = _read_rows(train_path)
    X_rows, y, feature_columns, encoders = _encode_rows(train_rows, target_col=target_col)
    X = np.asarray(X_rows, dtype=float)
    y_arr = np.asarray(y)

    if test_path and test_path.exists():
        test_rows = _read_rows(test_path)
        X_test_rows, y_test, _features, _encoders = _encode_rows(test_rows, target_col=target_col, feature_columns=feature_columns, encoders=encoders)
        X_train, y_train = X, y_arr
        X_test = np.asarray(X_test_rows, dtype=float)
        y_test_arr = np.asarray(y_test)
    else:
        label_counts = Counter(y)
        can_stratify = len(label_counts) > 1 and min(label_counts.values()) >= 2
        X_train, X_test, y_train, y_test_arr = sklearn["train_test_split"](
            X, y_arr, test_size=0.25, random_state=42, stratify=y_arr if can_stratify else None
        )

    model = _choose_model(kind, model_name, sklearn)
    model.fit(X_train, y_train)
    predictions = model.predict(X_test)
    labels = sorted(set(list(y_train) + list(y_test_arr) + list(predictions)))
    accuracy = float(sklearn["accuracy_score"](y_test_arr, predictions))
    report_dict = sklearn["classification_report"](y_test_arr, predictions, output_dict=True, zero_division=0)
    matrix = sklearn["confusion_matrix"](y_test_arr, predictions, labels=labels).tolist()

    artifact = {
        "model": model,
        "kind": kind,
        "feature_columns": feature_columns,
        "encoders": encoders,
        "labels": labels,
        "trained_at": time.time(),
        "training_rows": len(train_rows),
        "model_name": model_name,
    }
    model_path.parent.mkdir(parents=True, exist_ok=True)
    sklearn["joblib"].dump(artifact, model_path)

    training_report = {
        "ok": True,
        "kind": kind,
        "model_version": f"{kind}-{int(time.time())}",
        "model_name": model_name,
        "dataset_used": str(train_path),
        "test_dataset": str(test_path) if test_path else "auto_split",
        "rows": len(train_rows),
        "train_rows": int(len(X_train)),
        "test_rows": int(len(X_test)),
        "labels": labels,
        "accuracy": round(accuracy, 4),
        "precision": round(float(report_dict.get("weighted avg", {}).get("precision", 0.0)), 4),
        "recall": round(float(report_dict.get("weighted avg", {}).get("recall", 0.0)), 4),
        "f1_score": round(float(report_dict.get("weighted avg", {}).get("f1-score", 0.0)), 4),
        "classification_report": report_dict,
        "confusion_matrix": {"labels": labels, "matrix": matrix},
        "training_time_s": round(time.time() - start, 3),
        "model_path": str(model_path),
    }
    if report_path:
        report_path.parent.mkdir(parents=True, exist_ok=True)
        with report_path.open("w", encoding="utf-8") as handle:
            json.dump(training_report, handle, indent=2)
    return training_report


def train_security_model(train_path: Path | None = None, test_path: Path | None = None) -> dict[str, Any]:
    return train_classifier(
        kind="security",
        train_path=train_path or DATASET_ROOT / "processed" / "security_train.csv",
        test_path=test_path or DATASET_ROOT / "processed" / "security_test.csv",
        model_path=DATASET_ROOT / "models" / "security_model.pkl",
        report_path=DATASET_ROOT / "models" / "training_report.json",
    )


def train_congestion_model(train_path: Path | None = None) -> dict[str, Any]:
    return train_classifier(
        kind="congestion",
        train_path=train_path or DATASET_ROOT / "realtime" / "live_congestion_dataset.csv",
        model_path=DATASET_ROOT / "models" / "congestion_model.pkl",
        report_path=DATASET_ROOT / "models" / "training_report.json",
        target_col="label",
    )


def train_qos_model(train_path: Path | None = None) -> dict[str, Any]:
    return train_classifier(
        kind="qos",
        train_path=train_path or DATASET_ROOT / "realtime" / "live_qos_dataset.csv",
        model_path=DATASET_ROOT / "models" / "qos_model.pkl",
        report_path=DATASET_ROOT / "models" / "training_report.json",
        target_col="label",
    )
