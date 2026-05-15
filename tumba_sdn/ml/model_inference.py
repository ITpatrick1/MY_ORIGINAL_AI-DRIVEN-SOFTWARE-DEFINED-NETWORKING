#!/usr/bin/env python3
"""Safe model inference helpers for trained Tumba College SDN classifiers."""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
DATASET_ROOT = Path(os.environ.get("CAMPUS_DATASET_ROOT", REPO_ROOT / "datasets"))
MODEL_DIR = DATASET_ROOT / "models"


@lru_cache(maxsize=1)
def _load_joblib():
    try:
        import joblib
        import numpy as np
    except Exception as exc:  # pragma: no cover - depends on local env
        raise RuntimeError("joblib and numpy are required for model inference") from exc
    return joblib, np


@lru_cache(maxsize=16)
def _load_artifact(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    joblib, _np = _load_joblib()
    return joblib.load(path)


def _to_float(value: Any) -> tuple[bool, float]:
    try:
        text = str(value).strip()
        if text == "":
            return True, 0.0
        return True, float(text)
    except (TypeError, ValueError):
        return False, 0.0


def _features(artifact: dict[str, Any], sample: dict[str, Any]):
    _joblib, np = _load_joblib()
    values: list[float] = []
    for column in artifact.get("feature_columns", []):
        ok, number = _to_float(sample.get(column, ""))
        if ok:
            values.append(number)
        else:
            mapping = artifact.get("encoders", {}).get(column, {})
            values.append(float(mapping.get(str(sample.get(column, "unknown") or "unknown"), -1)))
    return np.asarray([values], dtype=float)


def _predict(path: Path, sample: dict[str, Any]) -> dict[str, Any]:
    artifact = _load_artifact(path)
    if not artifact:
        return {"ok": False, "error": f"model not found: {path}"}
    X = _features(artifact, sample)
    model = artifact["model"]
    label = str(model.predict(X)[0])
    result = {
        "ok": True,
        "kind": artifact.get("kind", ""),
        "prediction": label,
        "labels": artifact.get("labels", []),
        "model_path": str(path),
        "trained_at": artifact.get("trained_at"),
    }
    if hasattr(model, "predict_proba"):
        probabilities = model.predict_proba(X)[0]
        result["probabilities"] = {
            str(label_name): round(float(prob), 4)
            for label_name, prob in zip(model.classes_, probabilities)
        }
        result["confidence"] = round(float(max(probabilities)), 4)
    return result


def safety_validate(sample: dict[str, Any], prediction: str) -> dict[str, Any]:
    """Keep critical academic/exam flows from being blocked by classifier output."""
    activity = str(sample.get("activity", "")).lower()
    priority = str(sample.get("priority_level", "")).upper()
    if ("exam" in activity or priority == "CRITICAL") and prediction in {"blocked", "isolated", "throttle", "rate_limit", "attack"}:
        return {
            "allowed": False,
            "safe_prediction": "protected",
            "reason": "Safety rail: exam/critical academic traffic cannot be blocked without deterministic policy validation.",
        }
    return {"allowed": True, "safe_prediction": prediction, "reason": "model suggestion allowed"}


def predict_security(flow_features: dict[str, Any]) -> dict[str, Any]:
    result = _predict(MODEL_DIR / "security_model.pkl", flow_features)
    if result.get("ok"):
        result["safety"] = safety_validate(flow_features, result["prediction"])
    return result


def predict_congestion(link_features: dict[str, Any]) -> dict[str, Any]:
    return _predict(MODEL_DIR / "congestion_model.pkl", link_features)


def predict_qos(flow_features: dict[str, Any]) -> dict[str, Any]:
    result = _predict(MODEL_DIR / "qos_model.pkl", flow_features)
    if result.get("ok"):
        result["safety"] = safety_validate(flow_features, result["prediction"])
    return result
