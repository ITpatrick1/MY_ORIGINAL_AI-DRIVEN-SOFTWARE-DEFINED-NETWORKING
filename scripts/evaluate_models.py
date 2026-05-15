#!/usr/bin/env python3
"""Evaluate trained Tumba SDN models and write datasets/models/training_report.json."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tumba_sdn.ml.model_inference import MODEL_DIR, _features, _load_artifact, _load_joblib
from tumba_sdn.ml.model_trainer import DATASET_ROOT


def _read_rows(path: Path, limit: int = 1000) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    with path.open(newline="", encoding="utf-8", errors="replace") as handle:
        rows = []
        for row in csv.DictReader(handle):
            rows.append(dict(row))
            if limit and len(rows) >= limit:
                break
        return rows


def _evaluate(kind: str, rows: list[dict[str, Any]]) -> dict[str, Any]:
    if not rows:
        return {"ok": False, "kind": kind, "error": "no rows available"}
    artifact = _load_artifact(MODEL_DIR / f"{kind}_model.pkl")
    if not artifact:
        return {"ok": False, "kind": kind, "error": f"{kind} model unavailable"}
    _joblib, np = _load_joblib()
    X = np.vstack([_features(artifact, row)[0] for row in rows])
    y_true = [str(row.get("label", "")) for row in rows]
    y_pred = [str(value) for value in artifact["model"].predict(X)]
    labels = set(y_true)
    predictions = set(y_pred)
    correct = sum(int(expected == predicted) for expected, predicted in zip(y_true, y_pred))
    total = len(y_true)
    return {
        "ok": True,
        "kind": kind,
        "rows": total,
        "accuracy": round(correct / max(total, 1), 4),
        "labels": sorted(labels),
        "predictions": sorted(predictions),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate trained Tumba SDN models")
    parser.add_argument("--limit", type=int, default=1000)
    args = parser.parse_args()
    security_test = DATASET_ROOT / "processed" / "security_test.csv"
    if not security_test.exists():
        security_test = DATASET_ROOT / "realtime" / "live_security_dataset.csv"
    report = {
        "security": _evaluate("security", _read_rows(security_test, args.limit)),
        "congestion": _evaluate("congestion", _read_rows(DATASET_ROOT / "realtime" / "live_congestion_dataset.csv", args.limit)),
        "qos": _evaluate("qos", _read_rows(DATASET_ROOT / "realtime" / "live_qos_dataset.csv", args.limit)),
    }
    out = DATASET_ROOT / "models" / "training_report.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
