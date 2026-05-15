#!/usr/bin/env python3
"""Train a QoS/action classifier from live SDN QoS datasets."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tumba_sdn.ml.model_trainer import DATASET_ROOT, train_qos_model


def main() -> None:
    parser = argparse.ArgumentParser(description="Train Tumba SDN QoS model")
    parser.add_argument("--train", type=Path, default=DATASET_ROOT / "realtime" / "live_qos_dataset.csv")
    args = parser.parse_args()
    report = train_qos_model(args.train)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
