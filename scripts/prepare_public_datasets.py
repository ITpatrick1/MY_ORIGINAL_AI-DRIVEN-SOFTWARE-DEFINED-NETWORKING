#!/usr/bin/env python3
"""Normalize public benchmark datasets into the Tumba SDN security schema."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tumba_sdn.ml.dataset_preprocessor import DATASET_ROOT, NORMALIZERS, prepare_public_dataset


def main() -> None:
    parser = argparse.ArgumentParser(description="Prepare public IDS datasets for Tumba SDN model training")
    parser.add_argument("--dataset", required=True, choices=sorted(NORMALIZERS))
    parser.add_argument("--input-dir", type=Path, help="Directory containing raw/public CSV files")
    parser.add_argument("--output-dir", type=Path, default=DATASET_ROOT / "processed")
    parser.add_argument("--max-rows", type=int, default=0, help="Optional cap for quick experiments")
    parser.add_argument("--test-ratio", type=float, default=0.25)
    args = parser.parse_args()
    result = prepare_public_dataset(args.dataset, args.input_dir, args.output_dir, args.max_rows, args.test_ratio)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
