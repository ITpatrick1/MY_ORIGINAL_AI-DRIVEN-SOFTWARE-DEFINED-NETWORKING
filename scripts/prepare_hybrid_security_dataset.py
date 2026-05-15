#!/usr/bin/env python3
"""Build a hybrid security dataset from public IDS CSVs and live SDN rows.

The public benchmark datasets can be several gigabytes, so this script keeps
training preparation bounded by sampling a configurable number of rows from
each input file instead of loading every public record into memory.
"""

from __future__ import annotations

import argparse
import csv
import random
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Callable

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tumba_sdn.ml.dataset_preprocessor import (  # noqa: E402
    DATASET_ROOT,
    SECURITY_SCHEMA,
    _normalize_cic,
    _normalize_mawi,
    _normalize_unsw,
    write_csv,
)


def _csv_files(root: Path, patterns: list[str] | None = None) -> list[Path]:
    if not root.exists():
        return []
    if patterns:
        files: list[Path] = []
        for pattern in patterns:
            files.extend(root.rglob(pattern))
        return sorted(path for path in files if path.is_file())
    return sorted(path for path in root.rglob("*.csv") if path.is_file())


def _sample_file(
    path: Path,
    normalizer: Callable[[dict[str, Any]], dict[str, Any]],
    rows_per_file: int,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open(newline="", encoding="utf-8", errors="replace") as handle:
        reader = csv.DictReader(handle)
        for raw in reader:
            if rows_per_file and len(rows) >= rows_per_file:
                break
            normalized = normalizer(raw)
            rows.append({field: normalized.get(field, "") for field in SECURITY_SCHEMA})
    return rows


def _read_live_security(path: Path, limit: int) -> list[dict[str, Any]]:
    if not path.exists() or limit <= 0:
        return []
    rows: list[dict[str, Any]] = []
    with path.open(newline="", encoding="utf-8", errors="replace") as handle:
        for raw in csv.DictReader(handle):
            if len(rows) >= limit:
                break
            rows.append(
                {
                    "duration": 0,
                    "protocol": "tcp",
                    "source_port": 0,
                    "destination_port": str(raw.get("target_ip", "")).split(":")[-1].split()[0] if ":" in str(raw.get("target_ip", "")) else 0,
                    "packet_count": raw.get("packet_rate", 0),
                    "byte_count": 0,
                    "packet_rate": raw.get("packet_rate", 0),
                    "byte_rate": 0,
                    "flow_rate": raw.get("packet_rate", 0),
                    "port_count": raw.get("port_count", 0),
                    "destination_count": 0,
                    "failed_attempts": raw.get("failed_attempts", 0),
                    "source_vlan": raw.get("attacker_vlan", 0),
                    "target_vlan": raw.get("target_vlan", 0),
                    "activity": raw.get("attack_type", "normal"),
                    "priority_level": "THREAT" if str(raw.get("label", "normal")) != "normal" else "BEST-EFFORT",
                    "dscp_value": 0,
                    "label": raw.get("label", "normal") or "normal",
                }
            )
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description="Prepare hybrid public + live SDN security dataset")
    parser.add_argument("--rows-per-file", type=int, default=20000)
    parser.add_argument("--live-limit", type=int, default=50000)
    parser.add_argument("--test-ratio", type=float, default=0.25)
    parser.add_argument("--output-dir", type=Path, default=DATASET_ROOT / "processed")
    args = parser.parse_args()

    sources: list[tuple[str, Path, list[Path], Callable[[dict[str, Any]], dict[str, Any]]]] = [
        ("CICIDS2017", DATASET_ROOT / "public" / "CICIDS2017", _csv_files(DATASET_ROOT / "public" / "CICIDS2017"), _normalize_cic),
        ("CSE_CIC_IDS2018", DATASET_ROOT / "public" / "CSE_CIC_IDS2018", _csv_files(DATASET_ROOT / "public" / "CSE_CIC_IDS2018"), _normalize_cic),
        (
            "UNSW_NB15",
            DATASET_ROOT / "public" / "UNSW_NB15",
            _csv_files(DATASET_ROOT / "public" / "UNSW_NB15", ["UNSW_NB15_training-set.csv", "UNSW_NB15_testing-set.csv"]),
            _normalize_unsw,
        ),
        ("MAWI", DATASET_ROOT / "public" / "MAWI", _csv_files(DATASET_ROOT / "public" / "MAWI"), _normalize_mawi),
    ]

    all_rows: list[dict[str, Any]] = []
    source_counts: dict[str, int] = {}
    skipped: dict[str, str] = {}
    for name, root, files, normalizer in sources:
        if not files:
            skipped[name] = f"no supported CSV files found in {root}"
            continue
        count = 0
        for file_path in files:
            sampled = _sample_file(file_path, normalizer, args.rows_per_file)
            all_rows.extend(sampled)
            count += len(sampled)
        source_counts[name] = count

    live_rows = _read_live_security(DATASET_ROOT / "realtime" / "live_security_dataset.csv", args.live_limit)
    if live_rows:
        all_rows.extend(live_rows)
        source_counts["live_sdn_security"] = len(live_rows)

    if not _csv_files(DATASET_ROOT / "public" / "MAWI"):
        skipped["MAWI"] = "only PCAP traces detected; convert to flow CSV before security preprocessing"

    if not all_rows:
        raise SystemExit("no rows collected for hybrid dataset")

    random.Random(42).shuffle(all_rows)
    split_at = max(1, int(len(all_rows) * (1.0 - args.test_ratio)))
    train, test = all_rows[:split_at], all_rows[split_at:]
    train_path = args.output_dir / "security_train.csv"
    test_path = args.output_dir / "security_test.csv"
    write_csv(train_path, train)
    write_csv(test_path, test)

    labels = Counter(str(row.get("label", "normal")) for row in all_rows)
    print(
        {
            "ok": True,
            "rows": len(all_rows),
            "train_rows": len(train),
            "test_rows": len(test),
            "sources": source_counts,
            "skipped": skipped,
            "labels": dict(sorted(labels.items())),
            "train_path": str(train_path),
            "test_path": str(test_path),
        }
    )


if __name__ == "__main__":
    main()
