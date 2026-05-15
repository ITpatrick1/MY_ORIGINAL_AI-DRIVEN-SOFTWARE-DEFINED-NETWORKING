#!/usr/bin/env python3
"""Dataset preprocessing helpers for Tumba College SDN.

The public IDS datasets use different column names, so this module maps them
into a compact common schema that can be joined with the live SDN security
dataset. It intentionally avoids downloading datasets; operators place public
CSV files in datasets/public/<DATASET>/ and run scripts/prepare_public_datasets.py.
"""

from __future__ import annotations

import argparse
import csv
import os
import random
from pathlib import Path
from typing import Any, Iterable

REPO_ROOT = Path(__file__).resolve().parents[2]
DATASET_ROOT = Path(os.environ.get("CAMPUS_DATASET_ROOT", REPO_ROOT / "datasets"))

SECURITY_SCHEMA = [
    "duration",
    "protocol",
    "source_port",
    "destination_port",
    "packet_count",
    "byte_count",
    "packet_rate",
    "byte_rate",
    "flow_rate",
    "port_count",
    "destination_count",
    "failed_attempts",
    "source_vlan",
    "target_vlan",
    "activity",
    "priority_level",
    "dscp_value",
    "label",
]


def _clean_key(key: str) -> str:
    return str(key or "").strip().lower().replace("_", " ")


def _index(row: dict[str, Any]) -> dict[str, str]:
    return {_clean_key(key): key for key in row.keys()}


def _get(row: dict[str, Any], idx: dict[str, str], *names: str, default: Any = "") -> Any:
    for name in names:
        key = idx.get(_clean_key(name))
        if key is not None:
            value = row.get(key)
            if value not in (None, ""):
                return value
    return default


def _num(value: Any, default: float = 0.0) -> float:
    try:
        text = str(value).strip()
        if text in {"", "nan", "NaN", "Infinity", "inf", "-Infinity", "-inf"}:
            return default
        return float(text)
    except (TypeError, ValueError):
        return default


def _label(raw: Any) -> str:
    text = str(raw or "normal").strip().lower().replace(" ", "_").replace("-", "_")
    if text in {"", "benign", "normal", "0"}:
        return "normal"
    if "portscan" in text or "port_scan" in text or "reconnaissance" in text:
        return "port_scan"
    if "ddos" in text or text.startswith("dos") or "_dos" in text:
        return "ddos"
    if "brute" in text or "ftp_patator" in text or "ssh_patator" in text:
        return "brute_force"
    if "infiltration" in text or "backdoor" in text or "shellcode" in text or "worms" in text:
        return "unauthorized_access"
    if "analysis" in text or "fuzzer" in text or "exploits" in text or "generic" in text:
        return text
    if "bot" in text:
        return "botnet"
    if "web" in text or "xss" in text or "sql" in text:
        return "web_attack"
    return text


def discover_csv_files(input_dir: Path) -> list[Path]:
    if input_dir.is_file() and input_dir.suffix.lower() == ".csv":
        return [input_dir]
    if not input_dir.exists():
        return []
    return sorted(path for path in input_dir.rglob("*.csv") if path.is_file())


def _normalize_cic(row: dict[str, Any]) -> dict[str, Any]:
    idx = _index(row)
    fwd_packets = _num(_get(row, idx, "Total Fwd Packets", "Tot Fwd Pkts"))
    bwd_packets = _num(_get(row, idx, "Total Backward Packets", "Tot Bwd Pkts"))
    fwd_bytes = _num(_get(row, idx, "Total Length of Fwd Packets", "TotLen Fwd Pkts", "Fwd Header Length"))
    bwd_bytes = _num(_get(row, idx, "Total Length of Bwd Packets", "TotLen Bwd Pkts", "Bwd Header Length"))
    duration = _num(_get(row, idx, "Flow Duration", "duration"))
    packet_rate = _num(_get(row, idx, "Flow Packets/s", "Flow Pkts/s"))
    byte_rate = _num(_get(row, idx, "Flow Bytes/s", "Flow Byts/s"))
    return {
        "duration": duration,
        "protocol": _get(row, idx, "Protocol", "proto", default="unknown"),
        "source_port": _get(row, idx, "Source Port", "Src Port", "sport", default=0),
        "destination_port": _get(row, idx, "Destination Port", "Dst Port", "dport", default=0),
        "packet_count": fwd_packets + bwd_packets,
        "byte_count": fwd_bytes + bwd_bytes,
        "packet_rate": packet_rate,
        "byte_rate": byte_rate,
        "flow_rate": packet_rate,
        "port_count": 0,
        "destination_count": 0,
        "failed_attempts": 0,
        "source_vlan": 0,
        "target_vlan": 0,
        "activity": _get(row, idx, "Label", default="normal"),
        "priority_level": "THREAT" if _label(_get(row, idx, "Label", default="normal")) != "normal" else "BEST-EFFORT",
        "dscp_value": 0,
        "label": _label(_get(row, idx, "Label", default="normal")),
    }


def _normalize_unsw(row: dict[str, Any]) -> dict[str, Any]:
    idx = _index(row)
    sbytes = _num(_get(row, idx, "sbytes", default=0))
    dbytes = _num(_get(row, idx, "dbytes", default=0))
    spkts = _num(_get(row, idx, "spkts", default=0))
    dpkts = _num(_get(row, idx, "dpkts", default=0))
    attack_cat = _get(row, idx, "attack_cat", "label", default="normal")
    label = _label(attack_cat)
    return {
        "duration": _num(_get(row, idx, "dur", "duration", default=0)),
        "protocol": _get(row, idx, "proto", "protocol", default="unknown"),
        "source_port": _get(row, idx, "sport", "source_port", default=0),
        "destination_port": _get(row, idx, "dport", "destination_port", default=0),
        "packet_count": spkts + dpkts,
        "byte_count": sbytes + dbytes,
        "packet_rate": _num(_get(row, idx, "rate", default=0)),
        "byte_rate": 0,
        "flow_rate": _num(_get(row, idx, "rate", default=0)),
        "port_count": _num(_get(row, idx, "ct_dst_sport_ltm", "ct_srv_dst", default=0)),
        "destination_count": _num(_get(row, idx, "ct_dst_ltm", "ct_dst_src_ltm", default=0)),
        "failed_attempts": _num(_get(row, idx, "ct_ftp_cmd", default=0)),
        "source_vlan": 0,
        "target_vlan": 0,
        "activity": attack_cat,
        "priority_level": "THREAT" if label != "normal" else "BEST-EFFORT",
        "dscp_value": 0,
        "label": label,
    }


def _normalize_mawi(row: dict[str, Any]) -> dict[str, Any]:
    idx = _index(row)
    duration = _num(_get(row, idx, "duration", "dur", default=0))
    packets = _num(_get(row, idx, "packets", "packet_count", default=0))
    bytes_ = _num(_get(row, idx, "bytes", "byte_count", default=0))
    return {
        "duration": duration,
        "protocol": _get(row, idx, "protocol", "proto", default="unknown"),
        "source_port": _get(row, idx, "source_port", "sport", default=0),
        "destination_port": _get(row, idx, "destination_port", "dport", default=0),
        "packet_count": packets,
        "byte_count": bytes_,
        "packet_rate": packets / max(duration, 1.0),
        "byte_rate": bytes_ / max(duration, 1.0),
        "flow_rate": packets / max(duration, 1.0),
        "port_count": 0,
        "destination_count": 0,
        "failed_attempts": 0,
        "source_vlan": 0,
        "target_vlan": 0,
        "activity": "normal_traffic",
        "priority_level": "BEST-EFFORT",
        "dscp_value": 0,
        "label": _label(_get(row, idx, "label", default="normal")),
    }


NORMALIZERS = {
    "CICIDS2017": _normalize_cic,
    "CSE_CIC_IDS2018": _normalize_cic,
    "CSE-CIC-IDS2018": _normalize_cic,
    "UNSW_NB15": _normalize_unsw,
    "UNSW-NB15": _normalize_unsw,
    "MAWI": _normalize_mawi,
}


def normalize_rows(dataset: str, csv_files: Iterable[Path], max_rows: int = 0) -> list[dict[str, Any]]:
    normalizer = NORMALIZERS.get(dataset)
    if normalizer is None:
        raise ValueError(f"unsupported dataset: {dataset}")
    rows: list[dict[str, Any]] = []
    for path in csv_files:
        with path.open(newline="", encoding="utf-8", errors="replace") as handle:
            reader = csv.DictReader(handle)
            for raw in reader:
                row = normalizer(raw)
                rows.append({field: row.get(field, "") for field in SECURITY_SCHEMA})
                if max_rows and len(rows) >= max_rows:
                    return rows
    return rows


def split_rows(rows: list[dict[str, Any]], test_ratio: float = 0.25, seed: int = 42) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    shuffled = list(rows)
    random.Random(seed).shuffle(shuffled)
    split_at = max(1, int(len(shuffled) * (1.0 - test_ratio))) if shuffled else 0
    return shuffled[:split_at], shuffled[split_at:]


def write_csv(path: Path, rows: list[dict[str, Any]], fields: list[str] = SECURITY_SCHEMA) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field, "") for field in fields})
    try:
        path.chmod(0o644)
    except OSError:
        pass


def prepare_public_dataset(dataset: str, input_dir: Path | None = None, output_dir: Path | None = None, max_rows: int = 0, test_ratio: float = 0.25) -> dict[str, Any]:
    dataset = dataset.strip()
    input_dir = input_dir or DATASET_ROOT / "public" / dataset
    output_dir = output_dir or DATASET_ROOT / "processed"
    files = discover_csv_files(input_dir)
    if not files:
        raise FileNotFoundError(f"no CSV files found in {input_dir}")
    rows = normalize_rows(dataset, files, max_rows=max_rows)
    train, test = split_rows(rows, test_ratio=test_ratio)
    train_path = output_dir / "security_train.csv"
    test_path = output_dir / "security_test.csv"
    write_csv(train_path, train)
    write_csv(test_path, test)
    labels = sorted({row["label"] for row in rows})
    return {
        "ok": True,
        "dataset": dataset,
        "input_files": [str(path) for path in files],
        "rows": len(rows),
        "train_rows": len(train),
        "test_rows": len(test),
        "labels": labels,
        "train_path": str(train_path),
        "test_path": str(test_path),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Normalize public IDS datasets for Tumba SDN ML training")
    parser.add_argument("--dataset", required=True, choices=sorted(NORMALIZERS))
    parser.add_argument("--input-dir", type=Path)
    parser.add_argument("--output-dir", type=Path, default=DATASET_ROOT / "processed")
    parser.add_argument("--max-rows", type=int, default=0)
    parser.add_argument("--test-ratio", type=float, default=0.25)
    args = parser.parse_args()
    result = prepare_public_dataset(args.dataset, args.input_dir, args.output_dir, args.max_rows, args.test_ratio)
    print(result)


if __name__ == "__main__":
    main()
