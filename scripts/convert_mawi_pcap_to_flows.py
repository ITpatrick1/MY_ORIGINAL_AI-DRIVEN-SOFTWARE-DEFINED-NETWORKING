#!/usr/bin/env python3
"""Convert MAWI PCAP traces into compact flow CSV files.

This intentionally uses only the Python standard library so the project can
convert MAWI traces even when tshark, Zeek, Scapy, or CICFlowMeter are not
installed. The converter streams packets, aggregates them into directional
5-tuple flows, and periodically flushes inactive flows to keep memory bounded.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import shutil
import socket
import struct
import subprocess
import time
from collections import OrderedDict
from pathlib import Path
from typing import Any


FLOW_FIELDS = [
    "flow_id",
    "src_ip",
    "dst_ip",
    "source_port",
    "destination_port",
    "protocol",
    "first_seen",
    "last_seen",
    "duration",
    "packets",
    "bytes",
    "packet_count",
    "byte_count",
    "packet_rate",
    "byte_rate",
    "label",
]

PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
}


def _iso(ts: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(ts))


def _inet_ntop(family: int, packed: bytes) -> str:
    try:
        return socket.inet_ntop(family, packed)
    except OSError:
        return ""


def _parse_packet(packet: bytes) -> tuple[str, str, str, int, int] | None:
    if len(packet) < 14:
        return None
    offset = 14
    ethertype = struct.unpack("!H", packet[12:14])[0]
    while ethertype in {0x8100, 0x88A8, 0x9100} and len(packet) >= offset + 4:
        ethertype = struct.unpack("!H", packet[offset + 2 : offset + 4])[0]
        offset += 4

    if ethertype == 0x0800:
        if len(packet) < offset + 20:
            return None
        version_ihl = packet[offset]
        version = version_ihl >> 4
        ihl = (version_ihl & 0x0F) * 4
        if version != 4 or ihl < 20 or len(packet) < offset + ihl:
            return None
        proto_num = packet[offset + 9]
        src_ip = _inet_ntop(socket.AF_INET, packet[offset + 12 : offset + 16])
        dst_ip = _inet_ntop(socket.AF_INET, packet[offset + 16 : offset + 20])
        l4 = offset + ihl
    elif ethertype == 0x86DD:
        if len(packet) < offset + 40:
            return None
        version = packet[offset] >> 4
        if version != 6:
            return None
        proto_num = packet[offset + 6]
        src_ip = _inet_ntop(socket.AF_INET6, packet[offset + 8 : offset + 24])
        dst_ip = _inet_ntop(socket.AF_INET6, packet[offset + 24 : offset + 40])
        l4 = offset + 40
    else:
        return None

    protocol = {1: "icmp", 6: "tcp", 17: "udp", 58: "icmpv6"}.get(proto_num, str(proto_num))
    source_port = 0
    destination_port = 0
    if proto_num in {6, 17} and len(packet) >= l4 + 4:
        source_port, destination_port = struct.unpack("!HH", packet[l4 : l4 + 4])
    return src_ip, dst_ip, protocol, source_port, destination_port


def _flow_row(key: tuple[str, str, str, int, int], flow: dict[str, Any]) -> dict[str, Any]:
    src_ip, dst_ip, protocol, source_port, destination_port = key
    duration = max(float(flow["last_seen"]) - float(flow["first_seen"]), 0.0)
    packets = int(flow["packets"])
    bytes_ = int(flow["bytes"])
    rate_window = max(duration, 0.000001)
    flow_id = f"{src_ip}-{source_port}_{dst_ip}-{destination_port}_{protocol}"
    return {
        "flow_id": flow_id,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "source_port": source_port,
        "destination_port": destination_port,
        "protocol": protocol,
        "first_seen": _iso(float(flow["first_seen"])),
        "last_seen": _iso(float(flow["last_seen"])),
        "duration": round(duration, 6),
        "packets": packets,
        "bytes": bytes_,
        "packet_count": packets,
        "byte_count": bytes_,
        "packet_rate": round(packets / rate_window, 6),
        "byte_rate": round(bytes_ / rate_window, 6),
        "label": "normal",
    }


def convert_pcap(
    pcap_path: Path,
    output_csv: Path,
    *,
    max_packets: int = 1_000_000,
    idle_timeout: float = 120.0,
    flush_interval: int = 50_000,
    max_active_flows: int = 200_000,
) -> dict[str, Any]:
    output_csv.parent.mkdir(parents=True, exist_ok=True)
    active: OrderedDict[tuple[str, str, str, int, int], dict[str, Any]] = OrderedDict()
    packets_seen = 0
    ip_packets = 0
    flow_rows = 0
    skipped = 0
    start = time.time()

    def flush(writer: csv.DictWriter, now_ts: float | None = None, force: bool = False) -> None:
        nonlocal flow_rows
        if not active:
            return
        keys_to_flush: list[tuple[str, str, str, int, int]] = []
        if force:
            keys_to_flush = list(active.keys())
        elif now_ts is not None:
            for key, flow in active.items():
                if now_ts - float(flow["last_seen"]) >= idle_timeout:
                    keys_to_flush.append(key)
                else:
                    break
        while not force and len(active) - len(keys_to_flush) > max_active_flows:
            key = next(iter(active))
            if key not in keys_to_flush:
                keys_to_flush.append(key)
        for key in keys_to_flush:
            flow = active.pop(key, None)
            if flow is None:
                continue
            writer.writerow(_flow_row(key, flow))
            flow_rows += 1

    with pcap_path.open("rb") as source, output_csv.open("w", newline="", encoding="utf-8") as sink:
        magic = source.read(4)
        if magic not in PCAP_MAGICS:
            raise ValueError(f"unsupported PCAP magic {magic!r}; pcapng is not supported by this lightweight converter")
        endian, ts_scale = PCAP_MAGICS[magic]
        header_rest = source.read(20)
        if len(header_rest) != 20:
            raise ValueError("truncated PCAP global header")
        _version_major, _version_minor, _thiszone, _sigfigs, _snaplen, linktype = struct.unpack(f"{endian}HHiiii", header_rest)
        if linktype != 1:
            raise ValueError(f"unsupported link type {linktype}; expected Ethernet/linktype 1")

        writer = csv.DictWriter(sink, fieldnames=FLOW_FIELDS)
        writer.writeheader()
        record_struct = struct.Struct(f"{endian}IIII")
        while True:
            record_header = source.read(16)
            if not record_header:
                break
            if len(record_header) != 16:
                skipped += 1
                break
            ts_sec, ts_frac, incl_len, orig_len = record_struct.unpack(record_header)
            packet = source.read(incl_len)
            if len(packet) != incl_len:
                skipped += 1
                break
            packets_seen += 1
            ts = float(ts_sec) + (float(ts_frac) / ts_scale)
            parsed = _parse_packet(packet)
            if parsed is None:
                skipped += 1
            else:
                ip_packets += 1
                key = parsed
                flow = active.get(key)
                if flow is None:
                    active[key] = {"first_seen": ts, "last_seen": ts, "packets": 1, "bytes": int(orig_len or incl_len)}
                else:
                    flow["last_seen"] = ts
                    flow["packets"] += 1
                    flow["bytes"] += int(orig_len or incl_len)
                    active.move_to_end(key)
            if packets_seen % flush_interval == 0:
                flush(writer, now_ts=ts)
            if max_packets and packets_seen >= max_packets:
                break
        flush(writer, force=True)

    try:
        output_csv.chmod(0o644)
    except OSError:
        pass
    return {
        "ok": True,
        "pcap": str(pcap_path),
        "output_csv": str(output_csv),
        "packets_seen": packets_seen,
        "ip_packets": ip_packets,
        "flows_written": flow_rows,
        "skipped_packets": skipped,
        "max_packets": max_packets,
        "elapsed_s": round(time.time() - start, 3),
    }


def _split_endpoint(endpoint: str) -> tuple[str, int]:
    endpoint = endpoint.strip().rstrip(":")
    if "." not in endpoint:
        return endpoint, 0
    host, maybe_port = endpoint.rsplit(".", 1)
    if maybe_port.isdigit():
        return host, int(maybe_port)
    return endpoint, 0


def _parse_tcpdump_line(line: str) -> tuple[float, tuple[str, str, str, int, int], int] | None:
    line = line.strip()
    if not line:
        return None
    try:
        ts_text, rest = line.split(" ", 1)
        ts = float(ts_text)
    except ValueError:
        return None
    if rest.startswith("IP6 "):
        rest = rest[4:]
    elif rest.startswith("IP "):
        rest = rest[3:]
    else:
        return None
    if " > " not in rest or ": " not in rest:
        return None
    src_text, remainder = rest.split(" > ", 1)
    dst_text, detail = remainder.split(": ", 1)
    if detail.startswith("UDP"):
        protocol = "udp"
    elif detail.startswith("ICMP6"):
        protocol = "icmpv6"
    elif detail.startswith("ICMP"):
        protocol = "icmp"
    elif "Flags [" in detail:
        protocol = "tcp"
    else:
        protocol = "ip"
    if protocol in {"tcp", "udp"}:
        src_ip, source_port = _split_endpoint(src_text)
        dst_ip, destination_port = _split_endpoint(dst_text)
    else:
        src_ip, source_port = src_text.strip(), 0
        dst_ip, destination_port = dst_text.strip(), 0
    length_match = re.search(r"\blength\s+(\d+)", detail)
    bytes_ = int(length_match.group(1)) if length_match else 0
    if bytes_ <= 0:
        bytes_ = 64
    return ts, (src_ip, dst_ip, protocol, source_port, destination_port), bytes_


def convert_pcap_with_tcpdump(
    pcap_path: Path,
    output_csv: Path,
    *,
    max_packets: int = 1_000_000,
    idle_timeout: float = 120.0,
    flush_interval: int = 50_000,
    max_active_flows: int = 200_000,
) -> dict[str, Any]:
    tcpdump = shutil.which("tcpdump")
    if not tcpdump:
        raise RuntimeError("tcpdump is not installed")
    output_csv.parent.mkdir(parents=True, exist_ok=True)
    active: OrderedDict[tuple[str, str, str, int, int], dict[str, Any]] = OrderedDict()
    packets_seen = 0
    ip_packets = 0
    flow_rows = 0
    skipped = 0
    start = time.time()

    def flush(writer: csv.DictWriter, now_ts: float | None = None, force: bool = False) -> None:
        nonlocal flow_rows
        if not active:
            return
        keys_to_flush: list[tuple[str, str, str, int, int]] = []
        if force:
            keys_to_flush = list(active.keys())
        elif now_ts is not None:
            for key, flow in active.items():
                if now_ts - float(flow["last_seen"]) >= idle_timeout:
                    keys_to_flush.append(key)
                else:
                    break
        while not force and len(active) - len(keys_to_flush) > max_active_flows:
            key = next(iter(active))
            if key not in keys_to_flush:
                keys_to_flush.append(key)
        for key in keys_to_flush:
            flow = active.pop(key, None)
            if flow is None:
                continue
            writer.writerow(_flow_row(key, flow))
            flow_rows += 1

    cmd = [tcpdump, "-nn", "-tt", "-r", str(pcap_path)]
    if max_packets:
        cmd.extend(["-c", str(max_packets)])
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="replace")
    assert proc.stdout is not None
    with output_csv.open("w", newline="", encoding="utf-8") as sink:
        writer = csv.DictWriter(sink, fieldnames=FLOW_FIELDS)
        writer.writeheader()
        for line in proc.stdout:
            packets_seen += 1
            parsed = _parse_tcpdump_line(line)
            if parsed is None:
                skipped += 1
            else:
                ts, key, bytes_ = parsed
                ip_packets += 1
                flow = active.get(key)
                if flow is None:
                    active[key] = {"first_seen": ts, "last_seen": ts, "packets": 1, "bytes": bytes_}
                else:
                    flow["last_seen"] = ts
                    flow["packets"] += 1
                    flow["bytes"] += bytes_
                    active.move_to_end(key)
                if packets_seen % flush_interval == 0:
                    flush(writer, now_ts=ts)
        stderr = proc.stderr.read() if proc.stderr is not None else ""
        return_code = proc.wait()
        flush(writer, force=True)
    if return_code not in {0, 1}:
        raise RuntimeError(f"tcpdump failed rc={return_code}: {stderr[-1000:]}")
    try:
        output_csv.chmod(0o644)
    except OSError:
        pass
    return {
        "ok": True,
        "backend": "tcpdump",
        "pcap": str(pcap_path),
        "output_csv": str(output_csv),
        "packets_seen": packets_seen,
        "ip_packets": ip_packets,
        "flows_written": flow_rows,
        "skipped_packets": skipped,
        "max_packets": max_packets,
        "elapsed_s": round(time.time() - start, 3),
        "stderr": stderr.strip()[-1000:],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Convert MAWI PCAP to a flow-like CSV usable by Tumba SDN preprocessing")
    parser.add_argument("--pcap", type=Path, default=Path("datasets/public/MAWI/202401011400.pcap/202401011400.pcap"))
    parser.add_argument("--output", type=Path, help="Output flow CSV path")
    parser.add_argument("--max-packets", type=int, default=1_000_000, help="0 means convert the full PCAP")
    parser.add_argument("--idle-timeout", type=float, default=120.0)
    parser.add_argument("--flush-interval", type=int, default=50_000)
    parser.add_argument("--max-active-flows", type=int, default=200_000)
    parser.add_argument("--backend", choices=["auto", "tcpdump", "python"], default="auto")
    args = parser.parse_args()
    output = args.output or Path("datasets/public/MAWI/flows") / f"{args.pcap.stem}_flows.csv"
    if args.backend in {"auto", "tcpdump"} and shutil.which("tcpdump"):
        result = convert_pcap_with_tcpdump(
            args.pcap,
            output,
            max_packets=args.max_packets,
            idle_timeout=args.idle_timeout,
            flush_interval=args.flush_interval,
            max_active_flows=args.max_active_flows,
        )
    else:
        result = convert_pcap(
            args.pcap,
            output,
            max_packets=args.max_packets,
            idle_timeout=args.idle_timeout,
            flush_interval=args.flush_interval,
            max_active_flows=args.max_active_flows,
        )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
