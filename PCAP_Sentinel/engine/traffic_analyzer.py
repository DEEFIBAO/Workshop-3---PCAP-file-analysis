"""Traffic analyser: general statistics, flows and time-window rates (no attack logic here).

Pipeline position:   packets --> analyze_traffic() --> context --> rules --> build_report()

``analyze_traffic(packets, capture_info=None, config=None)`` returns the shared ``context`` dict.
It is built from one small function per statistics block (each one is a workshop task):

    context["packets"], context["capture_info"], context["config"]
    context["flows"]    list of conversations (see _new_flow)
    context["summary"]  the statistics block documented below

summary layout (``None`` = could not be computed, which is NOT the same as 0):
    capture      file_size_bytes, format, link_types, packet_count, first_timestamp, last_timestamp,
                 duration_seconds, start_utc, end_utc
    totals       packets, captured_bytes, wire_bytes, average_packet_size
    protocols    [{protocol, packets, bytes, percent}] largest first
    top_sources / top_destinations      [{ip, packets, bytes}]
    top_destination_ports               [{port, protocol, service, packets}]
    tcp          packets, connection_attempts, synack_responses, reset_packets, fin_packets,
                 retransmissions, flag_counts
    flows        total, tracked, truncated, top (busiest conversations)
    traffic_rate window_seconds, average_pps, average_bytes_per_second, peak, bursts, series
                 (None when the capture has no usable timestamps)
    data_quality truncated_packets, malformed_packets, unsupported_packets, packets_without_timestamp,
                 file_truncated, read_limit_reached, warnings, notes
"""
from __future__ import annotations

import statistics
from collections import Counter
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from engine.default_rules.services import service_name

DEFAULT_CONFIG = {
    "top_n": 10,                    # rows in each "top" table
    "rate_window_seconds": 1.0,     # width of one time bin for rates / bursts
    "max_rate_bins": 3600,          # bins are widened automatically for very long captures
    "burst_factor": 5.0,            # a bin is a burst if it is >= factor x the median busy bin ...
    "burst_min_packets": 100,       # ... and holds at least this many packets
    "max_flows": 50_000,            # memory guard for scans / floods that create endless flows
    "series_points": 120,           # points kept for the dashboard sparkline
}


def _utc(timestamp: Optional[float]) -> Optional[str]:
    if timestamp is None:
        return None
    try:
        return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        return None


def capture_block(packets: List[dict], capture_info: Optional[dict]) -> dict:
    """summary["capture"]: file facts plus first/last timestamp and duration (None if no timestamps)."""
    info = capture_info or {}
    stamps = [p["timestamp"] for p in packets if p["timestamp"] is not None]
    first, last = (min(stamps), max(stamps)) if stamps else (None, None)
    return {"file_size_bytes": info.get("file_size_bytes"), "format": info.get("format"),
            "link_types": info.get("link_types", []), "packet_count": len(packets),
            "first_timestamp": first, "last_timestamp": last,
            "duration_seconds": round(last - first, 6) if first is not None else None,
            "start_utc": _utc(first), "end_utc": _utc(last)}


def totals_block(packets: List[dict]) -> dict:
    """summary["totals"]: packets, captured_bytes, wire_bytes (None if any length unknown), average_packet_size."""
    total = len(packets)
    captured = sum(p["captured_length"] for p in packets)
    wire_known = all(p["original_length"] is not None for p in packets)
    return {"packets": total, "captured_bytes": captured,
            "wire_bytes": sum(p["original_length"] for p in packets) if total and wire_known else None,
            "average_packet_size": round(captured / total, 1) if total else None}


def protocol_table(packets: List[dict]) -> List[dict]:
    """summary["protocols"]: [{protocol, packets, bytes, percent}] ordered by packets, largest first."""
    counts, sizes = Counter(), Counter()
    for p in packets:
        counts[p["protocol"]] += 1
        sizes[p["protocol"]] += p["captured_length"]
    return [{"protocol": name, "packets": n, "bytes": sizes[name], "percent": round(100 * n / len(packets), 1)}
            for name, n in counts.most_common()]


def top_hosts(packets: List[dict], role: str, top_n: int) -> List[dict]:
    """summary["top_sources"] (role="source") / ["top_destinations"] (role="destination"): [{ip, packets, bytes}]."""
    key = "source_ip" if role == "source" else "destination_ip"
    counts, sizes = Counter(), Counter()
    for p in packets:
        if p[key]:
            counts[p[key]] += 1
            sizes[p[key]] += p["captured_length"]
    return [{"ip": ip, "packets": n, "bytes": sizes[ip]} for ip, n in counts.most_common(top_n)]


def top_service_ports(packets: List[dict], top_n: int) -> List[dict]:
    """summary["top_destination_ports"]: [{port, protocol, service, packets}].

    Replies go to random client ports, so only count packets heading TOWARDS the service port:
    destination_port <= source_port (or a missing source port).
    """
    ports: Counter = Counter()
    for p in packets:
        if p["protocol"] in ("TCP", "UDP") and p["destination_port"] is not None and (
                p["source_port"] is None or p["destination_port"] <= p["source_port"]):
            ports[(p["protocol"], p["destination_port"])] += 1
    return [{"port": port, "protocol": proto, "service": service_name(port), "packets": n}
            for (proto, port), n in ports.most_common(top_n)]


def tcp_statistics(packets: List[dict]) -> dict:
    """summary["tcp"]: packets, connection_attempts (SYN-only), synack_responses, reset_packets, fin_packets,
    retransmissions (same segment seen twice), flag_counts."""
    flag_counts: Counter = Counter()
    seen, retransmissions, total = set(), 0, 0
    for p in packets:
        if p["protocol"] != "TCP":
            continue
        total += 1
        flags = p["tcp_flags"] or ""
        for name, letter in (("SYN", "S"), ("RST", "R"), ("FIN", "F"), ("PSH", "P")):
            if letter in flags:
                flag_counts[name] += 1
        if "S" in flags and "A" in flags:
            flag_counts["SYN-ACK"] += 1
        elif "S" in flags and "R" not in flags:
            flag_counts["SYN-only"] += 1
        if flags == "":
            flag_counts["NULL (no flags)"] += 1
        if p["payload_length"] or "S" in flags or "F" in flags:
            key = (p["source_ip"], p["source_port"], p["destination_ip"], p["destination_port"],
                   p["tcp_seq"], p["payload_length"], "S" in flags, "F" in flags)
            if key in seen:
                retransmissions += 1
            elif len(seen) < 1_000_000:
                seen.add(key)
    return {"packets": total, "connection_attempts": flag_counts["SYN-only"], "synack_responses": flag_counts["SYN-ACK"],
            "reset_packets": flag_counts["RST"], "fin_packets": flag_counts["FIN"],
            "retransmissions": retransmissions, "flag_counts": dict(flag_counts)}


def build_flows(packets: List[dict], max_flows: int) -> Tuple[List[dict], int]:
    """Conversations (both directions together) -> (flow list, packets that did not fit under ``max_flows``).

    Flow dict: protocol, a_ip, a_port, b_ip, b_port, packets, bytes, packets_a_to_b, first_ts, last_ts,
    duration (None when no timestamps). Sorted by packets, largest first. ARP / non-IP packets are skipped.
    """
    flows: Dict[tuple, dict] = {}
    untracked = 0
    for p in packets:
        src, dst = p["source_ip"], p["destination_ip"]
        if not src or not dst or p["protocol"] == "ARP":
            continue
        a, b = (src, p["source_port"] or 0), (dst, p["destination_port"] or 0)
        key = (p["protocol"],) + ((a, b) if a <= b else (b, a))
        flow = flows.get(key)
        if flow is None:
            if len(flows) >= max_flows:
                untracked += 1
                continue
            flow = flows[key] = {"protocol": p["protocol"], "a_ip": src, "a_port": p["source_port"], "b_ip": dst,
                                 "b_port": p["destination_port"], "packets": 0, "bytes": 0, "packets_a_to_b": 0,
                                 "first_ts": None, "last_ts": None, "duration": None}
        flow["packets"] += 1
        flow["bytes"] += p["captured_length"]
        if (src, p["source_port"]) == (flow["a_ip"], flow["a_port"]):
            flow["packets_a_to_b"] += 1
        ts = p["timestamp"]
        if ts is not None:
            flow["first_ts"] = ts if flow["first_ts"] is None else min(flow["first_ts"], ts)
            flow["last_ts"] = ts if flow["last_ts"] is None else max(flow["last_ts"], ts)
    for flow in flows.values():
        if flow["first_ts"] is not None:
            flow["duration"] = round(flow["last_ts"] - flow["first_ts"], 6)
    return sorted(flows.values(), key=lambda f: (-f["packets"], f["first_ts"] or 0)), untracked


def rate_summary(packets: List[dict], config: dict) -> Optional[dict]:
    """summary["traffic_rate"]: packets per time bin, the peak bin, burst bins and a down-sampled series.

    Uses packet timestamps only; returns None when no packet has a timestamp (unavailable, not zero).
    """
    timed = [p for p in packets if p["timestamp"] is not None]
    timestamps = [p["timestamp"] for p in timed]
    sizes = [p["captured_length"] for p in timed]
    if not timestamps:
        return None
    start, end = min(timestamps), max(timestamps)
    duration = end - start
    width = float(config["rate_window_seconds"])
    if duration / width > config["max_rate_bins"]:
        width = duration / config["max_rate_bins"]
    bins_p: Counter = Counter()
    bins_b: Counter = Counter()
    for ts, size in zip(timestamps, sizes):
        slot = int((ts - start) / width)
        bins_p[slot] += 1
        bins_b[slot] += size
    busy = [n for n in bins_p.values() if n]
    median = statistics.median(busy)
    peak_slot = max(bins_p, key=lambda s: (bins_p[s], -s))
    bursts = [{"offset_seconds": round(slot * width, 3), "window_seconds": round(width, 3), "packets": n,
               "packets_per_second": round(n / width, 1), "bytes": bins_b[slot]}
              for slot, n in sorted(bins_p.items(), key=lambda kv: -kv[1])
              if n >= config["burst_min_packets"] and n >= config["burst_factor"] * median][:5]
    points = int(config["series_points"])
    chunk = max(1, -(-(int(duration / width) + 1) // points))      # ceil division
    series: Dict[int, List[int]] = {}
    for slot, n in bins_p.items():
        bucket = series.setdefault(slot // chunk, [0, 0])
        bucket[0] += n
        bucket[1] += bins_b[slot]
    return {
        "window_seconds": round(width, 3),
        "average_pps": round(len(timestamps) / duration, 2) if duration > 0 else None,
        "average_bytes_per_second": round(sum(sizes) / duration, 1) if duration > 0 else None,
        "peak": {"offset_seconds": round(peak_slot * width, 3), "packets": bins_p[peak_slot],
                 "packets_per_second": round(bins_p[peak_slot] / width, 1), "bytes": bins_b[peak_slot]},
        "bursts": bursts,
        "series": [{"offset_seconds": round(k * chunk * width, 3), "packets": v[0], "bytes": v[1]}
                   for k, v in sorted(series.items())],
    }


def quality_block(packets: List[dict], capture_info: Optional[dict]) -> dict:
    """summary["data_quality"]: counts of truncated / malformed / unsupported packets, missing timestamps, warnings."""
    info = capture_info or {}
    missing = sum(1 for p in packets if p["timestamp"] is None)
    notes: List[str] = []
    if missing:
        notes.append(f"{missing} packet(s) have no timestamp and are excluded from rate and time-window analysis.")
    if info.get("file_truncated"):
        notes.append("The capture file ends abruptly; the final packets may be missing.")
    truncated = sum(1 for p in packets if p["truncated"])
    if info.get("snaplen") and truncated:
        notes.append("Some packets were cut short by the capture snap length; payload-based findings may be incomplete.")
    return {"truncated_packets": truncated, "malformed_packets": sum(1 for p in packets if p["malformed"]),
            "unsupported_packets": info.get("unsupported_packets"), "packets_without_timestamp": missing,
            "file_truncated": info.get("file_truncated", False), "read_limit_reached": info.get("read_limit_reached", False),
            "warnings": list(info.get("warnings", [])), "notes": notes}


def analyze_traffic(packets: List[dict], capture_info: Optional[dict] = None, config: Optional[dict] = None) -> dict:
    config = {**DEFAULT_CONFIG, **(config or {})}
    flow_list, untracked = build_flows(packets, config["max_flows"])
    summary = {
        "capture": capture_block(packets, capture_info),
        "totals": totals_block(packets),
        "protocols": protocol_table(packets),
        "top_sources": top_hosts(packets, "source", config["top_n"]),
        "top_destinations": top_hosts(packets, "destination", config["top_n"]),
        "top_destination_ports": top_service_ports(packets, config["top_n"]),
        "tcp": tcp_statistics(packets),
        "flows": {"total": len(flow_list), "tracked": len(flow_list), "untracked_packets": untracked,
                  "truncated": untracked > 0, "top": flow_list[:config["top_n"]]},
        "traffic_rate": rate_summary(packets, config),
        "data_quality": quality_block(packets, capture_info),
    }
    return {"packets": packets, "capture_info": dict(capture_info or {}), "config": config, "flows": flow_list, "summary": summary}
