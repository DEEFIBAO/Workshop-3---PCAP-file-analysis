"""TASK 2 - Traffic analyser: general statistics, conversations and traffic rates (no attack logic here).

WHERE IT FITS
    packets --> analyze_traffic() --> context --> (detection rules) --> build_report()

You implement nine small functions. ``analyze_traffic()`` at the bottom is PROVIDED and simply calls them and
packs the results into the ``context`` dictionary the rules and the dashboard use.

RULES OF THE GAME
    * Packets are the dictionaries described at the top of engine/pcap_reader.py.
    * "Not available" is NOT zero: use None when something cannot be computed (no timestamps -> no duration, no rate).
    * Do not loop in a way that explodes memory: captures can have hundreds of thousands of packets.

HOW YOU KNOW YOU ARE DONE
    python -m unittest tests.test_student_tasks.Task2TrafficAnalyzer -v
    python -m unittest tests.test_framework.StatisticsTests -v
"""
from __future__ import annotations

import statistics   # noqa: F401  (handy for the median)
from collections import Counter   # noqa: F401  (handy for counting)
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from engine.default_rules.services import service_name   # noqa: F401  (port -> "HTTP", "FTP", ...)

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
    """PROVIDED. Epoch seconds -> ISO-8601 UTC text (None stays None)."""
    if timestamp is None:
        return None
    try:
        return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        return None


def capture_block(packets: List[dict], capture_info: Optional[dict]) -> dict:
    """summary["capture"].

    Return a dict with: file_size_bytes, format, link_types (copy these three from capture_info with sensible defaults),
    packet_count, first_timestamp, last_timestamp, duration_seconds, start_utc, end_utc.

    TODO  Ignore packets whose timestamp is None. If NO packet has a timestamp, first/last/duration/start/end are None.
          duration_seconds = last - first (round to 6 places). Use _utc() for start_utc / end_utc.
    """
    raise NotImplementedError("TODO (Task 2): capture_block()")


def totals_block(packets: List[dict]) -> dict:
    """summary["totals"] -> {"packets", "captured_bytes", "wire_bytes", "average_packet_size"}.

    TODO  captured_bytes = sum of captured_length. wire_bytes = sum of original_length, but None when the capture is
          empty OR any packet's original_length is None (a partial sum would be misleading).
          average_packet_size = captured_bytes / packets rounded to 1 place, None for an empty capture.
    """
    raise NotImplementedError("TODO (Task 2): totals_block()")


def protocol_table(packets: List[dict]) -> List[dict]:
    """summary["protocols"] -> [{"protocol", "packets", "bytes", "percent"}] ordered by packets, largest first.

    TODO  Count packets and captured bytes per packet["protocol"]; percent = 100 * packets / total, 1 decimal place.
    """
    raise NotImplementedError("TODO (Task 2): protocol_table()")


def top_hosts(packets: List[dict], role: str, top_n: int) -> List[dict]:
    """summary["top_sources"] (role == "source") or summary["top_destinations"] (role == "destination").

    Return [{"ip", "packets", "bytes"}] for the ``top_n`` busiest addresses, busiest first.
    TODO  Use source_ip or destination_ip depending on ``role``. Skip packets where that address is None.
    """
    raise NotImplementedError("TODO (Task 2): top_hosts()")


def top_service_ports(packets: List[dict], top_n: int) -> List[dict]:
    """summary["top_destination_ports"] -> [{"port", "protocol", "service", "packets"}], busiest first.

    Replies travel to random client ports, which would swamp the table. So count only TCP/UDP packets that head TOWARDS
    the service port: destination_port <= source_port (or source_port is None).
    TODO  Count by (protocol, destination_port); service = service_name(port) (None when unknown).
    """
    raise NotImplementedError("TODO (Task 2): top_service_ports()")


def tcp_statistics(packets: List[dict]) -> dict:
    """summary["tcp"] -> {"packets", "connection_attempts", "synack_responses", "reset_packets", "fin_packets",
    "retransmissions", "flag_counts"}.

    TODO  Look only at TCP packets. A connection attempt is a SYN WITHOUT ACK (and without RST). A SYN-ACK has both S and A.
          Count RST and FIN packets. flag_counts = a dict of counts (e.g. {"SYN": .., "SYN-ACK": .., "RST": ..}).
          Retransmission: a segment with data (or SYN/FIN) whose (source ip, source port, destination ip, destination port,
          tcp_seq, payload_length, has-SYN, has-FIN) was already seen. Keep the 'seen' set bounded (<= 1,000,000 entries).
    """
    raise NotImplementedError("TODO (Task 2): tcp_statistics()")


def build_flows(packets: List[dict], max_flows: int) -> Tuple[List[dict], int]:
    """Conversations (both directions together) -> (flow_list, untracked_packets).

    A flow dict: {"protocol", "a_ip", "a_port", "b_ip", "b_port", "packets", "bytes", "packets_a_to_b",
                  "first_ts", "last_ts", "duration"}      (a = whoever sent the first packet we saw)
    TODO  Skip packets without both IP addresses and ARP packets. The flow key must be the same for A->B and B->A
          (hint: sort the two (ip, port) endpoints). Missing ports count as 0 in the key.
          Stop creating NEW flows once ``max_flows`` exist; count the packets that did not fit as untracked.
          duration = last_ts - first_ts, or None when the flow has no timestamps.
          Return the flows sorted by packets (largest first).
    """
    raise NotImplementedError("TODO (Task 2): build_flows()")


def rate_summary(packets: List[dict], config: dict) -> Optional[dict]:
    """summary["traffic_rate"]: packets per time window. Return None if no packet has a timestamp.

    Return {"window_seconds", "average_pps", "average_bytes_per_second", "peak", "bursts", "series"} where
        peak   = {"offset_seconds", "packets", "packets_per_second", "bytes"}   (the busiest window)
        bursts = up to 5 windows with >= config["burst_min_packets"] packets AND >= config["burst_factor"] x the
                 MEDIAN busy window, strongest first: {"offset_seconds", "window_seconds", "packets",
                 "packets_per_second", "bytes"}
        series = about config["series_points"] points for the dashboard chart: [{"offset_seconds", "packets", "bytes"}]
    TODO  1. Window width = config["rate_window_seconds"]; widen it if duration / width > config["max_rate_bins"].
          2. window index = int((timestamp - first_timestamp) / width). Count packets and bytes per window.
          3. average_pps = packets / duration, but None when duration is 0 (undefined, not 0).
          4. Find the peak and the bursts, then merge neighbouring windows into at most series_points points.
    """
    raise NotImplementedError("TODO (Task 2): rate_summary()")


def quality_block(packets: List[dict], capture_info: Optional[dict]) -> dict:
    """summary["data_quality"] -> {"truncated_packets", "malformed_packets", "unsupported_packets",
    "packets_without_timestamp", "file_truncated", "read_limit_reached", "warnings", "notes"}.

    TODO  Count truncated / malformed packets from the packet flags and packets with timestamp None.
          Copy unsupported_packets, file_truncated, read_limit_reached and warnings from capture_info (defaults: None,
          False, False, []). ``notes`` = human sentences, e.g. when timestamps are missing, the file ends abruptly
          (file_truncated) or packets were cut by the snap length - the dashboard shows them as warnings.
    """
    raise NotImplementedError("TODO (Task 2): quality_block()")


def analyze_traffic(packets: List[dict], capture_info: Optional[dict] = None, config: Optional[dict] = None) -> dict:
    """PROVIDED glue: calls your functions and builds the shared ``context`` dictionary."""
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
