"""Rule: high-rate, mostly one-way UDP traffic aimed at one host."""
from __future__ import annotations

from collections import Counter
from typing import List

from engine.default_rules.base_rule import BaseRule
from engine.default_rules.windows import episodes_by_count, group_by, sorted_by_time


class UDPFloodRule(BaseRule):
    rule_id = "udp_flood"
    name = "Possible UDP flood"
    category = "Denial of Service"
    description = "Large numbers of UDP packets to one host in a short window with few or no replies."
    defaults = {"packet_threshold": 500, "window_seconds": 5.0, "max_reverse_ratio": 0.2,
                "excluded_source_ports": (53,)}
    limitations = ("Only packet counts, direction and sizes are used. A capture taken on one side of the link "
                   "may hide the target's replies; DNS responses are handled by the DNS amplification rule.")
    false_positives = "One-way media/telemetry streams (RTP, syslog, NetFlow, game or video traffic) and backups."

    def detect(self, context: dict) -> List[dict]:
        udp = [p for p in sorted_by_time(context["index"]["udp"])
               if p["destination_ip"] and p["source_port"] not in self.params["excluded_source_ports"]]
        by_target = group_by(udp, lambda p: p["destination_ip"])
        by_sender = group_by(context["index"]["udp"], lambda p: p["source_ip"])
        threshold, window = self.params["packet_threshold"], self.params["window_seconds"]
        findings = []
        for target, items in by_target.items():
            if len(items) < threshold:
                continue
            for burst in episodes_by_count(items, lambda p: p["timestamp"], window, threshold):
                first, last = burst[0]["timestamp"], burst[-1]["timestamp"]
                sources = {p["source_ip"] for p in burst}
                replies = [p for p in by_sender.get(target, []) if p["destination_ip"] in sources
                           and p["timestamp"] is not None and first <= p["timestamp"] <= last]
                reverse_ratio = len(replies) / len(burst)
                if reverse_ratio > self.params["max_reverse_ratio"]:
                    continue
                span = max(last - first, 1e-6)
                total_bytes = sum(p["captured_length"] for p in burst)
                visible = bool(by_sender.get(target))
                heavy = len(burst) >= 4 * threshold
                confidence = "High" if heavy and visible and reverse_ratio < 0.05 else ("Medium" if visible or heavy else "Low")
                top = Counter(p["source_ip"] for p in burst).most_common(1)[0]
                findings.append(self.finding(
                    summary=(f"{len(burst)} UDP packets ({total_bytes / 1e6:.2f} MB) reached {target} in {span:.1f}s "
                             f"({len(burst) / span:.0f} packets/s) with {reverse_ratio:.0%} reverse traffic."),
                    severity="High" if confidence == "High" else "Medium", confidence=confidence,
                    classification="inferred",
                    explanation=("UDP has no handshake, so floods are recognised by rate and one-sidedness: many "
                                 "packets towards one host and (almost) nothing coming back."),
                    evidence=[f"{len(burst)} UDP packets in {span:.2f}s to {target}",
                              f"{len(sources)} source(s); busiest {top[0]} sent {top[1]}",
                              f"{len({p['destination_port'] for p in burst})} distinct destination port(s)",
                              f"average packet size {total_bytes / len(burst):.0f} bytes",
                              f"{len(replies)} reply packet(s) from the target ({reverse_ratio:.0%})"],
                    stats={"packets": len(burst), "packets_per_second": round(len(burst) / span, 1),
                           "bytes": total_bytes, "distinct_sources": len(sources), "reverse_ratio": round(reverse_ratio, 3)},
                    source_ips=sorted(sources), destination_ips=[target],
                    destination_ports=[p["destination_port"] for p in burst[:200]], protocol="UDP",
                    first_seen=first, last_seen=last, window_seconds=window,
                    packet_numbers=[p["packet_number"] for p in burst],
                    recommendation="Rate-limit or filter UDP to this host/port upstream and check the target's load and logs."))
        return findings
