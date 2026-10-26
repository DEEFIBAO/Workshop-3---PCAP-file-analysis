"""Rule: generic high-rate bursts that no specific rule explains (informational)."""
from __future__ import annotations

import statistics
from collections import Counter
from typing import List

from engine.default_rules.base_rule import BaseRule
from engine.default_rules.windows import sorted_by_time


class TrafficBurstRule(BaseRule):
    rule_id = "traffic_burst"
    name = "Traffic burst"
    category = "Denial of Service"
    description = "A time bin carrying far more packets than the capture's typical busy bin."
    defaults = {"bin_seconds": 1.0, "min_packets": 500, "burst_factor": 10.0, "max_findings": 3}
    limitations = "Says only that traffic spiked and who dominated it; it cannot say whether the spike is hostile."
    false_positives = "Bulk file transfers, backups, software updates, streaming and any benign high-volume burst."

    def detect(self, context: dict) -> List[dict]:
        packets = sorted_by_time(context["packets"])
        if not packets:
            return []
        width, start = self.params["bin_seconds"], packets[0]["timestamp"]
        bins: dict = {}
        for p in packets:
            bins.setdefault(int((p["timestamp"] - start) / width), []).append(p)
        median = statistics.median(len(v) for v in bins.values())
        hot = sorted((s for s, v in bins.items()
                      if len(v) >= self.params["min_packets"] and len(v) >= self.params["burst_factor"] * median),
                     key=lambda s: -len(bins[s]))[: self.params["max_findings"]]
        findings = []
        for slot in sorted(hot):
            items = bins[slot]
            talker = Counter((p["source_ip"], p["destination_ip"], p["protocol"], p["destination_port"]) for p in items)
            (src, dst, proto, port), count = talker.most_common(1)[0]
            syn = sum(1 for p in items if p["tcp_flags"] and "S" in p["tcp_flags"] and "A" not in p["tcp_flags"])
            findings.append(self.finding(
                summary=f"{len(items)} packets in {width:g}s ({len(items) / width:.0f}/s), about {len(items) / max(median, 1):.0f}x a typical busy second.",
                severity="Informational", confidence="Low", classification="observed",
                explanation="A sudden spike in packet rate. Dedicated flood and scan rules decide whether it is an attack; this only highlights the spike.",
                evidence=[f"busiest conversation: {src} -> {dst} {proto}" + (f" port {port}" if port else "") + f" ({count} packets, {count / len(items):.0%})",
                          f"{syn} new-connection (SYN-only) packets in the bin", f"typical busy bin: {median:g} packets"],
                stats={"packets": len(items), "packets_per_second": round(len(items) / width, 1), "typical_busy_bin": median},
                source_ips=[src] if src else [], destination_ips=[dst] if dst else [],
                destination_ports=[port] if port else [], protocol=proto,
                first_seen=items[0]["timestamp"], last_seen=items[-1]["timestamp"], window_seconds=width,
                packet_numbers=[p["packet_number"] for p in items],
                recommendation="Check what generated the spike (backup, update, scan or attack) using the per-conversation statistics."))
        return findings
