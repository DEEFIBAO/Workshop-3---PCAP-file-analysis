"""Rule: UDP port scanning - many ports on one host, small probes, ICMP port-unreachable replies."""
from __future__ import annotations

import statistics
from typing import List

from engine.default_rules.base_rule import BaseRule
from engine.default_rules.windows import episodes_by_distinct, group_by, sorted_by_time


class UDPScanRule(BaseRule):
    rule_id = "udp_port_scan"
    name = "UDP port scan"
    category = "Reconnaissance"
    description = "One source sending small UDP datagrams to many ports on one host, often answered by ICMP port-unreachable."
    defaults = {"port_threshold": 20, "window_seconds": 60.0, "max_median_payload": 64}
    limitations = "Open UDP ports normally stay silent, so only the unreachable replies for closed ports give strong evidence."
    false_positives = "VoIP/RTP port ranges, game traffic and P2P software legitimately use many UDP ports."

    def detect(self, context: dict) -> List[dict]:
        udp = [p for p in sorted_by_time(context["index"]["udp"]) if p["destination_port"] is not None
               and p["source_port"] != 53]
        unreachable = group_by((p for p in context["index"]["icmp"] if p["protocol"] == "ICMP"
                                and p["icmp_type"] == 3 and p["icmp_code"] == 3),
                               lambda p: (p["source_ip"], p["destination_ip"]))
        findings = []
        for (src, dst), items in group_by(udp, lambda p: (p["source_ip"], p["destination_ip"])).items():
            if len({p["destination_port"] for p in items}) < self.params["port_threshold"]:
                continue
            for ep in episodes_by_distinct(items, lambda p: p["timestamp"], lambda p: p["destination_port"],
                                           self.params["window_seconds"], self.params["port_threshold"]):
                payload = statistics.median(p["payload_length"] or 0 for p in ep)
                if payload > self.params["max_median_payload"]:
                    continue
                first, last = ep[0]["timestamp"], ep[-1]["timestamp"]
                ports = sorted({p["destination_port"] for p in ep})
                errors = [p for p in unreachable.get((dst, src), []) if first <= p["timestamp"] <= last + 2]
                confidence = "High" if len(errors) >= 0.3 * len(ports) else ("Medium" if errors else "Low")
                findings.append(self.finding(
                    summary=f"{src} sent small UDP datagrams to {len(ports)} different ports on {dst} within {last - first:.1f}s.",
                    severity="Medium" if confidence != "Low" else "Low", confidence=confidence, classification="inferred",
                    explanation="Many distinct UDP ports probed with tiny payloads in a short time is how UDP scanners work; closed ports usually answer with ICMP port-unreachable.",
                    evidence=[f"{len(ep)} UDP packets to {len(ports)} distinct ports", f"median payload {payload:g} bytes",
                              f"{len(errors)} ICMP port-unreachable replies from the target"],
                    stats={"packets": len(ep), "distinct_ports": len(ports), "icmp_unreachable": len(errors)},
                    source_ips=[src], destination_ips=[dst], destination_ports=ports, protocol="UDP",
                    first_seen=first, last_seen=last, window_seconds=self.params["window_seconds"],
                    packet_numbers=[p["packet_number"] for p in ep] + [p["packet_number"] for p in errors],
                    recommendation="Confirm whether the source is an authorised scanner; block it and review which UDP services are exposed."))
        return findings
