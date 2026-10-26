"""Rule: bursts of TCP resets (refused connections, aborted sessions, scan responses)."""
from __future__ import annotations

from typing import List

from engine.default_rules.base_rule import BaseRule
from engine.default_rules.windows import episodes_by_count, group_by, sorted_by_time


class TCPResetRule(BaseRule):
    rule_id = "tcp_reset_burst"
    name = "TCP reset burst"
    category = "Connection anomalies"
    description = "Many TCP RST packets from one host to another in a short window."
    defaults = {"rst_threshold": 50, "window_seconds": 10.0}
    limitations = "A reset burst is a symptom with several causes; it never identifies the cause on its own."
    false_positives = "Services restarting, firewalls rejecting traffic, load balancers, and the replies a closed host sends to a scan."

    def detect(self, context: dict) -> List[dict]:
        findings = []
        rsts = sorted_by_time(context["index"]["rst"])
        for (src, dst), items in group_by(rsts, lambda p: (p["source_ip"], p["destination_ip"])).items():
            for ep in episodes_by_count(items, lambda p: p["timestamp"], self.params["window_seconds"], self.params["rst_threshold"]):
                ports = {p["source_port"] for p in ep}
                refused = sum(1 for p in ep if "A" in (p["tcp_flags"] or ""))
                many_ports = len(ports) >= 10
                findings.append(self.finding(
                    summary=f"{len(ep)} TCP resets from {src} to {dst} over {ep[-1]['timestamp'] - ep[0]['timestamp']:.0f}s (at least {self.params['rst_threshold']} per {self.params['window_seconds']:g}s window).",
                    severity="Informational", confidence="Low", classification="observed",
                    explanation=("Resets from many different ports are typical replies to a scan of closed ports. "
                                 "Resets from one port suggest a service repeatedly refusing or aborting connections.")
                    if many_ports else "Repeated resets from the same port suggest a service refusing or aborting connections.",
                    evidence=[f"{len(ep)} RST packets; {refused} were RST+ACK (typical 'connection refused')",
                              f"{len(ports)} distinct source port(s) sent resets"],
                    stats={"packets": len(ep), "rst_ack": refused, "distinct_ports": len(ports)},
                    source_ips=[src], destination_ips=[dst], source_ports=list(ports)[:30], protocol="TCP",
                    first_seen=ep[0]["timestamp"], last_seen=ep[-1]["timestamp"], window_seconds=self.params["window_seconds"],
                    packet_numbers=[p["packet_number"] for p in ep],
                    recommendation="Correlate with service logs and firewall rules to find out why connections were refused or aborted."))
        return findings
