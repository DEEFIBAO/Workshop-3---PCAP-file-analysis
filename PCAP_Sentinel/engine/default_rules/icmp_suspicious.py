"""Rule: suspicious ICMP behaviour - ping sweeps, oversized echo payloads, redirects."""
from __future__ import annotations

from typing import List

from engine.default_rules.base_rule import BaseRule
from engine.default_rules.windows import episodes_by_distinct, group_by, sorted_by_time


class ICMPSuspiciousRule(BaseRule):
    rule_id = "icmp_suspicious"
    name = "Suspicious ICMP behaviour"
    category = "Reconnaissance"
    description = "Ping sweeps across many hosts, unusually large echo payloads (possible tunnelling), ICMP redirects."
    defaults = {"sweep_host_threshold": 10, "window_seconds": 60.0, "large_payload_bytes": 256,
                "large_payload_packets": 5}
    limitations = "Payload contents are not decoded; large payloads are only an indicator of possible covert use."
    false_positives = "Network discovery tools, path-MTU testing and monitoring systems."

    def detect(self, context: dict) -> List[dict]:
        icmp = sorted_by_time(context["index"]["icmp"])
        requests = [p for p in icmp if (p["protocol"], p["icmp_type"]) in (("ICMP", 8), ("ICMPv6", 128))]
        findings = []
        for src, items in group_by(requests, lambda p: p["source_ip"]).items():
            for ep in episodes_by_distinct(items, lambda p: p["timestamp"], lambda p: p["destination_ip"],
                                           self.params["window_seconds"], self.params["sweep_host_threshold"]):
                hosts = {p["destination_ip"] for p in ep}
                findings.append(self.finding(
                    title="ICMP ping sweep", summary=f"{src} sent echo requests to {len(hosts)} different hosts within {ep[-1]['timestamp'] - ep[0]['timestamp']:.1f}s.",
                    severity="Low", confidence="Medium", classification="inferred",
                    explanation="One source pinging many different addresses in a short time is host discovery.",
                    evidence=[f"{len(ep)} echo requests to {len(hosts)} distinct hosts"],
                    stats={"packets": len(ep), "distinct_hosts": len(hosts)}, source_ips=[src],
                    destination_ips=sorted(hosts), protocol=ep[0]["protocol"], first_seen=ep[0]["timestamp"],
                    last_seen=ep[-1]["timestamp"], window_seconds=self.params["window_seconds"],
                    packet_numbers=[p["packet_number"] for p in ep],
                    recommendation="Confirm the source is an authorised discovery tool; consider filtering ICMP at network boundaries."))
        big = [p for p in requests if (p["payload_length"] or 0) >= self.params["large_payload_bytes"]]
        for (src, dst), items in group_by(big, lambda p: (p["source_ip"], p["destination_ip"])).items():
            if len(items) >= self.params["large_payload_packets"]:
                findings.append(self.finding(
                    title="Unusually large ICMP echo payloads",
                    summary=f"{len(items)} ICMP echo requests from {src} to {dst} carried {max(p['payload_length'] for p in items)} bytes or more.",
                    severity="Low", confidence="Low", classification="indicator",
                    explanation="Ordinary ping payloads are tiny (32-64 bytes). Repeated large payloads can indicate data being smuggled inside ICMP, or simply MTU testing.",
                    evidence=[f"{len(items)} echo requests with payload >= {self.params['large_payload_bytes']} bytes"],
                    stats={"packets": len(items), "max_payload": max(p["payload_length"] for p in items)},
                    source_ips=[src], destination_ips=[dst], protocol=items[0]["protocol"],
                    first_seen=items[0]["timestamp"], last_seen=items[-1]["timestamp"],
                    packet_numbers=[p["packet_number"] for p in items],
                    recommendation="Inspect the payloads in Wireshark; block or rate-limit ICMP between these hosts if it is not needed."))
        redirects = [p for p in icmp if p["protocol"] == "ICMP" and p["icmp_type"] == 5]
        for (src, dst), items in group_by(redirects, lambda p: (p["source_ip"], p["destination_ip"])).items():
            findings.append(self.finding(
                title="ICMP redirect observed", summary=f"{src} sent {len(items)} ICMP redirect(s) to {dst}.",
                severity="Low", confidence="Medium", classification="observed",
                explanation="ICMP redirects change a host's routing and are a known man-in-the-middle technique; modern networks rarely need them.",
                evidence=[f"{len(items)} redirect message(s)"], stats={"packets": len(items)},
                source_ips=[src], destination_ips=[dst], protocol="ICMP", first_seen=items[0]["timestamp"],
                last_seen=items[-1]["timestamp"], packet_numbers=[p["packet_number"] for p in items],
                recommendation="Disable acceptance of ICMP redirects on hosts and verify the sender is a legitimate router."))
        return findings
