"""Rule: DNS reflection/amplification - unsolicited large responses, or tiny queries drawing huge answers."""
from __future__ import annotations

from collections import Counter
from typing import List

from engine.default_rules.base_rule import BaseRule
from engine.default_rules.windows import episodes_by_count, group_by


class DNSAmplificationRule(BaseRule):
    rule_id = "dns_amplification"
    name = "DNS amplification indicators"
    category = "Denial of Service"
    description = "Many large DNS responses sent to a host that never asked for them, or answers far larger than the queries."
    defaults = {"response_threshold": 20, "window_seconds": 10.0, "min_response_bytes": 300,
                "amplification_factor": 10.0, "min_queries": 20}
    limitations = "Unsolicited-response detection needs the victim's outbound queries to be in the capture; UDP DNS only."
    false_positives = "Captures that start mid-conversation (queries missing), and legitimate DNSSEC/large-TXT lookups."

    def detect(self, context: dict) -> List[dict]:
        msgs = [m for m in context["dns_messages"] if m["timestamp"] is not None]
        asked = {(m["client_ip"], m["id"], m["qname"]) for m in msgs if not m["is_response"]}
        findings = []
        big = [m for m in msgs if m["is_response"] and m["size"] >= self.params["min_response_bytes"]
               and (m["client_ip"], m["id"], m["qname"]) not in asked]
        for victim, items in group_by(big, lambda m: m["client_ip"]).items():
            items.sort(key=lambda m: m["timestamp"])
            for ep in episodes_by_count(items, lambda m: m["timestamp"], self.params["window_seconds"], self.params["response_threshold"]):
                servers = {m["server_ip"] for m in ep}
                kinds = Counter(m["qtype_name"] for m in ep)
                findings.append(self.finding(
                    title="Unsolicited large DNS responses (possible reflection)",
                    summary=f"{victim} received {len(ep)} large DNS responses from {len(servers)} server(s) that match no query it sent.",
                    severity="Medium", confidence="Medium" if len(servers) > 1 else "Low", classification="inferred",
                    explanation="In a reflection attack the attacker spoofs the victim's address in small queries, so open resolvers send big answers to a victim who never asked.",
                    evidence=[f"{len(ep)} responses of >= {self.params['min_response_bytes']} bytes (average {sum(m['size'] for m in ep) / len(ep):.0f})",
                              f"{len(servers)} responding server(s); types: " + ", ".join(f"{k} x{v}" for k, v in kinds.most_common(3)),
                              "no matching outbound query found in the capture"],
                    stats={"responses": len(ep), "servers": len(servers), "bytes": sum(m["size"] for m in ep)},
                    source_ips=sorted(servers), destination_ips=[victim], source_ports=[53], protocol="DNS",
                    first_seen=ep[0]["timestamp"], last_seen=ep[-1]["timestamp"], window_seconds=self.params["window_seconds"],
                    packet_numbers=[m["packet_number"] for m in ep],
                    recommendation="Filter inbound DNS responses that do not match outbound queries and rate-limit at the edge; ask resolver operators to close open resolvers."))
        for client, items in group_by([m for m in msgs if not m["is_response"]], lambda m: m["client_ip"]).items():
            items.sort(key=lambda m: m["timestamp"])
            for ep in episodes_by_count(items, lambda m: m["timestamp"], self.params["window_seconds"], self.params["min_queries"]):
                keys = {(m["client_ip"], m["id"], m["qname"]) for m in ep}
                answers = [m for m in msgs if m["is_response"] and (m["client_ip"], m["id"], m["qname"]) in keys]
                q_bytes, a_bytes = sum(m["size"] for m in ep), sum(m["size"] for m in answers)
                if not answers or a_bytes < self.params["amplification_factor"] * q_bytes:
                    continue
                findings.append(self.finding(
                    title="High DNS amplification ratio",
                    summary=f"{len(ep)} DNS queries from {client} drew {a_bytes / q_bytes:.0f}x more response bytes than were sent.",
                    severity="Low", confidence="Low", classification="indicator",
                    explanation="Answers far larger than queries are what attackers exploit for amplification; ANY/TXT/DNSSEC queries are typical choices.",
                    evidence=[f"{q_bytes} query bytes vs {a_bytes} response bytes", "query types: " + ", ".join(f"{k} x{v}" for k, v in Counter(m['qtype_name'] for m in ep).most_common(3))],
                    stats={"query_bytes": q_bytes, "response_bytes": a_bytes, "ratio": round(a_bytes / q_bytes, 1)},
                    source_ips=[client], destination_ips=sorted({m["server_ip"] for m in ep}), destination_ports=[53], protocol="DNS",
                    first_seen=ep[0]["timestamp"], last_seen=ep[-1]["timestamp"], window_seconds=self.params["window_seconds"],
                    packet_numbers=[m["packet_number"] for m in ep + answers],
                    recommendation="Check whether the client or server is being abused; disable recursion for untrusted sources and rate-limit ANY queries."))
        return findings
