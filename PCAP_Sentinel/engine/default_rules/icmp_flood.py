"""Rule: ICMP echo-request floods and unsolicited echo-reply floods (reflection)."""
from __future__ import annotations

from typing import List

from engine.default_rules.base_rule import BaseRule
from engine.default_rules.windows import episodes_by_count, group_by, sorted_by_time

ECHO_REQUEST = {("ICMP", 8), ("ICMPv6", 128)}
ECHO_REPLY = {("ICMP", 0), ("ICMPv6", 129)}


class ICMPFloodRule(BaseRule):
    rule_id = "icmp_flood"
    name = "Possible ICMP flood"
    category = "Denial of Service"
    description = "Many ICMP echo requests to one host, or many unsolicited echo replies (reflection)."
    defaults = {"packet_threshold": 100, "window_seconds": 5.0, "reply_flood_min_sources": 3}
    limitations = "Rate-based only; the capture does not show whether the target was actually degraded."
    false_positives = "Monitoring tools and administrators running `ping -f`, and network health checks."

    def detect(self, context: dict) -> List[dict]:
        icmp = sorted_by_time(context["index"]["icmp"])
        requests = [p for p in icmp if (p["protocol"], p["icmp_type"]) in ECHO_REQUEST]
        replies = [p for p in icmp if (p["protocol"], p["icmp_type"]) in ECHO_REPLY]
        threshold, window = self.params["packet_threshold"], self.params["window_seconds"]
        findings = []
        replies_by_src = group_by(replies, lambda p: p["source_ip"])
        for target, items in group_by(requests, lambda p: p["destination_ip"]).items():
            if len(items) < threshold:
                continue
            for burst in episodes_by_count(items, lambda p: p["timestamp"], window, threshold):
                first, last = burst[0]["timestamp"], burst[-1]["timestamp"]
                span = max(last - first, 1e-6)
                answered = sum(1 for p in replies_by_src.get(target, []) if first <= p["timestamp"] <= last + 1)
                sources = sorted({p["source_ip"] for p in burst})
                findings.append(self.finding(
                    summary=f"{len(burst)} ICMP echo requests reached {target} in {span:.1f}s ({len(burst) / span:.0f} per second).",
                    severity="Medium", confidence="High" if len(burst) >= 4 * threshold else "Medium",
                    classification="inferred",
                    explanation="Ordinary ping sends about one echo request per second per source; this rate is far higher.",
                    evidence=[f"{len(burst)} echo requests in {span:.2f}s", f"{len(sources)} source(s)",
                              f"{answered} echo replies from the target were seen in the same period"],
                    stats={"packets": len(burst), "packets_per_second": round(len(burst) / span, 1),
                           "distinct_sources": len(sources), "replies_seen": answered},
                    source_ips=sources, destination_ips=[target], protocol=burst[0]["protocol"],
                    first_seen=first, last_seen=last, window_seconds=window,
                    packet_numbers=[p["packet_number"] for p in burst],
                    recommendation="Rate-limit ICMP at the edge and confirm whether the source is an authorised monitoring host."))
        requests_by_src = group_by(requests, lambda p: p["source_ip"])
        for victim, items in group_by(replies, lambda p: p["destination_ip"]).items():
            if len(items) < threshold:
                continue
            for burst in episodes_by_count(items, lambda p: p["timestamp"], window, threshold):
                first, last = burst[0]["timestamp"], burst[-1]["timestamp"]
                senders = {p["source_ip"] for p in burst}
                asked = sum(1 for p in requests_by_src.get(victim, []) if first - 5 <= p["timestamp"] <= last)
                if len(senders) < self.params["reply_flood_min_sources"] or asked >= 0.2 * len(burst):
                    continue
                findings.append(self.finding(
                    title="Possible ICMP echo-reply flood (reflection)",
                    summary=f"{len(burst)} unsolicited ICMP echo replies from {len(senders)} hosts reached {victim}.",
                    severity="Medium", confidence="Medium", classification="inferred",
                    explanation="Many different hosts replied to a host that sent almost no echo requests, which is how reflection/smurf-style floods look.",
                    evidence=[f"{len(burst)} echo replies in {max(last - first, 0):.1f}s from {len(senders)} sources",
                              f"only {asked} matching echo request(s) from {victim}"],
                    stats={"packets": len(burst), "distinct_sources": len(senders), "matching_requests": asked},
                    source_ips=sorted(senders), destination_ips=[victim], protocol=burst[0]["protocol"],
                    first_seen=first, last_seen=last, window_seconds=window,
                    packet_numbers=[p["packet_number"] for p in burst],
                    recommendation="Disable directed-broadcast replies and filter ICMP echo replies that do not match outbound requests."))
        return findings
