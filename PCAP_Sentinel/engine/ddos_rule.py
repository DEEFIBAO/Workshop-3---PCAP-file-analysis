"""DDoS / flood rule: detect a possible TCP SYN flood.

HOW IT WORKS
    A SYN flood sends a very large number of connection requests (SYN packets) at ONE service and
    never finishes the handshake, so the server keeps half-open connections in memory.
    A port scan also sends many SYNs - but to MANY DIFFERENT PORTS, so we group SYNs by the
    service being hit (destination IP + destination port) and count within a short time window.
    Finally we check whether the connections were actually completed: if most were, it looks like
    busy-but-ordinary traffic (or a brute-force tool), not a half-open flood.

    The rule receives the shared ``context`` (see engine/default_rules/__init__.py) and returns a
    list of findings built with ``self.finding(...)`` (see engine/default_rules/base_rule.py).
"""
from __future__ import annotations

from collections import Counter
from typing import List

from engine.default_rules.base_rule import BaseRule


class DDoSDetectionRule(BaseRule):
    rule_id = "syn_flood"
    name = "Possible TCP SYN flood"
    category = "Denial of Service"
    description = ("Many TCP SYN packets aimed at one service within a short window, where the "
                   "handshakes are mostly never completed.")
    defaults = {
        "syn_threshold": 100,        # unique SYN-only packets to one service inside one window
        "window_seconds": 5.0,       # length of the sliding window
        "completed_cutoff": 0.5,     # if >= this share of the SYNs finished the handshake: not half-open
    }
    limitations = ("SYN packets alone do not prove a service was degraded. If the capture only shows one "
                   "direction, the handshake outcome cannot be checked and confidence is lowered.")
    false_positives = ("Load tests, busy servers behind NAT, and tools that open many short connections "
                       "(handled by the completed-handshake check, but not perfectly).")

    def detect(self, context: dict) -> List[dict]:
        packets = [p for p in context.get("packets", []) if p["protocol"] == "TCP" and p["timestamp"] is not None]
        threshold, window = self.params["syn_threshold"], self.params["window_seconds"]

        # 1. SYN-only packets (SYN set, ACK and RST clear), duplicates removed (same 4-tuple + sequence).
        seen, syns = set(), []
        for p in packets:
            flags = p["tcp_flags"] or ""
            if "S" in flags and "A" not in flags and "R" not in flags:
                key = (p["source_ip"], p["source_port"], p["destination_ip"], p["destination_port"], p["tcp_seq"])
                if key not in seen:
                    seen.add(key)
                    syns.append(p)

        # 2. Handshake evidence: which 4-tuples got a SYN-ACK, which finished with a client ACK,
        #    and which services ever spoke back (so we know whether the replies are even visible).
        answered, completed, talkers = set(), set(), set()
        for p in packets:
            flags = p["tcp_flags"] or ""
            talkers.add((p["source_ip"], p["source_port"]))
            if "S" in flags and "A" in flags:
                answered.add((p["destination_ip"], p["destination_port"], p["source_ip"], p["source_port"]))
            elif "A" in flags and "S" not in flags and "R" not in flags:
                completed.add((p["source_ip"], p["source_port"], p["destination_ip"], p["destination_port"]))

        # 3. Group by the targeted service.
        groups = {}
        for p in sorted(syns, key=lambda x: (x["timestamp"], x["packet_number"])):
            groups.setdefault((p["destination_ip"], p["destination_port"]), []).append(p)

        findings = []
        for (target, port), items in groups.items():
            if len(items) < threshold:
                continue
            # 4. Sliding window (two pointers): find the busiest window.
            left, best = 0, (0, 0)
            for right in range(len(items)):
                while items[right]["timestamp"] - items[left]["timestamp"] > window:
                    left += 1
                if right - left > best[1] - best[0]:
                    best = (left, right)
            burst = items[best[0]:best[1] + 1]
            if len(burst) < threshold:
                continue

            # 5. Were the handshakes completed?
            keys = [(p["source_ip"], p["source_port"], target, port) for p in burst]
            answered_ratio = sum(1 for k in keys if (k[0], k[1], k[2], k[3]) in answered) / len(burst)
            completed_ratio = sum(1 for k in keys if k in completed) / len(burst)
            if completed_ratio >= self.params["completed_cutoff"]:
                continue
            visible = (target, port) in talkers

            sources = Counter(p["source_ip"] for p in burst)
            span = max(burst[-1]["timestamp"] - burst[0]["timestamp"], 1e-6)
            if not visible:
                confidence = "Low"
            elif completed_ratio <= 0.1 and len(burst) >= 3 * threshold:
                confidence = "High"
            else:
                confidence = "Medium"
            kind = "single source" if len(sources) == 1 else f"distributed, {len(sources)} sources"
            findings.append(self.finding(
                title=f"Possible TCP SYN flood ({kind})",
                summary=(f"{len(burst)} SYN-only packets hit {target}:{port} within {span:.1f}s "
                         f"({len(burst) / span:.0f} per second) and {1 - completed_ratio:.0%} never completed the handshake."),
                severity="High" if confidence == "High" else "Medium", confidence=confidence,
                classification="inferred",
                explanation=("A SYN flood concentrates many connection requests on one service without finishing "
                             "the handshake. This burst was concentrated on a single destination port (unlike a port scan, "
                             "which spreads across ports) and most connections were not completed."),
                evidence=[f"{len(burst)} unique SYN-only packets to {target}:{port} in {span:.2f}s",
                          f"{len(sources)} distinct source address(es); busiest sent {sources.most_common(1)[0][1]}",
                          f"{answered_ratio:.0%} received a SYN-ACK; {completed_ratio:.0%} completed the handshake",
                          "Server replies are visible in the capture" if visible else
                          "No packets from the target service are visible, so the handshake outcome is unknown"],
                stats={"syn_count": len(burst), "syn_per_second": round(len(burst) / span, 1),
                       "distinct_sources": len(sources), "answered_ratio": round(answered_ratio, 3),
                       "completed_ratio": round(completed_ratio, 3)},
                source_ips=[ip for ip, _ in sources.most_common(5)], destination_ips=[target],
                destination_ports=[port], protocol="TCP",
                first_seen=burst[0]["timestamp"], last_seen=burst[-1]["timestamp"], window_seconds=window,
                packet_numbers=[p["packet_number"] for p in burst],
                recommendation=("Enable SYN cookies, rate-limit new connections per source, and filter upstream "
                                "(firewall / provider scrubbing). Confirm impact in server and load-balancer logs.")))
        return findings
