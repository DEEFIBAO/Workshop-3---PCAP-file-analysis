"""Rule: DNS tunnelling-like behaviour - many unique, long, high-entropy sub-domain labels."""
from __future__ import annotations

import math
from collections import Counter
from typing import List

from engine.default_rules.base_rule import BaseRule
from engine.default_rules.windows import episodes_by_count, group_by

SECOND_LEVEL = {"co", "com", "org", "net", "gov", "ac", "edu"}


def entropy(text: str) -> float:
    """Shannon entropy in bits per character."""
    if not text:
        return 0.0
    counts = Counter(text)
    return -sum(c / len(text) * math.log2(c / len(text)) for c in counts.values())


def split_domain(qname: str):
    labels = qname.strip(".").split(".")
    keep = 3 if len(labels) >= 3 and labels[-1].__len__() == 2 and labels[-2] in SECOND_LEVEL else 2
    return ".".join(labels[-keep:]), labels[:-keep]


class DNSTunnellingRule(BaseRule):
    rule_id = "dns_tunnelling"
    name = "DNS tunnelling-like queries"
    category = "Exfiltration / C2"
    description = "Many unique, long, high-entropy sub-domain labels queried under a single parent domain."
    defaults = {"min_unique_names": 10, "window_seconds": 300.0, "min_label_length": 20,
                "entropy_threshold": 3.5, "suspicious_ratio": 0.6}
    limitations = "UDP DNS only; payloads are judged by label length and randomness, not decoded. Encrypted DNS (DoH/DoT) is invisible."
    false_positives = "CDNs, anti-virus and cloud services that use long random sub-domains (e.g. hashes, UUIDs, reputation look-ups)."

    def detect(self, context: dict) -> List[dict]:
        queries = [m for m in context["dns_messages"] if not m["is_response"] and m["timestamp"] is not None]
        rows = []
        for m in queries:
            parent, sub = split_domain(m["qname"])
            if sub:
                rows.append({**m, "parent": parent, "label": max(sub, key=len), "sub": ".".join(sub)})
        findings = []
        for (client, parent), items in group_by(rows, lambda r: (r["client_ip"], r["parent"])).items():
            items.sort(key=lambda r: r["timestamp"])
            for ep in episodes_by_count(items, lambda r: r["timestamp"], self.params["window_seconds"], self.params["min_unique_names"]):
                unique = {r["sub"]: r for r in ep}
                if len(unique) < self.params["min_unique_names"]:
                    continue
                odd = [r for r in unique.values() if len(r["label"]) >= self.params["min_label_length"]
                       and entropy(r["label"]) >= self.params["entropy_threshold"]]
                ratio = len(odd) / len(unique)
                if ratio < self.params["suspicious_ratio"]:
                    continue
                types = Counter(r["qtype_name"] for r in ep)
                avg_len = sum(len(r["label"]) for r in odd) / len(odd)
                avg_ent = sum(entropy(r["label"]) for r in odd) / len(odd)
                findings.append(self.finding(
                    summary=f"{client} sent {len(unique)} unique long, random-looking DNS names under {parent}.",
                    severity="Medium", confidence="High" if ratio >= 0.9 and len(unique) >= 3 * self.params["min_unique_names"] else "Medium",
                    classification="indicator",
                    explanation="Normal host names are short and readable. Data hidden in DNS (tunnelling/exfiltration) appears as many different, long, random-looking labels under one domain the attacker controls.",
                    evidence=[f"{len(unique)} unique sub-domains; {len(odd)} ({ratio:.0%}) have a label >= {self.params['min_label_length']} chars and entropy >= {self.params['entropy_threshold']}",
                              f"average suspicious label: {avg_len:.0f} chars, {avg_ent:.2f} bits/char", "query types: " + ", ".join(f"{k} x{v}" for k, v in types.most_common(4))],
                    stats={"unique_names": len(unique), "suspicious_names": len(odd), "avg_label_length": round(avg_len, 1),
                           "avg_entropy": round(avg_ent, 2), "queries": len(ep)},
                    source_ips=[client], destination_ips=sorted({r["server_ip"] for r in ep}), destination_ports=[53], protocol="DNS",
                    first_seen=ep[0]["timestamp"], last_seen=ep[-1]["timestamp"], window_seconds=self.params["window_seconds"],
                    packet_numbers=[r["packet_number"] for r in ep],
                    recommendation="Inspect the parent domain's reputation, restrict DNS to approved resolvers, and consider DNS filtering/monitoring on the client."))
        return findings
