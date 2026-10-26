"""Rule: TCP port scans - vertical (many ports, one host) and horizontal (one port, many hosts)."""
from __future__ import annotations

from collections import Counter
from typing import Dict, List, Optional

from engine.default_rules.base_rule import BaseRule
from engine.default_rules.windows import episodes_by_distinct, group_by, sorted_by_time


def probe_type(flags: str) -> Optional[str]:
    """Classify the first packet of a connection attempt / scan probe."""
    if "S" in flags and "A" not in flags and "R" not in flags:
        return "SYN"
    if flags == "":
        return "NULL"
    if flags == "F":
        return "FIN"
    if set("FPU") <= set(flags) and "S" not in flags and "A" not in flags:
        return "XMAS"
    return None


class TCPPortScanRule(BaseRule):
    rule_id = "tcp_port_scan"
    name = "TCP port scan"
    category = "Reconnaissance"
    description = ("One source probing many ports on a host (vertical) or one port on many hosts (horizontal) "
                   "with SYN / NULL / FIN / XMAS probes that mostly do not turn into real connections.")
    defaults = {"vertical_port_threshold": 15, "horizontal_host_threshold": 10,
                "window_seconds": 60.0, "max_established_ratio": 0.5}
    limitations = ("Probe outcomes (open/closed) need the target's replies to be in the capture. Slow scans "
                   "spread over more than the window are not linked together.")
    false_positives = ("Browsers or crawlers contacting many hosts, service-discovery tools, load balancers "
                       "health-checking many backends, and FTP passive-mode data connections.")

    def detect(self, context: dict) -> List[dict]:
        tcp = context["index"]["tcp"]
        probes = [p for p in sorted_by_time(tcp) if p["destination_port"] is not None and probe_type(p["tcp_flags"] or "")]
        if not probes:
            return []
        replies: Dict[tuple, str] = {}          # (server_ip, server_port, client_ip, client_port) -> "open" | "closed"
        followups = set()                        # client 4-tuples that sent a real ACK after the handshake
        for p in tcp:
            flags = p["tcp_flags"] or ""
            if "S" in flags and "A" in flags:
                replies[(p["source_ip"], p["source_port"], p["destination_ip"], p["destination_port"])] = "open"
            elif "R" in flags:
                replies.setdefault((p["source_ip"], p["source_port"], p["destination_ip"], p["destination_port"]), "closed")
            elif "A" in flags and "S" not in flags:
                followups.add((p["source_ip"], p["source_port"], p["destination_ip"], p["destination_port"]))
        window = self.params["window_seconds"]
        findings = []
        by_pair = group_by(probes, lambda p: (p["source_ip"], p["destination_ip"]))
        for (src, dst), items in by_pair.items():
            if len({p["destination_port"] for p in items}) < self.params["vertical_port_threshold"]:
                continue
            for ep in episodes_by_distinct(items, lambda p: p["timestamp"], lambda p: p["destination_port"],
                                           window, self.params["vertical_port_threshold"]):
                f = self._report(ep, "vertical", src, dst, replies, followups, window)
                if f:
                    findings.append(f)
        by_port = group_by(probes, lambda p: (p["source_ip"], p["destination_port"]))
        for (src, port), items in by_port.items():
            if len({p["destination_ip"] for p in items}) < self.params["horizontal_host_threshold"]:
                continue
            for ep in episodes_by_distinct(items, lambda p: p["timestamp"], lambda p: p["destination_ip"],
                                           window, self.params["horizontal_host_threshold"]):
                f = self._report(ep, "horizontal", src, None, replies, followups, window)
                if f:
                    findings.append(f)
        return findings

    def _report(self, ep, direction, src, dst, replies, followups, window) -> Optional[dict]:
        # A scan touches each target once, so keep only the FIRST probe per distinct target (later repeats are
        # ordinary use of an open service, not part of the scan).
        first_probe: Dict[object, dict] = {}
        for p in ep:
            first_probe.setdefault(p["destination_port"] if direction == "vertical" else p["destination_ip"], p)
        ep = sorted(first_probe.values(), key=lambda p: (p["timestamp"], p["packet_number"]))
        # Judge each distinct TARGET (port for vertical scans, host for horizontal) once, by its best outcome,
        # so thousands of ordinary connections to one open port cannot hide a scan of the others.
        rank = {"connected": 3, "open (not completed)": 2, "closed (reset)": 1, "no reply": 0}
        per_target: Dict[object, str] = {}
        for p in ep:
            key = (p["destination_ip"], p["destination_port"], p["source_ip"], p["source_port"])
            reply = replies.get(key)
            if reply == "open":
                result = "connected" if (p["source_ip"], p["source_port"], p["destination_ip"], p["destination_port"]) in followups else "open (not completed)"
            else:
                result = "closed (reset)" if reply == "closed" else "no reply"
            target = p["destination_port"] if direction == "vertical" else p["destination_ip"]
            if rank[result] > rank.get(per_target.get(target), -1):
                per_target[target] = result
        outcomes = Counter(per_target.values())
        established = outcomes["connected"] / len(per_target)
        if established > self.params["max_established_ratio"]:
            return None                                  # mostly real connections: ordinary client behaviour
        visible = len(per_target) > outcomes["no reply"]
        types = Counter(probe_type(p["tcp_flags"] or "") for p in ep)
        ports = sorted({p["destination_port"] for p in ep})
        hosts = sorted({p["destination_ip"] for p in ep})
        count = len(ports) if direction == "vertical" else len(hosts)
        threshold = self.params["vertical_port_threshold" if direction == "vertical" else "horizontal_host_threshold"]
        confidence = ("High" if visible and established <= 0.2 and count >= threshold else
                      "Medium" if visible else ("Medium" if count >= 3 * threshold else "Low"))
        first, last = ep[0]["timestamp"], ep[-1]["timestamp"]
        half_open = outcomes["open (not completed)"] > 0 and outcomes["connected"] == 0 and types["SYN"] == len(ep)
        label = ("SYN (half-open) scan pattern" if half_open else
                 "/".join(sorted(t for t in types if t)) + " probes")
        if direction == "vertical":
            title = "TCP port scan (vertical): many ports on one host"
            summary = f"{src} probed {len(ports)} different TCP ports on {dst} within {last - first:.2f}s."
        else:
            title = "TCP port scan (horizontal): one port across many hosts"
            summary = f"{src} sent connection attempts to port {ports[0]} on {len(hosts)} different hosts within {last - first:.2f}s."
        return self.finding(
            title=title, summary=summary, severity="Medium" if confidence != "Low" else "Low", confidence=confidence,
            classification="inferred",
            explanation=("Scanners try many ports or hosts quickly and rarely complete connections. Here a single source "
                         "probed many distinct targets inside one short window, and most probes were not turned into real "
                         "connections. This is reconnaissance behaviour, not a flood."),
            evidence=[f"{len(ep)} probes; {count} distinct {'ports' if direction == 'vertical' else 'hosts'}; {label}",
                      "outcome per distinct " + ("port" if direction == "vertical" else "host") + ": " + ", ".join(f"{k}={v}" for k, v in outcomes.most_common()),
                      f"{len({p['source_port'] for p in ep})} distinct source port(s) used",
                      ("target replies visible in capture" if visible else "no target replies visible - outcomes unknown")],
            stats={"probes": len(ep), "distinct_ports": len(ports), "distinct_hosts": len(hosts),
                   "established_ratio": round(established, 3), "outcomes": dict(outcomes), "probe_types": dict(types)},
            source_ips=[src], destination_ips=[dst] if dst else hosts, destination_ports=ports, protocol="TCP",
            first_seen=first, last_seen=last, window_seconds=window, packet_numbers=[p["packet_number"] for p in ep],
            recommendation="Verify whether the source is an authorised scanner; otherwise block it and review exposed services.")
