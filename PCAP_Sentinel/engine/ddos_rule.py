"""TASK 4 - DDoS / flood rule: detect a possible TCP SYN flood.

THE IDEA
    A SYN flood sends a huge number of connection requests (SYN packets) at ONE service and never finishes the
    handshake, so the server fills up with half-open connections.
    A port scan also sends many SYNs - but to MANY DIFFERENT PORTS. So we group SYNs by the service being hit
    (destination IP + destination port) and count them inside a short sliding time window.
    Finally we check whether the handshakes were COMPLETED. If most were, the traffic is busy-but-ordinary (or a brute-force
    tool opening many connections) - not a half-open flood.

WHERE IT FITS
    app.py runs this rule beside all the prebuilt rules. It receives the shared ``context`` dictionary and returns a list of
    findings. You may read: context["packets"] (list of packet dicts, see engine/pcap_reader.py) and
    context["index"]["syn_only"] etc. (see engine/default_rules/__init__.py).

THE SHARED RULE INTERFACE (engine/default_rules/base_rule.py)
    Your class inherits from BaseRule. Thresholds live in ``defaults`` and are available as ``self.params[...]``. Build each
    finding with ``self.finding(...)``. Keyword arguments you will use:
        title=, summary=, severity= ("High"/"Medium"/"Low"/"Informational"), confidence= ("High"/"Medium"/"Low"),
        classification= ("observed" | "indicator" | "inferred"),  explanation=  (WHY it triggered, plain English),
        evidence= [short factual strings],  stats= {numbers},  source_ips=[...], destination_ips=[...],
        destination_ports=[...], protocol="TCP", first_seen=, last_seen= (packet timestamps), window_seconds=,
        packet_numbers=[...], recommendation=
    Strings are automatically scrubbed of secrets for you.

HOW YOU KNOW YOU ARE DONE
    python -m unittest tests.test_student_tasks.Task4SynFloodRule -v
    python -m unittest tests.test_rules.SynFloodTests -v
"""
from __future__ import annotations

from collections import Counter   # noqa: F401
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
        """Return a list of findings (an empty list when nothing is found).

        TODO 1  Keep TCP packets that have a timestamp. A SYN-ONLY packet has "S" in tcp_flags but no "A" and no "R".
                Remove duplicates: the same (source ip, source port, destination ip, destination port, tcp_seq) is ONE
                attempt, however many times it was captured or retransmitted.
        TODO 2  Collect handshake evidence in one pass over the TCP packets:
                  answered  = 4-tuples that received a SYN-ACK (S and A both set) - remember the tuple from the CLIENT's view
                  completed = 4-tuples where the client later sent an ACK (A set, no S, no R)
                  talkers   = (ip, port) pairs that ever SENT a packet (tells you whether the server's replies are visible)
        TODO 3  Group the SYN-only packets by (destination_ip, destination_port), each group sorted by timestamp.
                Skip groups smaller than self.params["syn_threshold"].
        TODO 4  Sliding window with two pointers (left, right): move ``left`` forward while
                timestamp[right] - timestamp[left] > self.params["window_seconds"]. Remember the window with the most packets.
                If that busiest window holds fewer than syn_threshold packets, skip the group.
        TODO 5  completed_ratio = share of the window's SYNs whose 4-tuple is in ``completed``;
                answered_ratio similarly. If completed_ratio >= self.params["completed_cutoff"] -> NOT a half-open flood: skip.
        TODO 6  Work out sources (Counter of source_ip), the time span (avoid dividing by zero), and whether the server's replies
                are visible. Confidence:  "Low" if replies are not visible;  "High" if completed_ratio <= 0.1 and the window has
                >= 3 x syn_threshold SYNs;  otherwise "Medium".  Severity: "High" when confidence is "High", else "Medium".
        TODO 7  Create the finding with self.finding(...): classification "inferred", a title that says "single source" or
                "distributed, N sources", a summary with the SYN count / rate / share that never completed, an explanation,
                four evidence lines (counts, sources, answered/completed ratios, whether server replies are visible),
                stats {"syn_count", "syn_per_second", "distinct_sources", "answered_ratio", "completed_ratio"},
                the first/last timestamps of the window, the packet numbers, and a defensive recommendation
                (SYN cookies, per-source rate limits, upstream filtering).
        """
        raise NotImplementedError("TODO (Task 4): implement DDoSDetectionRule.detect() in engine/ddos_rule.py")
