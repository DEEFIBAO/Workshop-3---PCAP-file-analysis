"""Rule: web path enumeration, request bursts and repeated HTTP errors."""
from __future__ import annotations

import re
from collections import Counter
from typing import List

from engine.default_rules.base_rule import BaseRule
from engine.default_rules.windows import episodes_by_count, episodes_by_distinct, group_by

SENSITIVE_PATH = re.compile(r"(^|/)(admin|administrator|wp-admin|wp-login|phpmyadmin|\.env|\.git|\.svn|\.htaccess|backup|config|server-status|cgi-bin|manager|console)(\.|/|$)|\.(bak|old|sql|zip|tar|gz|conf|ini|swp)$", re.I)


class WebEnumerationRule(BaseRule):
    rule_id = "web_enumeration"
    name = "Web path enumeration / request burst"
    category = "Web activity"
    description = "One client requesting many different paths (mostly errors or sensitive-looking), or flooding a web server with requests."
    defaults = {"distinct_path_threshold": 6, "window_seconds": 60.0, "min_error_ratio": 0.5,
                "sensitive_path_threshold": 3, "request_burst_threshold": 100, "burst_window_seconds": 10.0}
    limitations = "Needs visible clear-text HTTP; error ratios need the server's responses in the capture."
    false_positives = "Site crawlers/search engines, vulnerability scanners run by the owner, and single-page apps that request many assets."

    def detect(self, context: dict) -> List[dict]:
        txs = [t for t in context["http_transactions"] if t["timestamp"] is not None]
        findings = []
        for (client, server), items in group_by(txs, lambda t: (t["client_ip"], t["server_ip"])).items():
            items.sort(key=lambda t: t["timestamp"])
            for ep in episodes_by_distinct(items, lambda t: t["timestamp"], lambda t: t["path"].rstrip("/").lower() or "/",
                                           self.params["window_seconds"], self.params["distinct_path_threshold"]):
                answered = [t for t in ep if t["response"]]
                errors = [t for t in answered if t["response"]["status"] in (401, 403, 404, 405)]
                ratio = len(errors) / len(answered) if answered else None
                paths = sorted({t["path"] for t in ep})
                sensitive = [p for p in paths if SENSITIVE_PATH.search(p)]
                if not ((ratio is not None and ratio >= self.params["min_error_ratio"]) or len(sensitive) >= self.params["sensitive_path_threshold"]):
                    continue
                codes = Counter(t["response"]["status"] for t in answered)
                confidence = "High" if ratio is not None and ratio >= 0.5 and len(sensitive) >= 2 else "Medium"
                findings.append(self._f(
                    "Web path enumeration", client, server, ep, f"{len(paths)} different paths requested within {ep[-1]['timestamp'] - ep[0]['timestamp']:.0f}s",
                    "Real users follow links, so they rarely request many unrelated paths where most do not exist. Probing for admin, backup or config paths is how automated discovery tools work.",
                    [f"{len(paths)} distinct paths; {len(sensitive)} look sensitive: {', '.join(sensitive[:6]) or 'none'}",
                     "status codes: " + (", ".join(f"{k}x{v}" for k, v in codes.most_common()) or "none visible"),
                     f"error ratio (401/403/404/405): {'n/a' if ratio is None else f'{ratio:.0%}'}"],
                    {"distinct_paths": len(paths), "sensitive_paths": len(sensitive), "error_ratio": None if ratio is None else round(ratio, 3)},
                    "Medium", confidence, self.params["window_seconds"],
                    "Block or rate-limit the client, remove exposed admin/backup files, and require authentication on admin paths."))
            for ep in episodes_by_count(items, lambda t: t["timestamp"], self.params["burst_window_seconds"], self.params["request_burst_threshold"]):
                span = max(ep[-1]["timestamp"] - ep[0]["timestamp"], 1e-6)
                findings.append(self._f(
                    "HTTP request burst", client, server, ep, f"{len(ep)} requests in {span:.1f}s ({len(ep) / span:.0f}/s)",
                    "A very high request rate from one client can be an application-layer flood or an aggressive scraper.",
                    [f"{len(ep)} requests in {span:.2f}s", f"{len({t['path'] for t in ep})} distinct paths"],
                    {"requests": len(ep), "requests_per_second": round(len(ep) / span, 1)}, "Medium", "Medium",
                    self.params["burst_window_seconds"], "Apply per-client rate limiting or a CDN/WAF and check server load."))
        return findings

    def _f(self, title, client, server, ep, headline, why, evidence, stats, severity, confidence, window, rec) -> dict:
        return self.finding(
            title=title, summary=f"{client} -> {server}: {headline}.", severity=severity, confidence=confidence,
            classification="inferred", explanation=why, evidence=evidence, stats=stats, source_ips=[client],
            destination_ips=[server], destination_ports=[ep[0]["server_port"]], protocol="HTTP",
            first_seen=ep[0]["timestamp"], last_seen=ep[-1]["timestamp"], window_seconds=window,
            packet_numbers=[n for t in ep for n in t["frames"]] + [t["response"]["frame"] for t in ep if t["response"]],
            recommendation=rec)
