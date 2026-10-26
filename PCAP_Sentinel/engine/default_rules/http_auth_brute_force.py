"""Rule: repeated HTTP login submissions answered with failures."""
from __future__ import annotations

import re
from collections import Counter
from typing import List
from urllib.parse import parse_qsl

from engine.default_rules.base_rule import BaseRule
from engine.default_rules.redaction import is_sensitive_name
from engine.default_rules.windows import episodes_by_count, group_by

LOGIN_PATH = re.compile(r"(log-?in|sign-?in|logon|auth|session|wp-login)", re.I)


def has_password_field(tx: dict) -> bool:
    body = tx["body"]
    if "=" in body and "{" not in body[:2]:
        return any("pass" in k.lower() or "pwd" in k.lower() for k, _ in parse_qsl(body, keep_blank_values=True))
    return bool(re.search(r'"[a-z_]*(pass|pwd)[a-z_]*"\s*:', body, re.I))


def is_login_attempt(tx: dict) -> bool:
    if tx["has_authorization"] and tx["authorization_scheme"] in ("Basic", "Digest"):
        return True
    return tx["method"] == "POST" and (bool(LOGIN_PATH.search(tx["path"])) or has_password_field(tx))


def outcome(tx: dict) -> str:
    r = tx["response"]
    if r is None:
        return "no response"
    if r["status"] in (401, 403):
        return "failure"
    if 300 <= r["status"] < 400:
        return "redirect+cookie" if r["set_cookie_fps"] else "redirect"
    if r["status"] >= 500:
        return "server error"
    return "ambiguous (2xx)"


class HTTPAuthBruteForceRule(BaseRule):
    rule_id = "http_auth_brute_force"
    name = "Possible HTTP login brute force"
    category = "Authentication"
    description = "Repeated login submissions from one client to one login endpoint, judged by HTTP status codes."
    defaults = {"attempt_threshold": 8, "window_seconds": 300.0, "min_failures": 5}
    limitations = ("Only clear-text HTTP is visible. A 200 response is NOT proof of a failed or successful login - it needs server "
                   "logs or response-body review. Only 401/403 are counted as definite failures.")
    false_positives = "Single-page apps that poll an auth endpoint, API clients refreshing tokens, password-manager retries."

    def detect(self, context: dict) -> List[dict]:
        attempts = [t for t in context["http_transactions"] if t["timestamp"] is not None and is_login_attempt(t)]
        findings = []
        for (client, server, path), items in group_by(attempts, lambda t: (t["client_ip"], t["server_ip"], t["path"])).items():
            for ep in episodes_by_count(items, lambda t: t["timestamp"], self.params["window_seconds"], self.params["attempt_threshold"]):
                outcomes = Counter(outcome(t) for t in ep)
                fails = outcomes["failure"]
                if fails < self.params["min_failures"] and len(ep) < 2 * self.params["attempt_threshold"]:
                    continue
                first, last = ep[0]["timestamp"], ep[-1]["timestamp"]
                users = {u for t in ep for k, u in parse_qsl(t["body"], keep_blank_values=True)
                         if k.lower() in ("username", "user", "email", "login", "uname")}
                variants = len({hash(t["body"]) for t in ep})
                confidence = "High" if fails >= self.params["attempt_threshold"] else ("Medium" if fails >= self.params["min_failures"] else "Low")
                later = [t for t in items if t["timestamp"] > last or t in ep]
                cookies = [t for t in later if outcome(t) == "redirect+cookie"]
                issued = {fp for t in cookies for fp in t["response"]["set_cookie_fps"]}
                reused = sorted({t["path"] for t in context["http_transactions"] if t["client_ip"] == client
                                 and t["server_ip"] == server and issued & set(t["cookie_fps"])})[:5]
                evidence = [f"{len(ep)} login submissions to {path} in {last - first:.0f}s ({60 * len(ep) / max(last - first, 1):.1f}/min)",
                            "responses: " + ", ".join(f"{k}={v}" for k, v in outcomes.most_common()),
                            f"{variants} different request bodies; {len(users)} username value(s)"]
                if cookies:
                    evidence.append(f"{len(cookies)} submission(s) were answered with a redirect that set a session cookie - this MAY be a successful login (not proof)")
                if reused:
                    evidence.append("a session cookie issued in such a response was later presented to: " + ", ".join(reused))
                findings.append(self.finding(
                    summary=f"{len(ep)} login submissions from {client} to {server}{path}; {fails} were rejected (401/403).",
                    severity="High" if confidence == "High" else "Medium", confidence=confidence, classification="inferred",
                    explanation=("Repeated POSTs to the same login endpoint, mostly answered with 401/403, is the signature of password "
                                 "guessing. The pace can be slow (to avoid lockouts) and still be a brute force."),
                    evidence=evidence,
                    stats={"attempts": len(ep), "failures": fails, "outcomes": dict(outcomes), "request_variants": variants,
                           "usernames": len(users)},
                    source_ips=[client], destination_ips=[server], destination_ports=[ep[0]["server_port"]], protocol="HTTP",
                    first_seen=first, last_seen=last, window_seconds=self.params["window_seconds"],
                    packet_numbers=[n for t in ep for n in t["frames"]] + [t["response"]["frame"] for t in ep if t["response"]],
                    recommendation="Add rate limiting, account lockout/back-off and MFA to the login; review server logs for the account(s) targeted; serve logins over HTTPS only."))
        return findings
