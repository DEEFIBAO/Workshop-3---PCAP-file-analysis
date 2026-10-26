"""Rule: SQL-injection, directory-traversal and JNDI-lookup patterns in visible HTTP requests."""
from __future__ import annotations

import re
from collections import Counter
from typing import List, Tuple
from urllib.parse import parse_qsl, unquote, unquote_plus

from engine.default_rules.base_rule import BaseRule
from engine.default_rules.redaction import is_sensitive_name, safe_excerpt
from engine.default_rules.windows import group_by

SQLI = [
    (re.compile(r"union(\s|\+|/\*.*?\*/)+(all(\s|\+)+)?select", re.I), "UNION SELECT"),
    (re.compile(r"['\"]\s*(or|and)\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+", re.I), "quote + OR/AND tautology"),
    (re.compile(r"\b(or|and)\s+\d+\s*=\s*\d+", re.I), "OR/AND numeric tautology"),
    (re.compile(r"['\"]\s*(--|#|/\*)"), "quote followed by SQL comment"),
    (re.compile(r";\s*(drop|insert|update|delete|exec|shutdown)\b", re.I), "stacked statement"),
    (re.compile(r"\b(sleep|benchmark|pg_sleep|load_file|extractvalue|updatexml)\s*\(|waitfor\s+delay", re.I), "time/function injection"),
    (re.compile(r"information_schema|sysobjects|xp_cmdshell", re.I), "schema/system object access"),
]
TRAVERSAL = [
    (re.compile(r"(\.\.[/\\]){2,}"), "repeated ../ sequences"),
    (re.compile(r"/etc/(passwd|shadow)|boot\.ini|win\.ini|system32[/\\]config", re.I), "sensitive system file path"),
]
JNDI = [(re.compile(r"\$\{\s*(jndi|\$\{)", re.I), "JNDI lookup string")]
CATEGORIES = {"sqli": ("SQL injection pattern", SQLI), "traversal": ("Directory traversal pattern", TRAVERSAL),
              "jndi": ("JNDI/Log4Shell-style lookup", JNDI)}


def _decode(text: str) -> str:
    return unquote_plus(unquote(text))


def request_fields(tx: dict) -> List[Tuple[str, str]]:
    fields = [("path", _decode(tx["path"]))]
    fields += [(k, _decode(v)) for k, v in parse_qsl(tx["query"], keep_blank_values=True)]
    body, ctype = tx["body"], (tx["content_type"] or "").lower()
    if body:
        if "urlencoded" in ctype or ("=" in body and not body.lstrip().startswith(("{", "<"))):
            fields += [(k, _decode(v)) for k, v in parse_qsl(body, keep_blank_values=True)]
        else:
            fields.append(("body", _decode(body)))
    if tx["user_agent"]:
        fields.append(("user-agent", _decode(tx["user_agent"])))
    return fields


class WebAttackPatternRule(BaseRule):
    rule_id = "web_attack_patterns"
    name = "Web attack pattern in request"
    category = "Web activity"
    description = "Requests containing SQL-injection, directory-traversal or JNDI-lookup strings."
    defaults = {"max_examples": 3}
    limitations = ("A matching request is an ATTEMPT, not proof of exploitation. Only clear-text HTTP is visible; "
                   "HTTPS payloads cannot be inspected without decryption keys. Matching is signature-based.")
    false_positives = "Security scanners run by the owner, developers testing input validation, and unusual but harmless inputs (e.g. SQL discussed in a forum post)."

    def detect(self, context: dict) -> List[dict]:
        txs = context["http_transactions"]
        hits = []
        for tx in txs:
            for name, value in request_fields(tx):
                for cat, (_, patterns) in CATEGORIES.items():
                    for regex, label in patterns:
                        if regex.search(value):
                            shown = "[value in sensitive field omitted]" if is_sensitive_name(name) else safe_excerpt(value, 60)
                            hits.append({"tx": tx, "cat": cat, "label": label, "param": name, "shown": shown})
                            break
            r = tx["response"]
            if r and r["db_error"] and not any(h["tx"] is tx for h in hits):
                for name, value in request_fields(tx):
                    if name not in ("path", "user-agent") and re.search(r"['\"]", value):
                        hits.append({"tx": tx, "cat": "sqli", "label": "unbalanced quote answered by an SQL error", "param": name,
                                     "shown": "[value in sensitive field omitted]" if is_sensitive_name(name) else safe_excerpt(value, 60)})
                        break
        findings = []
        for (client, server, cat), items in group_by(hits, lambda h: (h["tx"]["client_ip"], h["tx"]["server_ip"], h["cat"])).items():
            title, _ = CATEGORIES[cat]
            reqs = list({id(h["tx"]): h["tx"] for h in items}.values())
            labels = Counter(h["label"] for h in items)
            statuses = Counter(t["response"]["status"] for t in reqs if t["response"])
            db_errors = [t for t in reqs if t["response"] and t["response"]["db_error"]]
            strong = [l for l in labels if "unbalanced" not in l]
            confidence = "High" if len(strong) >= 2 else "Medium" if strong or db_errors else "Low"
            severity = "High" if (cat == "sqli" and db_errors) or len(reqs) >= 10 or cat == "jndi" else "Medium"
            evidence = [f"{len(reqs)} request(s) matched; patterns: " + ", ".join(f"{k} x{v}" for k, v in labels.most_common(4)),
                        "examples: " + " | ".join(f"{h['tx']['method']} {safe_excerpt(h['tx']['path'], 40)} [{h['param']}] {h['shown']}" for h in items[:self.params['max_examples']]),
                        "response codes: " + (", ".join(f"{k}x{v}" for k, v in statuses.most_common()) or "none visible")]
            if db_errors:
                evidence.append(f"{len(db_errors)} response(s) contained database error text ({db_errors[0]['response']['db_error']}) - the input may have reached the SQL parser")
            if cat == "sqli":
                issued = {fp for t in reqs if t["response"] for fp in t["response"]["set_cookie_fps"]}
                reused = sorted({t["path"] for t in txs if t["client_ip"] == client and issued & set(t["cookie_fps"])})[:4]
                if issued:
                    evidence.append("an injection-pattern request was answered with a new session cookie"
                                    + (f", later presented to: {', '.join(reused)} - consistent with a login bypass but NOT proof" if reused else ""))
            times = [t["timestamp"] for t in reqs if t["timestamp"] is not None]
            findings.append(self.finding(
                title=title, summary=f"{client} sent {len(reqs)} request(s) to {server} containing {title.lower()}s.",
                severity=severity, confidence=confidence, classification="indicator",
                explanation="The request text (URL, form fields or headers, URL-decoded) matched known attack signatures. This shows an attempt, not whether it worked.",
                evidence=evidence, stats={"requests": len(reqs), "patterns": dict(labels), "db_error_responses": len(db_errors)},
                source_ips=[client], destination_ips=[server], destination_ports=[reqs[0]["server_port"]], protocol="HTTP",
                first_seen=min(times) if times else None, last_seen=max(times) if times else None,
                packet_numbers=[n for t in reqs for n in t["frames"]],
                recommendation="Use parameterised queries / input validation, deploy a WAF, hide database errors from users, and review server logs to see whether the attempts succeeded."))
        return findings
