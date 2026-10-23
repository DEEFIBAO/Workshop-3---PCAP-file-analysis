"""D6 - Website attacks detector.

Attacks aimed at a website rather than at the computer it runs on.

THE RULES
  Use the ready-made helper:  from ready_made.http_tools import http_exchanges
  Each x in http_exchanges(packets) is one website request + the server's answer:
    x["client"], x["server"], x["method"], x["path"], x["body"], x["status"], x["response"]

  1) Probing: one client asks for 5 or more DIFFERENT paths that the server answers
     with 403 (forbidden) or 404 (not found), e.g. /admin/, /backup.zip, /wp-admin/.
     -> one "medium" alert per (client, server).
  2) SQL injection: x["path"] or x["body"] contains database tricks such as
         ' OR '1'='1      UNION SELECT      '--
     OR the server crashed with a database error (x["status"] == 500 and
     "sql" in x["response"].lower()).
     -> one "high" alert per (client, server).
     If any of those requests got a success answer (200 or 302), say it probably WORKED.

HINT
  import re
  SQLI = re.compile(r"('|\")\s*(or|and)\s+['\"\d]|union\s+select|'\s*--", re.IGNORECASE)
  if SQLI.search(x["body"]): ...

EACH ALERT LOOKS LIKE THIS (keep these exact keys):
  {"detector": "web_attack", "severity": "high", "title": "Short name",
   "src": "1.2.3.4", "dst": "5.6.7.8", "detail": "One line explaining why"}

TEST IT ON ITS OWN:  python check.py web
  Expected on compsoc-incident.pcap: 2 alerts: probing, and an SQL injection that worked
  Expected on attack-demo.pcap and clean-traffic.pcap: no alerts

IDEAS: WHAT ELSE THIS MODULE COULD DO
  - Cross-site scripting (XSS): <script>, onerror=, javascript: in the path or body.
  - Path traversal: ../../etc/passwd or ..\\windows - trying to read files off the server.
  - Command injection: ;whoami  |cat  $(  in a form field.
  - Hacking tools announce themselves: User-Agent containing sqlmap, nikto, gobuster,
    dirbuster, hydra, curl, python-requests (look in x["headers"]).
  - Sensitive files that DID download (status 200): .env, .git/, backup.zip, .sql, .bak.
  - After a break-in: which pages did the attacker open next? List them in time order
    (x["time"]) - that is the story an investigator wants.
  - Uploads: a POST that sends a .php file = someone installing a "web shell".
"""
from ready_made.http_tools import http_exchanges


def detect(packets):
    alerts = []

    # TODO 1: probing - for each exchange that got 403/404, add x["path"] to a set per (client, server).

    # TODO 2: SQL injection - collect suspicious exchanges per (client, server), then build alerts.

    return alerts
