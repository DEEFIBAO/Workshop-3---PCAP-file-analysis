"""D2 - Brute force detector.

Many login attempts against one login service.

THE RULE
  1) Login services:
     Only look at packets where p["flags"] == "S" and p["dport"] is one of
     21 (FTP), 22 (SSH), 23 (Telnet) or 3389 (Remote Desktop).
     Count them for each (src, dst, dport). 10 or more -> one "high" alert.
  2) Website logins:
     Use the ready-made helper:  from ready_made.http_tools import http_exchanges
     Each x in http_exchanges(packets) is one website request + the server's answer.
     A failed login is: x["method"] == "POST", "password=" in x["body"],
     and the server said no: x["status"] is 401 or 403.
     5 or more failed logins from one x["client"] to one x["path"] -> one "high" alert.

HINT
  A dict of counters:  counts[(src, dst, dport)] = counts.get((src, dst, dport), 0) + 1

BONUS
  Only count attempts that happen within 60 seconds of each other (use p["time"]).

EACH ALERT LOOKS LIKE THIS (keep these exact keys):
  {"detector": "brute_force", "severity": "high", "title": "Short name",
   "src": "1.2.3.4", "dst": "5.6.7.8", "detail": "One line explaining why"}

TEST IT ON ITS OWN:  python check.py bruteforce
  Expected on attack-demo.pcap:      1 alert: 10.0.0.66 -> 192.168.1.30 port 22 (61 attempts)
  Expected on compsoc-incident.pcap: 1 alert: 12 failed logins to /admin/login.php
  Expected on clean-traffic.pcap:    no alerts

IDEAS: WHAT ELSE THIS MODULE COULD DO
  - More services: 445 (Windows file sharing), 3306 (MySQL), 5900 (VNC), 110/143 (email).
  - FTP tells you when a password is wrong: the server sends b"530 " back.
    Count those instead of connections - that is proof, not a guess.
  - Websites that answer 200 with "Invalid password" on the page instead of 401:
    look for words like "invalid" or "incorrect" in x["response"].
  - Password spraying: ONE password tried against MANY usernames (read username= in x["body"]).
  - Did they get in? A failed streak followed by a success (200 / 302 redirect) from the
    same client is the most important thing to report. Make that alert stand out.
  - Many attackers, one target: lots of different src all hitting the same login.
  - Never put the guessed passwords in the alert - say how many, not what they were.
"""
from ready_made.http_tools import http_exchanges

LOGIN_PORTS = {21: "FTP", 22: "SSH", 23: "Telnet", 3389: "Remote Desktop"}


def detect(packets):
    alerts = []

    # TODO 1: login services - loop over packets, count SYNs per (src, dst, dport), then decide.

    # TODO 2: website logins - loop over http_exchanges(packets), count failures per (client, server, path).

    return alerts
