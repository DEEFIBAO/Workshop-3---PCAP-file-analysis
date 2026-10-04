"""D2 - Brute force detector.

Many login attempts against one login service.

THE RULE
  Only look at packets where p["flags"] == "S" and p["dport"] is one of
  21 (FTP), 22 (SSH), 23 (Telnet) or 3389 (Remote Desktop).
  Count them for each (src, dst, dport). 10 or more -> one "high" alert.

HINT
  A dict of counters:  counts[(src, dst, dport)] = counts.get((src, dst, dport), 0) + 1

BONUS
  Only count attempts that happen within 60 seconds of each other (use p["time"]).

EACH ALERT LOOKS LIKE THIS (keep these exact keys):
  {"detector": "brute_force", "severity": "high", "title": "Short name",
   "src": "1.2.3.4", "dst": "5.6.7.8", "detail": "One line explaining why"}

TEST IT ON ITS OWN:  python check.py bruteforce
  Expected on attack-demo.pcap:  1 alert: 10.0.0.66 -> 192.168.1.30 port 22 (61 attempts)
  Expected on clean-traffic.pcap: no alerts
"""


def detect(packets):
    alerts = []

    # TODO: your code here. Loop over packets, take notes, then decide.

    return alerts

