"""D3 - Suspicious DNS detector.

Lookups for names that don't exist, a sign of some malware.

THE RULE
  A DNS reply with p["dns_rcode"] == 3 means "no such name".
  The computer that asked is the reply's p["dst"].
  Collect the DIFFERENT failed names per asking computer.
  20 or more -> one "medium" alert for that computer.

BONUS
  Queries (p["dns_rcode"] is None) longer than 60 characters can mean data is
  being smuggled out inside DNS. Add a "medium" alert, one per domain (not per packet!).

EACH ALERT LOOKS LIKE THIS (keep these exact keys):
  {"detector": "dns", "severity": "high", "title": "Short name",
   "src": "1.2.3.4", "dst": "5.6.7.8", "detail": "One line explaining why"}

TEST IT ON ITS OWN:  python check.py dns
  Expected on attack-demo.pcap:  1 alert for 192.168.1.11 (35 failed names). Bonus: 1 alert for tunnel-cdn.net
  Expected on clean-traffic.pcap: no alerts
"""


def detect(packets):
    alerts = []

    # TODO: your code here. Loop over packets, take notes, then decide.

    return alerts

