"""D1 - Port scan detector.

One machine knocking on lots of different doors (ports).

THE RULE
  Only look at packets where p["flags"] == "S" (a "can we talk?" knock).
  For each (src, dst) pair, count how many DIFFERENT dport values there are.
  15 or more different ports -> one "high" alert for that pair.

HINT
  A dict of sets is perfect:  ports = {}  ...  ports.setdefault((src, dst), set()).add(dport)
  A set ignores repeats, so len(the_set) is the number of different ports.

EACH ALERT LOOKS LIKE THIS (keep these exact keys):
  {"detector": "port_scan", "severity": "high", "title": "Short name",
   "src": "1.2.3.4", "dst": "5.6.7.8", "detail": "One line explaining why"}

TEST IT ON ITS OWN:  python check.py portscan
  Expected on attack-demo.pcap:  1 alert: 10.0.0.66 -> 192.168.1.30 (300 ports)
  Expected on clean-traffic.pcap: no alerts
"""


def detect(packets):
    alerts = []

    # TODO: your code here. Loop over packets, take notes, then decide.

    return alerts

