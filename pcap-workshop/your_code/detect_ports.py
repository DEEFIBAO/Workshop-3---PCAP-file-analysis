"""D5 - Malware ports detector.

Traffic to ports that hacking tools use by default.

THE RULE
  BAD_PORTS = {4444: "Metasploit", 1337: "backdoor", 31337: "Back Orifice",
               6667: "IRC botnet", 12345: "NetBus"}
  If p["dport"] is in BAD_PORTS AND the packet carries data (len(p["payload"]) > 0),
  -> one "medium" alert per (src, dst, dport).

THINK ABOUT
  Why ignore packets with no data? (Hint: what does a port scanner send?)

EACH ALERT LOOKS LIKE THIS (keep these exact keys):
  {"detector": "malware_ports", "severity": "high", "title": "Short name",
   "src": "1.2.3.4", "dst": "5.6.7.8", "detail": "One line explaining why"}

TEST IT ON ITS OWN:  python check.py ports
  Expected on attack-demo.pcap:  1 alert: 192.168.1.12 -> 203.0.113.66 port 4444
  Expected on clean-traffic.pcap: no alerts
"""


def detect(packets):
    alerts = []

    # TODO: your code here. Loop over packets, take notes, then decide.

    return alerts

