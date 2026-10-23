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

IDEAS: WHAT ELSE THIS MODULE COULD DO
  - More known ports: 9001/9030 (Tor), 5555 (Android debug), 8291 (router admin),
    2323 (IoT botnets), 1080 (proxies).
  - Beaconing: malware "phones home" at a steady rhythm, e.g. every 30 seconds exactly.
    For each (src, dst) look at the gaps between p["time"] values - nearly equal gaps
    for a long time = beacon. Humans are never that regular.
  - Big uploads: one inside computer sending far more bytes OUT than it receives
    (add up len(p["payload"]) each way) - data being stolen.
  - Odd hours: lots of traffic at 3am (convert p["time"] with datetime.fromtimestamp).
  - Shell commands in the data: b"whoami", b"cmd.exe", b"/bin/sh" in the payload means
    someone is remotely controlling the machine. Show the command in the detail.
  - Severity: "high" if the inside computer started the conversation (it's infected).
"""


def detect(packets):
    alerts = []

    # TODO: your code here. Loop over packets, take notes, then decide.

    return alerts
