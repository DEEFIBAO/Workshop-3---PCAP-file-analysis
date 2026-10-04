"""D4 - Cleartext logins detector.

Passwords sent where anyone can read them.

THE RULE
  Look inside p["payload"] (it's bytes, so compare with b"..." strings):
    - starts with b"PASS " and dport is 21 or 110  -> FTP / POP3 password
    - contains b"Authorization: Basic"              -> website login (HTTP Basic)
    - contains b"password="                         -> website login form
  Each one -> a "high" alert. One alert per (src, dst, dport) is enough.

IMPORTANT
  Never copy the password itself into the alert.

EACH ALERT LOOKS LIKE THIS (keep these exact keys):
  {"detector": "cleartext", "severity": "high", "title": "Short name",
   "src": "1.2.3.4", "dst": "5.6.7.8", "detail": "One line explaining why"}

TEST IT ON ITS OWN:  python check.py cleartext
  Expected on attack-demo.pcap:  3 alerts: FTP (port 21), HTTP Basic and a login form (port 80)
  Expected on clean-traffic.pcap: no alerts
"""


def detect(packets):
    alerts = []

    # TODO: your code here. Loop over packets, take notes, then decide.

    return alerts

