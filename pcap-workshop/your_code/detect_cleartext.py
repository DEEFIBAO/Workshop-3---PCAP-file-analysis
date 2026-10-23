"""D4 - Cleartext logins detector.

Passwords sent where anyone can read them.

THE RULE
  Look inside p["payload"] (it's bytes, so compare with b"..." strings):
    - starts with b"PASS " and dport is 21 or 110  -> FTP / POP3 password
    - contains b"Authorization: Basic"              -> website login (HTTP Basic)
    - contains b"password="                         -> website login form
  Each one -> a "high" alert. One alert per kind of login per (src, dst, dport) is enough.
  Only look at what a CLIENT sends. A server's reply page can mention "password=" too
  (for example inside an error message) and that is not someone logging in:
      from ready_made.http_tools import is_request    ->  is_request(payload) is True for requests

IMPORTANT
  Never copy the password itself into the alert.

EACH ALERT LOOKS LIKE THIS (keep these exact keys):
  {"detector": "cleartext", "severity": "high", "title": "Short name",
   "src": "1.2.3.4", "dst": "5.6.7.8", "detail": "One line explaining why"}

TEST IT ON ITS OWN:  python check.py cleartext
  Expected on attack-demo.pcap:      3 alerts: FTP (port 21), HTTP Basic and a login form (port 80)
  Expected on compsoc-incident.pcap: 1 alert: the admin login form (port 80)
  Expected on clean-traffic.pcap:    no alerts

IDEAS: WHAT ELSE THIS MODULE COULD DO
  - Email: IMAP sends b"LOGIN user pass" (port 143), SMTP sends b"AUTH LOGIN" / b"AUTH PLAIN" (port 25/587).
  - Telnet (port 23): everything typed, including the password, travels as plain text.
  - Other field names: pass=, pwd=, passwd=, secret=, token=, api_key=.
  - Passwords in the web address itself: GET /login?user=bob&password=... (even worse:
    it ends up in logs and browser history).
  - Session cookies (Cookie: PHPSESSID=...) over plain HTTP can be stolen and reused
    without knowing the password.
  - Show the USERNAME but hide the password, e.g. "admin / ********".
  - Tell the user how to fix it: "use SFTP instead of FTP", "use HTTPS".
"""


def detect(packets):
    alerts = []

    # TODO: your code here. Loop over packets, take notes, then decide.

    return alerts
