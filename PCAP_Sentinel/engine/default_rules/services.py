"""Provided: small port -> service-name table for readable statistics."""
from __future__ import annotations

SERVICE_NAMES = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP",
    69: "TFTP", 80: "HTTP", 110: "POP3", 111: "RPC", 119: "NNTP", 123: "NTP", 135: "MS-RPC", 137: "NetBIOS",
    138: "NetBIOS", 139: "NetBIOS-SSN", 143: "IMAP", 161: "SNMP", 389: "LDAP", 443: "HTTPS", 445: "SMB",
    465: "SMTPS", 514: "Syslog", 554: "RTSP", 587: "SMTP-submission", 636: "LDAPS", 993: "IMAPS", 995: "POP3S",
    1433: "MS-SQL", 1521: "Oracle", 1723: "PPTP", 1900: "SSDP", 3128: "Squid-proxy", 3306: "MySQL",
    3389: "RDP", 5060: "SIP", 5353: "mDNS", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8000: "HTTP-alt",
    8080: "HTTP-proxy", 8443: "HTTPS-alt", 8888: "HTTP-alt", 9200: "Elasticsearch", 27017: "MongoDB",
}


def service_name(port, protocol=None):
    """Return a service label for a port, or None when it is not in the table."""
    if port is None:
        return None
    return SERVICE_NAMES.get(int(port))
