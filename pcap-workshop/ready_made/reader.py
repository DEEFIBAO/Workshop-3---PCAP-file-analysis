"""READY-MADE: the reader. Nobody needs to change this file.

read_packets(path) opens a .pcap or .pcapng file and returns a list of
Packet dicts, one per packet, in the shape everyone agreed on:

    {"time": 1790758820.0,      # seconds since 1 Jan 1970
     "src": "10.0.0.66",        # who sent it
     "dst": "192.168.1.30",     # who it's for
     "proto": "TCP",            # "TCP", "UDP" or "OTHER"
     "sport": 61000,            # sender's port   (None if not TCP/UDP)
     "dport": 22,               # receiver's port (None if not TCP/UDP)
     "flags": "S",              # TCP flags, e.g. "S", "SA", "PA" ("" if not TCP)
     "payload": b"",            # the message bytes after the TCP/UDP header
     "dns_query": None,         # e.g. "example.com" for DNS packets
     "dns_rcode": None}         # DNS replies only: 0 = OK, 3 = no such name

Try it (from the main folder):  python check.py reader
"""
import sys

from scapy.all import DNS, DNSQR, IP, TCP, UDP, rdpcap
from scapy.layers.inet6 import IPv6


def read_packets(path):
    packets = []
    for pkt in rdpcap(path):
        if IP in pkt:
            ip = pkt[IP]
        elif IPv6 in pkt:
            ip = pkt[IPv6]
        else:
            continue  # not an IP packet (e.g. ARP), skip it

        p = {
            "time": float(pkt.time),
            "src": ip.src,
            "dst": ip.dst,
            "proto": "OTHER",
            "sport": None,
            "dport": None,
            "flags": "",
            "payload": b"",
            "dns_query": None,
            "dns_rcode": None,
        }
        if TCP in pkt:
            p["proto"] = "TCP"
            p["sport"] = pkt[TCP].sport
            p["dport"] = pkt[TCP].dport
            p["flags"] = str(pkt[TCP].flags)
            p["payload"] = bytes(pkt[TCP].payload)
        elif UDP in pkt:
            p["proto"] = "UDP"
            p["sport"] = pkt[UDP].sport
            p["dport"] = pkt[UDP].dport
            p["payload"] = bytes(pkt[UDP].payload)

        if pkt.haslayer(DNSQR):
            p["dns_query"] = pkt[DNSQR].qname.decode(errors="replace").rstrip(".")
            if pkt[DNS].qr == 1:  # qr = 1 means "this is a reply"
                p["dns_rcode"] = pkt[DNS].rcode

        packets.append(p)
    return packets


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "samples/attack-demo.pcap"
    packets = read_packets(path)
    print(f"{len(packets)} packets in {path}\n")
    for p in packets[:5]:
        print(p)
