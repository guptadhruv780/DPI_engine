from __future__ import annotations

import random
import time

from scapy.all import DNS, DNSQR, IP, TCP, UDP, Raw, wrpcap  # type: ignore

"""
Sample PCAP Generator for DPI Engine Testing
This script generates a realistic-looking PCAP file with various types of traffic
including HTTP, HTTPS (TLS SNI), and generic UDP packets to test the DPI engine's
classification capabilities.
"""


def tls_client_hello_with_sni(hostname: str) -> bytes:
    """Creates a raw TLS ClientHello packet with a specific SNI hostname."""
    host = hostname.encode("utf-8")
    server_name = b"\x00" + len(host).to_bytes(2, "big") + host
    sni_list = len(server_name).to_bytes(2, "big") + server_name
    sni_ext = b"\x00\x00" + len(sni_list).to_bytes(2, "big") + sni_list
    extensions = sni_ext
    body = (
        b"\x03\x03"
        + b"\x00" * 32
        + b"\x00"
        + b"\x00\x02\x13\x01"
        + b"\x01\x00"
        + len(extensions).to_bytes(2, "big")
        + extensions
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    record = b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake
    return record


def main() -> None:
    packets = []
    now = int(time.time())
    src_pool = [f"192.168.1.{i}" for i in range(10, 30)]
    dst_pool = [f"93.184.216.{i}" for i in range(10, 80)]

    # 20 HTTP packets
    for i in range(20):
        src = random.choice(src_pool)
        dst = random.choice(dst_pool)
        host = random.choice(["example.com", "news.example.com", "api.example.com"])
        payload = f"GET /{i} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: test\r\n\r\n".encode()
        pkt = IP(src=src, dst=dst) / TCP(sport=20000 + i, dport=80, flags="PA") / Raw(load=payload)
        pkt.time = now + i * 0.001
        packets.append(pkt)

    # 20 HTTPS packets with SNI
    domains = ["www.youtube.com", "www.facebook.com", "github.com"]
    for i in range(20):
        src = random.choice(src_pool)
        dst = random.choice(dst_pool)
        sni = random.choice(domains)
        payload = tls_client_hello_with_sni(sni)
        pkt = IP(src=src, dst=dst) / TCP(sport=30000 + i, dport=443, flags="PA") / Raw(load=payload)
        pkt.time = now + 1 + i * 0.001
        packets.append(pkt)

    # 5 DNS packets
    for i in range(5):
        src = random.choice(src_pool)
        dst = "8.8.8.8"
        query = random.choice(["google.com", "youtube.com", "github.com"])
        pkt = IP(src=src, dst=dst) / UDP(sport=40000 + i, dport=53) / DNS(rd=1, qd=DNSQR(qname=query))
        pkt.time = now + 2 + i * 0.001
        packets.append(pkt)

    # 5 generic UDP packets
    for i in range(5):
        src = random.choice(src_pool)
        dst = random.choice(dst_pool)
        pkt = IP(src=src, dst=dst) / UDP(sport=50000 + i, dport=9000) / Raw(load=b"udp-data")
        pkt.time = now + 3 + i * 0.001
        packets.append(pkt)

    # 100 packets from same IP in one second to trigger DDOS alert
    attacker = "10.0.0.50"
    for i in range(100):
        dst = random.choice(dst_pool)
        payload = tls_client_hello_with_sni("www.youtube.com")
        pkt = IP(src=attacker, dst=dst) / TCP(sport=60000 + i, dport=443, flags="PA") / Raw(load=payload)
        pkt.time = now + 5 + (i * 0.0001)
        packets.append(pkt)

    wrpcap("sample.pcap", packets)
    print(f"Generated sample.pcap with {len(packets)} packets")


if __name__ == "__main__":
    main()
