"""Craft small, valid capture files for the network challenges.

Everything is built from the standard library. The packets are real enough
that Wireshark, tshark and tcpdump dissect them as Ethernet / IPv4 / TCP /
UDP / DNS / HTTP, with correct IP, TCP and UDP checksums, so students analyse
them with the actual tools.

Link type is 1 (Ethernet); the pcap uses the classic microsecond format.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import List, Optional

ETH_P_IP = 0x0800
PROTO_ICMP = 1
PROTO_TCP = 6
PROTO_UDP = 17

# TCP flag bits
FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10


def _checksum(data: bytes) -> int:
    """The 16-bit one's-complement Internet checksum (RFC 1071)."""
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return (~total) & 0xFFFF


def mac_bytes(mac: str) -> bytes:
    return bytes(int(b, 16) for b in mac.split(":"))


def ip_bytes(ip: str) -> bytes:
    return bytes(int(b) for b in ip.split("."))


def _ipv4(src_ip: str, dst_ip: str, proto: int, payload: bytes, ident: int, ttl: int = 64) -> bytes:
    total_len = 20 + len(payload)
    header = struct.pack("!BBHHHBBH4s4s",
                         0x45, 0x00, total_len, ident & 0xFFFF, 0x4000,  # DF set
                         ttl, proto, 0, ip_bytes(src_ip), ip_bytes(dst_ip))
    checksum = _checksum(header)
    header = header[:10] + struct.pack("!H", checksum) + header[12:]
    return header + payload


def _l4_checksum(src_ip: str, dst_ip: str, proto: int, segment: bytes) -> int:
    pseudo = ip_bytes(src_ip) + ip_bytes(dst_ip) + struct.pack("!BBH", 0, proto, len(segment))
    return _checksum(pseudo + segment)


def _udp(src_ip, dst_ip, src_port, dst_port, payload) -> bytes:
    length = 8 + len(payload)
    seg = struct.pack("!HHHH", src_port, dst_port, length, 0) + payload
    csum = _l4_checksum(src_ip, dst_ip, PROTO_UDP, seg) or 0xFFFF  # 0 means "no checksum"; avoid it
    return seg[:6] + struct.pack("!H", csum) + seg[8:]


def _tcp(src_ip, dst_ip, src_port, dst_port, flags, seq, ack, payload) -> bytes:
    offset = (5 << 4)  # 20-byte header, no options
    seg = struct.pack("!HHIIBBHHH", src_port, dst_port, seq, ack, offset, flags, 64240, 0, 0) + payload
    csum = _l4_checksum(src_ip, dst_ip, PROTO_TCP, seg)
    return seg[:16] + struct.pack("!H", csum) + seg[18:]


ICMP_ECHO_REPLY = 0
ICMP_ECHO_REQUEST = 8


def _icmp_echo(icmp_type: int, ident: int, seq: int, payload: bytes) -> bytes:
    body = struct.pack("!BBHHH", icmp_type, 0, 0, ident & 0xFFFF, seq & 0xFFFF) + payload
    csum = _checksum(body)
    return body[:2] + struct.pack("!H", csum) + body[4:]


def dns_query(name: str, qtype: int = 1, txid: int = 0x1234) -> bytes:
    """A standard recursive DNS query message (qtype 1 = A, 16 = TXT)."""
    header = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)  # RD set, 1 question
    qname = b"".join(struct.pack("!B", len(label)) + label.encode()
                     for label in name.split(".")) + b"\x00"
    return header + qname + struct.pack("!HH", qtype, 1)  # qtype, IN class


@dataclass
class Packet:
    ts: float          # seconds since the capture start
    src_mac: str
    dst_mac: str
    src_ip: str
    dst_ip: str
    proto: int         # PROTO_TCP or PROTO_UDP
    src_port: int
    dst_port: int
    payload: bytes = b""
    flags: int = 0     # TCP only
    seq: int = 0
    ack: int = 0
    ident: int = 0

    icmp_type: int = 0  # ICMP only: 8 request, 0 reply
    icmp_id: int = 0
    icmp_seq: int = 0

    def frame(self) -> bytes:
        if self.proto == PROTO_ICMP:
            l4 = _icmp_echo(self.icmp_type, self.icmp_id, self.icmp_seq,
                            self.payload or b"cyberlab-echo-payload")
        elif self.proto == PROTO_UDP:
            l4 = _udp(self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.payload)
        else:
            l4 = _tcp(self.src_ip, self.dst_ip, self.src_port, self.dst_port,
                      self.flags, self.seq, self.ack, self.payload)
        ip = _ipv4(self.src_ip, self.dst_ip, self.proto, l4, self.ident)
        eth = mac_bytes(self.dst_mac) + mac_bytes(self.src_mac) + struct.pack("!H", ETH_P_IP)
        return eth + ip


def udp_dns(ts, src_ip, dst_ip, src_port, name, qtype=1, txid=0x1234,
            src_mac="02:00:00:00:00:01", dst_mac="02:00:00:00:00:02") -> Packet:
    return Packet(ts, src_mac, dst_mac, src_ip, dst_ip, PROTO_UDP, src_port, 53,
                  payload=dns_query(name, qtype, txid))


def tcp_syn(ts, src_ip, dst_ip, src_port, dst_port,
            src_mac="02:00:00:00:00:01", dst_mac="02:00:00:00:00:02") -> Packet:
    return Packet(ts, src_mac, dst_mac, src_ip, dst_ip, PROTO_TCP, src_port, dst_port,
                  flags=SYN, seq=0)


def tcp_data(ts, src_ip, dst_ip, src_port, dst_port, text,
             src_mac="02:00:00:00:00:01", dst_mac="02:00:00:00:00:02") -> Packet:
    body = text.encode() if isinstance(text, str) else text
    return Packet(ts, src_mac, dst_mac, src_ip, dst_ip, PROTO_TCP, src_port, dst_port,
                  flags=PSH | ACK, seq=1, ack=1, payload=body)


def icmp_echo(ts, src_ip, dst_ip, icmp_type, ident, seq,
              src_mac="02:00:00:00:00:01", dst_mac="02:00:00:00:00:02") -> Packet:
    return Packet(ts, src_mac, dst_mac, src_ip, dst_ip, PROTO_ICMP, 0, 0,
                  icmp_type=icmp_type, icmp_id=ident, icmp_seq=seq)


def write_pcap(path, packets: List[Packet], base_epoch: int = 1_760_000_000) -> None:
    """Write packets to a classic-format pcap file (link type Ethernet)."""
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for p in packets:
            frame = p.frame()
            sec = base_epoch + int(p.ts)
            usec = int(round((p.ts - int(p.ts)) * 1_000_000))
            f.write(struct.pack("<IIII", sec, usec, len(frame), len(frame)))
            f.write(frame)
