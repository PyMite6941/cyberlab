"""Build a synthetic smurf-amplification capture for the ICMP challenges.

A smurf attack: the attacker sends ICMP echo requests with the source address
forged to the victim's, to a network's broadcast address. Every host on that
network ("reflectors") answers the echo — and the replies all go to the
victim. The capture shows the forged requests to the broadcast plus a reply
from each reflector to the victim, so the victim is drowned in echoes it never
asked for. Uses documentation IP ranges (RFC 5737), as the class worksheet does.
"""

from __future__ import annotations

import random
from typing import List

from cyberlab import pcap

BROADCAST = "198.51.100.255"      # the reflector network's broadcast address
REFLECTOR_NET = "198.51.100.{}"   # reflectors live here


def reflector_ips(rng: random.Random, count: int) -> List[str]:
    return [REFLECTOR_NET.format(n) for n in sorted(rng.sample(range(10, 250), count))]


def build(rng: random.Random, victim: str, reflectors: List[str],
          requests: int = 3) -> List[pcap.Packet]:
    """A smurf capture: forged requests to the broadcast, a reply per reflector."""
    pkts: List[pcap.Packet] = []
    t = 0.0
    # A little normal ping traffic between other hosts, so the victim isn't the
    # only ICMP address in the capture.
    for _ in range(4):
        a, b = f"192.0.2.{rng.randint(10, 40)}", f"192.0.2.{rng.randint(41, 80)}"
        ident = rng.randint(1, 0xFFFF)
        pkts.append(pcap.icmp_echo(t, a, b, pcap.ICMP_ECHO_REQUEST, ident, 1)); t += 0.5
        pkts.append(pcap.icmp_echo(t, b, a, pcap.ICMP_ECHO_REPLY, ident, 1)); t += 0.5
    # The attack: each forged request to the broadcast draws one reply per
    # reflector, all aimed at the victim, sharing the request's id/seq.
    ident = rng.randint(1, 0xFFFF)
    for seq in range(1, requests + 1):
        pkts.append(pcap.icmp_echo(t, victim, BROADCAST, pcap.ICMP_ECHO_REQUEST, ident, seq))
        t += 0.01
        for ip in reflectors:
            pkts.append(pcap.icmp_echo(t, ip, victim, pcap.ICMP_ECHO_REPLY, ident, seq))
            t += 0.002
    pkts.sort(key=lambda p: p.ts)
    return pkts
