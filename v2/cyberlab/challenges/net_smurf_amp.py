"""net-smurf-amp: count the reflectors amplifying a smurf attack."""

from __future__ import annotations

import random
import shlex
from typing import List, Tuple

from cyberlab import pcap, smurf
from cyberlab.challenges import Challenge, register
from cyberlab.workspace import Workspace


class NetSmurfAmp(Challenge):
    def _reflectors(self, ws: Workspace):
        rng = random.Random(ws.derive("net-smurf-amp:seed"))
        victim = f"192.0.2.{int(ws.derive('net-smurf-amp:ip', 4), 16) % 240 + 11}"
        reflectors = smurf.reflector_ips(rng, count=rng.randint(8, 16))
        return rng, victim, reflectors

    def setup(self, ws: Workspace) -> str:
        rng, victim, reflectors = self._reflectors(ws)
        path = ws.path("net-smurf-amp", "capture.pcap")
        pcap.write_pcap(str(path), smurf.build(rng, victim, reflectors, requests=3))
        return (f"Capture: {path}\n"
                f"Open it:  wireshark {path}   (or  tshark -r {path} -Y icmp)\n"
                "Each forged request made every reflector answer the victim. Submit how "
                "many distinct reflectors (reply sources) hit the victim.")

    def check(self, ws: Workspace, answer: str) -> bool:
        _, _, reflectors = self._reflectors(ws)
        try:
            return int(answer.strip()) == len(reflectors)
        except ValueError:
            return False

    def snippets(self, ws: Workspace) -> List[Tuple[str, str]]:
        capture = shlex.quote(str(ws.home / "net-smurf-amp" / "capture.pcap"))
        return [
            ("Open the capture in Wireshark", f"wireshark {capture}"),
            ("Find the victim: the top destination of the echo replies",
             f"tshark -r {capture} -Y 'icmp.type==0' -T fields -e ip.dst "
             "| sort | uniq -c | sort -rn | head -1"),
            ("Count the distinct reflectors (unique reply sources), not total replies",
             f"tshark -r {capture} -Y 'icmp.type==0' -T fields -e ip.src | sort -u | wc -l"),
        ]


register(NetSmurfAmp(
    id="net-smurf-amp",
    title="Measure the smurf amplification",
    track="network",
    difficulty="hard",
    goal=("The real power of a smurf attack is amplification: one forged request draws a "
          "reply from every reflector. Count the distinct reflectors (the distinct source "
          "addresses of the echo replies hitting the victim) and submit that number."),
    hints=[
        "The victim is the one address nearly every echo reply targets. Look at the "
        "distinct source addresses of the replies going to it.",
        "Count unique reply sources, not total replies: each reflector answers every "
        "request, so replies = reflectors x requests.",
        "tshark -r capture.pcap -Y 'icmp.type==0' -T fields -e ip.src | sort -u | wc -l . "
        "Note: this many reflectors does NOT mean this many attackers — one attacker "
        "forged every request.",
    ],
    tools=["Wireshark", "tshark"],
    learned=("You measured the amplification of a smurf attack by counting distinct "
             "reflectors. Each forged request made every reflector answer the victim, so "
             "replies equal reflectors times requests — a few packets become many."),
    real_world=("Amplification is what makes reflection attacks dangerous: a small amount "
                "of attacker traffic produces a large flood at the victim. The number of "
                "reflectors is not the number of attackers; counting reply sources measures "
                "amplification, not attribution."),
    defend=[
        "Disable directed broadcasts and apply anti-spoofing so the amplifier cannot be used.",
        "Harden or patch services known to amplify (ICMP here; DNS, NTP, memcached elsewhere).",
        "Use upstream DDoS mitigation and traffic baselining to absorb and spot amplified floods.",
    ],
    ap_unit="Unit 3",
    ap_topic="3.1 Network Vulnerabilities and Attacks; 3.5 Detecting Network Attacks",
    ap_skill=["Analyze Risk", "Detect Attacks"],
))
