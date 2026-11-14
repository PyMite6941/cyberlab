"""net-smurf-victim: find the target of a smurf amplification flood."""

from __future__ import annotations

import random
import shlex
from typing import List, Tuple

from cyberlab import pcap, smurf
from cyberlab.challenges import Challenge, register
from cyberlab.workspace import Workspace


class NetSmurfVictim(Challenge):
    def _victim(self, ws: Workspace) -> str:
        n = int(ws.derive("net-smurf-victim:ip", 4), 16) % 240 + 11
        return f"192.0.2.{n}"

    def setup(self, ws: Workspace) -> str:
        rng = random.Random(ws.derive("net-smurf-victim:seed"))
        victim = self._victim(ws)
        reflectors = smurf.reflector_ips(rng, count=rng.randint(6, 12))
        path = ws.path("net-smurf-victim", "capture.pcap")
        pcap.write_pcap(str(path), smurf.build(rng, victim, reflectors, requests=3))
        return (f"Capture: {path}\n"
                f"Open it:  wireshark {path}   (or  tshark -r {path} -Y icmp)\n"
                "This capture shows a smurf attack. Submit the victim's IP address.")

    def check(self, ws: Workspace, answer: str) -> bool:
        return answer.strip() == self._victim(ws)

    def snippets(self, ws: Workspace) -> List[Tuple[str, str]]:
        capture = shlex.quote(str(ws.home / "net-smurf-victim" / "capture.pcap"))
        return [
            ("Open the capture in Wireshark", f"wireshark {capture}"),
            ("Rank where the echo replies are going; the victim is the top destination",
             f"tshark -r {capture} -Y 'icmp.type==0' -T fields -e ip.dst "
             "| sort | uniq -c | sort -rn | head"),
            ("Show the forged requests: that same address as source, to a broadcast",
             f"tshark -r {capture} -Y 'icmp.type==8' -T fields -e ip.src -e ip.dst"),
        ]


register(NetSmurfVictim(
    id="net-smurf-victim",
    title="Who is the smurf attack aimed at?",
    track="network",
    difficulty="medium",
    goal=("In a smurf attack, echo requests are sent with the victim's address forged as "
          "the source, to a broadcast, so every host replies to the victim. Find the "
          "victim: the address all those echo replies pour into. Submit its IP."),
    hints=[
        "Filter to ICMP echo replies (icmp.type==0). Where are they nearly all going?",
        "One address is the destination of dozens of replies it never asked for. "
        "That same address appears, forged, as the source of the requests to the broadcast.",
        "tshark -r capture.pcap -Y 'icmp.type==0' -T fields -e ip.dst | sort | uniq -c | sort -rn | head",
    ],
    tools=["Wireshark", "tshark"],
    learned=("You traced a smurf attack: echo requests were sent with the victim's address "
             "forged as the source to a broadcast, so every host on that network answered "
             "the victim. The victim is the address all the replies converge on, and the "
             "forged source of the broadcast requests."),
    real_world=("Reflection-and-amplification attacks use innocent third parties to flood a "
                "target, which also hides the real attacker. The reply count shows how many "
                "reflectors answered, not how many attackers there were: one attacker forged "
                "every request."),
    defend=[
        "Disable directed-broadcast forwarding on routers so a broadcast ping is not amplified.",
        "Apply anti-spoofing (BCP 38 ingress filtering) so forged source addresses are dropped.",
        "Rate-limit ICMP and watch for many replies to a host that sent no matching requests.",
    ],
    ap_unit="Unit 3",
    ap_topic="3.1 Network Vulnerabilities and Attacks; 3.5 Detecting Network Attacks",
    ap_skill=["Analyze Risk", "Detect Attacks"],
))
