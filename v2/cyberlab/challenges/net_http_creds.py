"""net-http-creds: recover a password sent in cleartext over HTTP."""

from __future__ import annotations

import random
import shlex
from typing import List, Tuple

from cyberlab import pcap
from cyberlab.challenges import Challenge, register
from cyberlab.workspace import Workspace

CLIENT = "10.0.0.24"
SERVER = "10.0.0.8"


class NetHttpCreds(Challenge):
    def _password(self, ws: Workspace) -> str:
        return "N0rth-" + ws.derive("net-http-creds:password", 8)

    def setup(self, ws: Workspace) -> str:
        rng = random.Random(ws.derive("net-http-creds:seed"))
        pw = self._password(ws)
        pkts = []
        t = 0.0
        # Background browsing: DNS lookups and plain GETs.
        for host in ["news.example.com", "cdn.example.net", "intranet.local"]:
            pkts.append(pcap.udp_dns(t, CLIENT, "10.0.0.1", rng.randint(40000, 60000), host))
            t += rng.uniform(0.1, 0.5)
            pkts.append(pcap.tcp_data(t, CLIENT, SERVER, rng.randint(40000, 60000), 80,
                                      f"GET / HTTP/1.1\r\nHost: {host}\r\n\r\n"))
            t += rng.uniform(0.1, 0.5)
        # The login POST, over HTTP, with the password in the clear.
        pkts.append(pcap.tcp_data(t, CLIENT, SERVER, rng.randint(40000, 60000), 80,
                                   "POST /login HTTP/1.1\r\nHost: intranet.local\r\n"
                                   "Content-Type: application/x-www-form-urlencoded\r\n\r\n"
                                   f"username=alice&password={pw}"))
        path = ws.path("net-http-creds", "capture.pcap")
        pcap.write_pcap(str(path), pkts)
        return (f"Capture: {path}\n"
                f"Open it:  wireshark {path}   (or  tshark -r {path} -Y http)\n"
                "Find the password alice sent, then submit it.")

    def check(self, ws: Workspace, answer: str) -> bool:
        return answer.strip() == self._password(ws)

    def snippets(self, ws: Workspace) -> List[Tuple[str, str]]:
        capture = shlex.quote(str(ws.home / "net-http-creds" / "capture.pcap"))
        return [
            ("Open the capture in Wireshark",
             f"wireshark {capture}"),
            ("Show the POST packet's hex and ASCII bytes with tshark",
             f"tshark -r {capture} -Y 'http.request.method==POST' -x"),
            ("Find readable login data in the capture file",
             f"strings {capture} | grep -E 'POST /login|username=alice'"),
        ]


register(NetHttpCreds(
    id="net-http-creds",
    title="Password in cleartext HTTP",
    track="network",
    difficulty="easy",
    goal=("A packet capture caught alice logging in to the intranet over plain HTTP. "
          "Recover the password she sent and submit it."),
    hints=[
        "Open the capture and filter to HTTP. One request is a login (POST /login).",
        "In Wireshark, right-click that packet and 'Follow > HTTP Stream'; the form body is in plain text.",
        "With tshark:  tshark -r capture.pcap -Y 'http.request.method==POST' -T fields -e http.file_data",
    ],
    tools=["Wireshark", "tshark"],
    learned=("You recovered a password because HTTP sent the login form as readable "
             "text. A packet capture records those bytes exactly; anyone able to observe "
             "the network path could read the credentials."),
    real_world=("Passwords and session tokens sent over unencrypted Wi-Fi or shared "
                "networks can be captured without breaking into the server. HTTPS protects "
                "the contents in transit, but a capture can still reveal metadata such as "
                "destination addresses and timing."),
    defend=[
        "Use HTTPS for every page and form, and redirect HTTP to HTTPS.",
        "Enable HSTS so browsers remember to use HTTPS for the site.",
        "Never send passwords, tokens or other secrets in URLs or unencrypted protocols.",
        "Treat packet captures as sensitive: restrict access and delete them when no longer needed.",
    ],
    ap_unit="Unit 3",
    ap_topic="3.1 Network Vulnerabilities and Attacks",
    ap_skill=["Analyze Risk", "Detect Attacks"],
))
