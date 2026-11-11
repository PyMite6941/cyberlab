"""net-http-creds: recover a password sent in cleartext over HTTP."""

from __future__ import annotations

import random

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
))
