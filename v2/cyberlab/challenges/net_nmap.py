"""net-nmap: find the services a host is really running.

setup() starts the netscan target (127.0.0.1 only): a public website on the
bottom port of a 100-port window, plus an old FTP server and a maintenance
console on two other ports in that window. Which two is different for each
student, so the only way to find them is to scan.

    nmap -sV -p <base>-<base+99> 127.0.0.1

The flag is on the maintenance console's page.
"""

from __future__ import annotations

from typing import List, Tuple

from cyberlab import targets
from cyberlab.challenges import Challenge, register
from cyberlab.netscan import WINDOW
from cyberlab.workspace import Workspace


class NetNmap(Challenge):
    def setup(self, ws: Workspace) -> str:
        base = targets.start(ws, "netscan")
        return (
            f"Target host: 127.0.0.1, ports {base}-{base + WINDOW - 1}\n"
            f"The public website is on port {base}: http://127.0.0.1:{base}/\n"
            "Two more services are listening somewhere in that range. Find them, "
            "work out what they are, and get the flag from the one that shouldn't be there:\n"
            f"  nmap -sV -p {base}-{base + WINDOW - 1} 127.0.0.1"
        )

    def snippets(self, ws: Workspace) -> List[Tuple[str, str]]:
        base = targets.port_of(ws, "netscan")
        window = f"{base}-{base + WINDOW - 1}"
        return [
            ("Which ports are open in a range",
             f"nmap -p {window} 127.0.0.1"),
            ("-sV talks to each open port to identify the software and version",
             f"nmap -sV -p {window} 127.0.0.1"),
            ("Read a banner yourself: most services introduce themselves",
             "nc 127.0.0.1 <port>"),
            ("See what a web service on an odd port is serving",
             "curl -si http://127.0.0.1:<port>/"),
            ("No nmap? bash can try every port itself",
             f"for p in $(seq {base} {base + WINDOW - 1}); do\n"
             "  (exec 3<>/dev/tcp/127.0.0.1/$p) 2>/dev/null && echo \"open: $p\"\n"
             "done"),
            ("The defender's view of the same question, on your own machine: what am I "
             "listening on?",
             "ss -tlnp"),
        ]


register(NetNmap(
    id="net-nmap",
    title="Find the forgotten services with nmap",
    track="network",
    difficulty="medium",
    goal=("A server is supposed to run one website. It's also running two services "
          "nobody remembers, on ports nobody wrote down. Scan the port range, identify "
          "what's listening, and submit the flag shown by the service that shouldn't be there."),
    hints=[
        "A port is open if something answers on it. nmap asks every port in a range: "
        "nmap -p <first>-<last> 127.0.0.1   (the range is in the start output).",
        "Add -sV and nmap also identifies each service. You should see three open ports: "
        "the website, an FTP server, and a second HTTP service.",
        "Open the second HTTP service: curl http://127.0.0.1:<its port>/   The flag is on "
        "that page.",
    ],
    tools=["nmap", "curl", "nc"],
    learned=("You asked a hundred ports whether anything was listening, and found two "
             "services the owner had forgotten: an FTP server whose banner gives away its "
             "exact version, and a maintenance console with no login. Running it on an odd "
             "port didn't hide it for longer than the scan took."),
    real_world=("Port scanning is the first step of an attack and of an audit, because you "
                "can't attack or defend a service you don't know is there. The whole internet "
                "is scanned continuously (that's what Shodan is), so a forgotten database, "
                "admin console or test server is found within hours of going up. The version "
                "string from -sV is then looked up for known vulnerabilities."),
    defend=[
        "Know what you're running: ss -tlnp lists every listening port and the program behind it.",
        "Turn off what you don't need, and bind internal tools to 127.0.0.1, not every interface.",
        "Put a firewall in front so only the ports you mean to offer are reachable.",
        "Anything that must be reachable needs a login. An unusual port isn't one.",
        "Scan your own machines regularly. The surprises are the point.",
    ],
))
