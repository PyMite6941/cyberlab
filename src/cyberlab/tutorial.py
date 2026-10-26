"""Baked-in interactive tutorial for cyberlab.

Runs entirely offline. Walks a first-time user through installing, launching,
and using the BurpSuite and Wireshark simulators step by step.
"""

from __future__ import annotations

import sys
from typing import List


# Each step: (title, body, optional "try this" command)
STEPS: List[tuple] = [
    (
        "Welcome to cyberlab",
        "cyberlab is an offline-first cybersecurity practice CLI. It simulates "
        "a BurpSuite-style intercepting proxy and a Wireshark-style packet "
        "capture so you can learn web-app testing and network analysis without "
        "touching a real network.\n\n"
        "Everything is simulated locally - HTTP requests, responses, Ethernet "
        "frames, IP/TCP/UDP/DNS packets - nothing goes over the wire.",
    ),
    (
        "Step 1 - Install (run once, while online)",
        "Open a terminal in this folder and run:\n\n"
        "    python install.py\n\n"
        "This creates a virtual environment (``.venv``), installs the required "
        "packages (``click``), installs the ``cyberlab`` command, and verifies "
        "it works by running ``cyberlab labs``.\n\n"
        "To prepare for offline use (no network later), run instead:\n\n"
        "    python install.py --cache-wheels\n\n"
        "That downloads dependency wheels into the ``wheels/`` folder so you can "
        "reinstall later with ``python install.py --offline``.",
    ),
    (
        "Step 2 - Launch the CLI",
        "After install, launch cyberlab any of these ways:\n\n"
        "    cyberlab --help          # Windows (if entry point is on PATH)\n    .venv\\Scripts\\python -m cyberlab --help  # always works\n    run.bat --help               # Windows wrapper\n    ./run.sh --help              # macOS / Linux wrapper\n\n"
        "On macOS/Linux, make the wrappers executable once:\n\n"
        "    chmod +x run.sh install.sh\n\n"
        "Pick one launch method and stick with it. The rest of this tutorial "
        "uses ``cyberlab`` for brevity.",
    ),
    (
        "Step 3 - See the available labs",
        "Run:\n\n"
        "    cyberlab labs\n\n"
        "You should see two labs:\n\n"
        "    burp-01      burp           Intercepting proxy basics\n"
        "    wireshark-01 wireshark      Packet capture analysis\n\n"
        "Each lab has tags like [web, proxy, burp, offline] to show what it teaches.",
    ),
    (
        "Step 4 - Launch the BurpSuite simulator",
        "Run:\n\n"
        "    cyberlab burp\n\n"
        "This opens an interactive proxy shell (prompt ``burp>``). Available "
        "commands:\n\n"
        "    targets          - list the simulated target endpoints\n"
        "    intercept GET /login   - capture a request for inspection\n"
        "    modify header X-Test 1 - change a request header\n"
        "    modify body username=admin - change the request body\n"
        "    show request / show response - view captured traffic\n"
        "    forward          - send the request to the mock target\n"
        "    quit / exit      - leave the simulator\n\n"
        "Example: intercept a login, modify the username, forward it, then read "
        "the simulated server response.",
    ),
    (
        "Step 5 - Launch the Wireshark simulator",
        "Run:\n\n"
        "    cyberlab wireshark\n\n"
        "This generates a synthetic capture (Ethernet/IP/TCP/UDP/DNS/HTTP) and "
        "opens an interactive shell (prompt ``wireshark>``). Commands:\n\n"
        "    list               - show all packets in a table\n"
        "    list proto==HTTP   - filter to HTTP packets only\n"
        "    list ip==192.168.1.10 - filter by IP\n"
        "    list port==80      - filter by port\n"
        "    export capture.pcap - save a real pcap you can open in Wireshark\n"
        "    count              - count packets by protocol\n"
        "    follow 1           - follow a simulated TCP stream\n"
        "    quit / exit        - leave the simulator\n\n"
        "The exported ``.pcap`` is a valid packet capture - open it in the real "
        "Wireshark to compare.",
    ),
    (
        "Step 6 - Go fully offline",
        "Once you've run ``python install.py --cache-wheels`` at least once "
        "while online, you can rebuild the entire environment with no network:\n\n"
        "    python install.py --offline\n\n"
        "Then ``cyberlab labs``, ``cyberlab burp``, and ``cyberlab wireshark`` "
        "all work offline forever. The proxy and packet capture are 100% "
        "simulated - no NIC, no internet, no BurpSuite/Wireshark install needed.",
    ),
    (
        "You're ready",
        "Pick a lab and start practicing:\n\n"
        "    cyberlab run burp-01\n    cyberlab run wireshark-01\n\n"
        "Expand as you learn: add new modules under ``src/cyberlab/modules/``, "
        "register new scenarios in ``src/cyberlab/core/lab.py``, and they'll "
        "appear in ``cyberlab labs`` automatically.",
    ),
]


def print_step(index: int) -> None:
    title, body = STEPS[index]
    print()
    print("=" * 60)
    print(title)
    print("=" * 60)
    print(body)


def run_tutorial() -> int:
    print("=== cyberlab interactive tutorial (offline) ===")
    print("Press Enter to continue to the next step, or type 'q' to quit.\n")
    for i in range(len(STEPS)):
        print_step(i)
        if i < len(STEPS) - 1:
            try:
                choice = input("\n[Enter = next, q = quit] ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                print()
                print("Tutorial paused. Resume anytime with: cyberlab tutorial")
                return 0
            if choice == "q":
                print("Tutorial paused. Resume anytime with: cyberlab tutorial")
                return 0
    print()
    print("Tutorial complete. Launch a tool with:  cyberlab burp  |  cyberlab wireshark")
    print("List labs with:  cyberlab labs")
    return 0


if __name__ == "__main__":
    sys.exit(run_tutorial())
