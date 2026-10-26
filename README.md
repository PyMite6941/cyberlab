# cyberlab

Offline-first cybersecurity practice CLI. Simulated labs for learning web
application testing (BurpSuite-style intercepting proxy) and packet analysis
(Wireshark-style capture) without needing a network connection.

## Quick start

```powershell
# Windows
.\install.bat
.\run.bat --help

# macOS / Linux
chmod +x install.sh run.sh
./install.sh
./run.sh --help
```

## What's included

- `cyberlab burp` — simulated intercepting proxy. View and modify HTTP
  requests/responses against a mock vulnerable target, entirely offline.
- `cyberlab wireshark` — simulated packet capture. Generate, inspect, filter,
  and export synthetic Ethernet/IP/TCP/UDP/HTTP/DNS packets to pcap.
- `cyberlab labs` — list built-in practice scenarios.
- `cyberlab run <scenario>` — walk through a guided lab.

## Offline use

`install.py` creates a `.venv`, installs dependencies, and (optionally) caches
wheels into `wheels/` so the whole environment can be reinstalled with no
network access:

```powershell
# While still online, populate the offline wheel cache
python install.py --cache-wheels

# Later, fully offline
python install.py --offline
```

All packet and proxy traffic is simulated locally — nothing touches the wire.
