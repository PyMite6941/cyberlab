# cyberterminal

Custom emulated terminal for offline cybersecurity practice. Simulated labs for
learning web application testing (BurpSuite-style intercepting proxy) and packet
analysis (Wireshark-style capture) without needing a network connection.

## Quick start

```powershell
# Windows
.\install.bat
.\run.bat

# macOS / Linux
chmod +x install.sh run.sh
./install.sh
./run.sh
```

## What is cyberterminal?

`cyberterminal` IS the program — there is no separate `cyberlab` command. Running
`cyberterminal` (or `.\run.bat` / `./run.sh`) launches a custom emulated terminal
shell:

```
cyberterminal> help
cyberterminal> tutorials
cyberterminal> tutorial burp-basics
cyberterminal> labs
cyberterminal> run burp-01
cyberterminal> burp
cyberterminal> wireshark
cyberterminal> help web          # opens tutorial search page in browser
cyberterminal> exit
```

## Included tools

- **burp** — simulated intercepting proxy. Inspect and modify HTTP requests/
  responses against a mock vulnerable target, entirely offline.
- **wireshark** — simulated packet capture. Generate, inspect, filter, and
  export synthetic Ethernet/IP/TCP/UDP/HTTP/DNS packets to pcap.
- **tutorials** — 4 baked-in tutorials (burp-basics, burp-sql-injection,
  wireshark-basics, wireshark-dns-analysis) with step-by-step commands.
- **help web** — opens a self-contained HTML tutorial search page (offline).

## Offline use

`install.py` creates a `.venv`, installs dependencies, and (optionally) caches
wheels into `wheels/` so the environment can be reinstalled with no network:

```powershell
# While still online, populate the offline wheel cache
python install.py --cache-wheels

# Later, fully offline
python install.py --offline
```

Install is interactive and asks:
- Install tutorial docs? (y/n)
- Which tools to set up: burp / wireshark / both
- Download tutorials for offline use? (y/n)

Use `--non-interactive` to skip prompts (defaults: yes to everything).

All traffic is simulated locally — nothing touches the wire.
