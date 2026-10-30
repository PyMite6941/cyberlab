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

Progress is saved to `~/.cyberterminal/progress.json`. Set
`CYBERTERMINAL_HOME` to keep it somewhere else.

Smoke test (no window needed):

```bash
python3 tests/smoke_terminal.py
```

## What is cyberterminal?

`cyberterminal` IS the program — there is no separate `cyberlab` command. Running
`cyberterminal` (or `.\run.bat` / `./run.sh`) launches a custom emulated terminal
shell:

```
student@cyberlab:~$ help
student@cyberlab:~$ ls             # read-only lab filesystem: ls, ll, cd, pwd, cat
student@cyberlab:~$ cat README.txt
student@cyberlab:~$ tutorials
student@cyberlab:~$ tutorial burp-basics
student@cyberlab:~$ labs
student@cyberlab:~$ run burp-01
student@cyberlab:~$ burp
student@cyberlab:~$ wireshark
student@cyberlab:~$ help web          # opens tutorial search page in browser
student@cyberlab:~$ exit
```

## Included tools

- **burp** — simulated intercepting proxy. Inspect and modify HTTP requests/
  responses against a mock vulnerable target, entirely offline.
- **wireshark** — simulated packet capture. Generate, inspect, filter, and
  export synthetic Ethernet/IP/TCP/UDP/HTTP/DNS packets to pcap.
- **tutorials** — 7 baked-in tutorials across web and network domains with
  step-by-step commands.
- **help web** — opens a self-contained HTML tutorial search page (offline).

## Available tutorials

| ID | Category | Title |
|----|----------|-------|
| burp-basics | web | BurpSuite Basics - Intercept & Modify |
| burp-sql-injection | web | Simulated SQL Injection via Proxy |
| burp-xss | web | Cross-Site Scripting (XSS) via Proxy |
| burp-admin-escalation | web | Privilege Escalation via Session Cookie |
| wireshark-basics | network | Wireshark Basics - Packet Inspection |
| wireshark-dns-analysis | network | DNS Traffic Analysis |
| wireshark-tcp-handshake | network | TCP Three-Way Handshake Analysis |

## Available labs

| ID | Module | Title |
|----|--------|-------|
| burp-01 | burp | Intercepting proxy basics |
| wireshark-01 | wireshark | Packet capture analysis |


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
