# cyberterminal — Expansion Guide

This document outlines areas where cyberterminal can be expanded and what new
simulated tools/modules can be incorporated for cybersecurity training. Use it
as a roadmap for adding new practice domains.

---

## 1. Current State

| Domain | Module | Simulator | Tutorials |
|--------|--------|-----------|-----------|
| Web / Proxy | `burp` | Intercepting proxy (HTTP request/response modification) | burp-basics, burp-sql-injection, burp-xss, burp-admin-escalation |
| Network / Packets | `wireshark` | Synthetic Ethernet/IP/TCP/UDP/DNS capture + pcap export | wireshark-basics, wireshark-dns-analysis, wireshark-tcp-handshake |

Total: 2 modules, 7 tutorials, 2 labs.

---

## 2. Near-Term Expansions (low effort, high value)

These build on the existing simulator architecture (mock target + cmd.Cmd shell).

### 2.1. Web Application Security (extend `burp` module)

Add new endpoints to `MockTarget` in `src/cyberlab/modules/burp.py`:

| Endpoint | Vulnerability to teach |
|----------|----------------------|
| `POST /search` | Reflected XSS (already tutorialized) |
| `GET /profile?id=<n>` | IDOR (Insecure Direct Object Reference) — access other users' profiles |
| `POST /upload` | File upload bypass (check extension/content-type) |
| `GET /redirect?url=<external>` | Open redirect |
| `POST /comment` | Stored XSS (comment reflected on page load) |
| `GET /api/users` | Broken authentication / missing authorization |

New tutorial ideas:
- `idor-01`: Access user2's profile by changing `id=1` to `id=2`
- `upload-01`: Bypass `.php` file upload filter using `.phtml`
- `redirect-01`: Craft an open redirect to an evil domain

### 2.2. Network Analysis (extend `wireshark` module)

Add new synthetic packet types to `src/cyberlab/modules/wireshark.py`:

| Packet type | What it teaches |
|-------------|-----------------|
| ARP | ARP spoofing / MAC flooding detection |
| ICMP | Ping sweeps, ICMP tunneling |
| TLS/HTTPS | Certificate inspection (simulated), SNI |
| SMTP | Email headers, phishing indicators |
| DHCP | DHCP starvation, rogue DHCP server |

New tutorial ideas:
- `arp-01`: Detect ARP spoofing (duplicate MAC for same IP)
- `icmp-01`: Identify ping sweep reconnaissance
- `dhcp-01`: Spot rogue DHCP server offering bad gateway

### 2.3. New Module: Password / Authentication

A simulated authentication lab for practicing:

- Password spraying (common passwords against many usernames)
- Credential stuffing (known pairs against multiple services)
- Hash cracking simulation (MD5/SHA1/NTPLM hashes to identify)
- Multi-factor authentication bypass simulation

Module file: `src/cyberlab/modules/auth.py`
Command: `cyberterminal> auth`

### 2.4. New Module: Log Analysis (SIEM)

A simulated security event log reader:

- Windows Security Event Log (4624 logon, 4625 failed logon)
- Apache/nginx access logs (404 scanning, user-agent enumeration)
- SSH auth logs (brute force patterns)
- Firewall denies (port scan detection)

Command: `cyberterminal> logs`
Subcommands: `list`, `filter`, `tail`, `export`

---

## 3. Medium-Term Expansions (architecture changes needed)

### 3.1. Scenario Difficulty Levels

Add a `difficulty` field to `Scenario` (beginner/intermediate/advanced) and
let users filter: `cyberterminal> labs --level beginner`

### 3.2. Progress Tracking

Save a local `progress.json` in the user's home directory tracking which
tutorials/labs they've completed. Show completion % in `tutorials` output.

### 3.3. CTF Flag System

Each scenario can have a hidden "flag" string. After completing steps, the
user enters the flag to mark the lab complete. Gamifies the experience.

### 3.4. Custom Scenario Creation

Allow users to author their own scenarios in YAML/JSON and drop them into a
`scenarios/` directory. The terminal auto-discovers them on startup.

Example `scenarios/custom-01.yaml`:
```yaml
id: custom-01
title: My Custom Lab
module: burp
description: ...
steps:
  - command: intercept GET /flag
    notes: "Find the hidden flag"
```

---

## 4. Long-Term Expansions (new domains)

### 4.1. Wireless Security

Simulated Wi-Fi packet capture:
- 802.11 deauthentication attacks
- WPA2 handshake capture (simulated)
- Evil twin AP detection
- WPS pin brute force simulation

### 4.2. Active Directory / Identity

Simulated AD environment:
- Kerberoasting (request service tickets)
- Pass-the-hash simulation
- BloodHound-style path visualization (text-based)
- GPO misconfiguration scanning

### 4.3. Cloud Security

Simulated cloud console:
- S3 bucket misconfigurations (public read/write)
- IAM policy over-permissioning
- CloudTrail log inspection
- Lambda function source review

### 4.4. Mobile / IoT

Simulated mobile app traffic interception:
- Certificate pinning bypass simulation
- API endpoint enumeration from APK strings
- IoT default credential scanning
- MQTT broker topic enumeration

### 4.5. Reverse Engineering / Binary Analysis

Simulated binary challenges:
- Strings extraction from mock binaries
- Disassembly reading (simulated assembly)
- Debugger breakpoint simulation
- Packed malware detection

---

## 5. How to Add a New Module

1. Create `src/cyberlab/modules/<name>.py`
2. Define a `MockTarget` or packet generator class
3. Define a `<Name>Shell(cmd.Cmd)` with `do_*` commands
4. Add a `run_<name>(args)` function that launches the shell
5. Self-register a `Scenario` at import time:

```python
from cyberlab.core import Scenario, registry as _registry

def _mymod_lab() -> int:
    return run_mymod(argparse.Namespace(...))

_registry.register(
    Scenario(
        id="mymod-01",
        title="My New Lab",
        description="...",
        module="mymod",
        run=_mymod_lab,
        tags=["domain", "skill", "offline"],
    )
)
```

6. Add a `do_mymod` command to `CyberTerminal` in `src/cyberlab/terminal.py`
7. Add tutorials to `src/cyberlab/tutorials/data.json`
8. Test: `cyberterminal> labs` should show your new scenario

---

## 6. Recommended Learning Path (for users)

```
Week 1:  wireshark-basics   -> wireshark-dns-analysis
Week 2:  burp-basics        -> burp-sql-injection
Week 3:  burp-xss           -> burp-admin-escalation
Week 4:  wireshark-tcp-handshake
Week 5+: Custom scenarios / new modules
```

---

## 7. Contributing

- Add tutorials as JSON entries in `data.json` (no code changes needed)
- Add new simulator modules as Python files in `src/cyberlab/modules/`
- Keep everything offline — no real network traffic, no external API calls
- Document every new command with a `do_<cmd>` docstring (shown by `help`)
- Add at least one tutorial per new module so users have a guided path
