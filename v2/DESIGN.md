# cyberlab v2 design

## Objective

A self-contained, offline cyber range for the cyber class, running on the
school's Linux Mint 22 VMs with nothing but stock Python 3. Students learn
common attacks and defenses (web, network, logs) by doing them against
realistic local targets, with the same tools and syntax used in the real world,
and get instant feedback.

## Principles

- **Offline, zero install.** Python standard library only. The real tools come
  from the separate offline tools pack (`v2/tools-pack`), but labs never require them.
- **Real over simulated.** Real HTTP targets, real files (logs, pcaps that open
  in Wireshark), real tools. v1 simulated the tools and taught invented syntax.
- **Safe by construction.** Targets bind to 127.0.0.1 only; nothing contacts
  the network; everything lives in `~/cyberlab`; `cyberlab stop` / `reset` clean up.
- **Checked answers.** Flags and answers are derived from a per-workspace secret,
  so they differ per student and aren't stored in the repo.
- **Content is data.** One file per challenge: goal, hints, `setup()`, `check()`.

## How it works

`cyberlab start <id>` runs the challenge's `setup()`, which starts the targets it
needs (each its own background process, pid and port kept in the state file)
and/or writes files into `~/cyberlab/<id>/`. Students attack with real tools,
then `cyberlab submit <id> <answer>` runs `check()`.

```
cyberlab/
  cli.py          commands
  workspace.py    ~/cyberlab, state, per-student secret, flags
  targets.py      start/stop target processes (127.0.0.1 only)
  webapp.py       the vulnerable web app (http.server + in-memory sqlite3)
  challenges/     one file per challenge
tests/            unittest, run in CI on Python 3.10 and 3.12
tools-pack/       offline apt bundle of nmap, tshark, sqlmap, hydra ...
```

## Milestones

1. **Done:** CLI, workspace, flags, target processes, `web-sqli`, tests and CI.
2. Web track: reflected XSS, IDOR, session-cookie tampering, upload filter bypass.
3. Network track: real pcaps for Wireshark/tshark (DNS tunnel, port scan,
   cleartext credentials, ARP spoofing).
4. Log track: real log files for grep (SSH brute force, password spray,
   privilege escalation, web attacks in an access log).
5. `cyberlab report` for the teacher.

v1 (the app at the repo root) stays as-is until v2 covers what the class uses.
