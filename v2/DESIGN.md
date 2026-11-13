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
then `cyberlab submit <id> <answer>` runs `check()`. Correct submissions and
`cyberlab learn <id>` show the same practical debrief: what happened, why it
matters, commands scoped to the lab, and how to defend against it.

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
2. **In progress:** web track includes reflected XSS and forgotten-directory
   discovery; access-control mistakes and unsafe upload validation remain.
3. **Done:** network track: generated pcaps for Wireshark/tshark (cleartext
   credentials, port scan, DNS tunnel), plus a local service-discovery lab.
4. Log track: real log files for grep (SSH brute force, password spray,
   privilege escalation, web attacks in an access log).
5. **Done:** `cyberlab report` for the teacher (text or JSON, `-o FILE`).

## Extending the network track

The network track is implemented with three self-contained packet-analysis
challenges. To add another, create a challenge module that writes a synthetic
capture into that student's workspace using `cyberlab.pcap`, register it in
`cyberlab/challenges/__init__.py`, and list Wireshark/`tshark` in its optional
tool hints. Keep the capture offline and synthetic: do not capture, inject, or
send traffic to external systems. Add tests that inspect the generated packets
and verify the answer check, then document the challenge in the README.

The distro's tools pack is separate from the challenge runtime, so challenges
must remain startable and checkable without those optional tools.

v2 is the standard application and the only supported challenge runtime. The
legacy root `src` terminal and its launch paths have been retired.
