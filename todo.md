# cyberterminal — todo / stopping point

## Status: COMPLETE (all verified, debugged, documented)

Repo: `C:/Users/gresh/OneDrive/ドキュメント/portfolio/cyberlab`
Git: commits on `master`, remote `origin` = `https://github.com/PyMite6941/cyberlab.git`

### Verified
- `cyberterminal` console script installed via `install.py --non-interactive --recreate`
- run.bat / run.sh launch `python -m src.terminal` directly
- Terminal is a windowed emulated terminal (typewriter-style): type directly in the buffer, no separate entry box, lines iterable, arrow-key history, tab-completion, gear/`⚙ Styles` icon for theme changes
- Terminal commands: help, tutorials, tracks, difficulty, focus, next, tutorial, labs, run, submit, progress, docs, burp, wireshark, nmap, sqlmap, hydra, nikto, cookie, webscan, osint, auth, siem, clear, exit/quit
- Each tool (burp, wireshark, nmap, sqlmap, hydra, nikto, cookie, webscan, osint, auth, siem) launches in its own Toplevel window with fully simulated, randomized packets/traffic — nothing touches the network
- `help web` opens HTML tutorial search page in browser
- 26 tutorials across 5 tracks (web, network, auth, siem, osint)
- Challenge system: dynamic generation, computed verification, NO hardcoded flags
- Wireshark challenges: DNS tunneling (easy), Port scan (medium) — pcap files written to `src/data/captures/`
- Burp challenges: SQL injection, IDOR, Auth bypass — simulated HTTP proxy
- All 11 modules import: auth, burp, hydra, nikto, nmap, cookie, webscan, osint, siem, sqlmap, wireshark
- OSINT is online-only (fails gracefully when offline)
- Docs system: list/search/download/status with online/offline detection
- Interactive install: prompts for docs, tools, tutorials; --non-interactive, --cache-wheels, --offline, --recreate flags
- All source files have comprehensive docstrings
- No hardcoded FLAG{...} anywhere in src/
- Dead submission system removed (src/core/submission.py + src/data/submissions.json deleted)

### Files
- `pyproject.toml` — `cyberterminal = "src.terminal:main"` entry point, packages = ["src"]
- `src/terminal.py` — windowed tkinter GUI terminal (CyberTerminalGUI + CyberTerminal alias for backward compat)
- `src/__main__.py` — `python -m src` entry point
- `src/core/challenge.py` — Challenge base class, ChallengeRegistry, CAPTURES_DIR
- `src/core/track.py` — Track, Tutorial, TrackRegistry
- `src/core/lab.py` — Scenario, LabRegistry
- `src/core/docs.py` — docs catalog, online/offline detection, hints, download
- `src/core/submission.py` — submission/verification
- `src/modules/*.py` — 11 simulators (auth, burp, hydra, nikto, nmap, cookie, webscan, osint, siem, sqlmap, wireshark)
- `src/tutorials/data.json` — 26 tutorial definitions
- `src/tutorials/tracks.json` — 5 track definitions
- `src/tutorials/index.html` — self-contained HTML tutorial search page
- `install.py` — interactive install (docs, tools, tutorials prompts)
- `install.bat` / `install.sh` — install wrappers
- `run.bat` / `run.sh` — terminal launch wrappers
- `.gitignore` — ignores .venv, wheels, caches, build artifacts, .env
- `README.md` — cyberterminal docs
- `todo.md` — this file

### Remaining (optional)
- Push to GitHub requires authentication setup (PAT or SSH)
