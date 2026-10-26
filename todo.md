# cyberterminal — todo / stopping point

## Status: COMPLETE (all verified, debugged, documented)

Repo: `C:/Users/gresh/OneDrive/ドキュメント/portfolio/cyberlab`
Git: initialized, 7 commits on `master`, working tree clean.

### Verified
- `cyberterminal` console script installed
- run.bat / run.sh launch the terminal directly
- Terminal commands: burp, clear, exit, help, labs, quit, run, tutorial, tutorials, wireshark
- `help web` opens HTML tutorial search page in browser
- 7 tutorials: burp-basics, burp-sql-injection, burp-xss, burp-admin-escalation, wireshark-basics, wireshark-dns-analysis, wireshark-tcp-handshake
- 2 labs: burp-01 (burp), wireshark-01 (wireshark)
- Burp login flow (200/401/403) + /search query-string fix verified
- Wireshark packet gen + filters + valid pcap export verified
- Tutorial manager search/categories verified
- Lab registry self-registration verified
- Interactive install: prompts for docs, tools, tutorials
- Offline path: --cache-wheels -> --offline tested
- --non-interactive mode works
- All source files have comprehensive docstrings

### Files
- `pyproject.toml` — `cyberterminal = "cyberlab.terminal:main"` entry point
- `src/cyberlab/terminal.py` — CyberTerminal (cmd.Cmd), the custom emulated terminal
- `src/cyberlab/cli.py` — legacy CLI (no longer entry point)
- `src/cyberlab/shell.py` — legacy shell module
- `src/cyberlab/tutorials/data.json` — 4 tutorials
- `src/cyberlab/tutorials/index.html` — self-contained HTML search page + logo/favicon
- `src/cyberlab/tutorials/manager.py` — TutorialManager
- `src/cyberlab/tutorials/assets/logo.svg`, `favicon.svg` — website logo/icon
- `src/cyberlab/modules/burp.py`, `src/cyberlab/modules/wireshark.py` — simulators
- `install.py` — interactive install (docs, tools, tutorials prompts)
- `install.bat` / `install.sh` — install wrappers
- `run.bat` / `run.sh` — terminal launch wrappers
- `.gitignore` — ignores .venv, wheels, caches, build artifacts, .env
- `README.md` — cyberterminal docs
- `todo.md` — this file

### Remaining (optional)
- Push to GitHub requires authentication setup (PAT or SSH)
