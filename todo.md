# cyberlab — todo / stopping point

## Status: COMPLETE (all verified)

Repo: `C:/Users/gresh/OneDrive/ドキュメント/portfolio/cyberlab`
Git: initialized, 2 commits on `master`, working tree clean.

### Verified commands
- `cyberlab --help` — lists all subcommands: labs, run, burp, wireshark, shell, tutorial
- `cyberlab labs` — lists 2 labs (burp-01, wireshark-01)
- `cyberlab tutorial <id>` — shows tutorial steps (burp-basics, wireshark-basics tested)
- `cyberlab burp` / `--help` — simulated intercepting proxy
- `cyberlab wireshark` / `--help` — simulated packet capture + pcap export
- `cyberlab shell` — custom terminator-like interactive environment:
  - `help`, `help web` (opens HTML tutorial search page in browser ✓)
  - `tutorials`, `tutorial <id>`, `run <id>`, `labs`, `burp`, `wireshark`, `cli <args>`, `clear`, `exit`

### Files
- `src/cyberlab/cli.py` — CLI entry point (shell + tutorial wired in)
- `src/cyberlab/shell.py` — CyberlabShell (cmd.Cmd), custom environment
- `src/cyberlab/tutorials/data.json` — 4 tutorials (burp-basics, burp-sql-injection, wireshark-basics, wireshark-dns-analysis)
- `src/cyberlab/tutorials/index.html` — self-contained offline tutorial search page (TUTORIALS_DATA embedded), category filters
- `src/cyberlab/tutorials/manager.py` — TutorialManager (load/search/get/categories)
- `src/cyberlab/modules/burp.py`, `src/cyberlab/modules/wireshark.py` — simulators
- `install.py` / `install.bat` / `install.sh` — venv + offline wheel cache
- `run.bat` / `run.sh` — launch wrappers
- `.gitignore` — ignores .venv, wheels, caches, build artifacts, .env
- `todo.md` — this file

### Remaining (optional)
- Test offline path: `install.py --cache-wheels` (online) then `install.py --offline` (fully offline)
- Push to GitHub requires authentication setup (PAT or SSH)
