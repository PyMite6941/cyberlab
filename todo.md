# cyberlab — todo / stopping point

## Status (last verified state)
- Repo: `C:/Users/gresh/OneDrive/ドキュメント/portfolio/cyberlab` — not git-initialized yet
- venv installed at `.venv/` (via `install.py`, uv backend)
- All commands verified working before the redesign: `cyberlab labs`, `burp --help`, `wireshark --help`, burp login flow, wireshark packet gen + pcap export

## Redesign in progress (code written, NOT re-verified after edits)
New files added:
- `src/cyberlab/tutorials/data.json` — 4 tutorials with steps/commands/notes
- `src/cyberlab/tutorials/index.html` — self-contained offline tutorial search page (TUTORIALS_DATA embedded), category filters (web/network)
- `src/cyberlab/tutorials/__init__.py` — package export
- `src/cyberlab/tutorials/manager.py` — TutorialManager: load/search/get/categories from data.json
- `src/cyberlab/shell.py` — CyberlabShell (cmd.Cmd), terminator-like custom environment:
  - `help` / `help web` -> opens HTML tutorial search page in browser
  - `tutorials` / `tutorial <id>` / `run <id>` / `labs` / `burp` / `wireshark` / `cli <args>` / `clear` / `exit`

CLI changes (`src/cyberlab/cli.py`):
- Replaced inline tutorial with TutorialManager-backed `tutorial <id>`
- Added `shell` subcommand launching CyberlabShell
- `burp`, `wireshark`, `labs`, `run` retained

## Remaining work
1. Reinstall venv after the tutorial/shell changes (`python install.py --recreate`)
2. Verify all entry points: `cyberlab --help`, `labs`, `tutorial <id>`, `shell`, `burp --help`, `wireshark --help`
3. Verify `cyberlab shell` -> `help web` opens the HTML page
4. `git init` the directory and make initial commit
5. Test offline path: `install.py --cache-wheels` then `install.py --offline` (cache_wheels now uses venv pip download since `uv pip download` doesn't exist in this uv version)

## Notes
- `uv pip download` is NOT available in this uv version (0.11.15) — `cache_wheels` falls back to `venv_python -m pip download`
- `git init` requested by user but not yet executed
- No `todo_list` tool available in this environment — using todo.md file instead
