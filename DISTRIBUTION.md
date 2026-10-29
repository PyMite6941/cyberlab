# Cross-Platform Distribution

cyberterminal is distributed as a PyInstaller `--onefile` single binary plus a
Python source mode. The committed `dist/cyberterminal.exe` is built on Windows
and runs on any Windows 10/11 machine **without Python installed** — the
interpreter and all modules are baked into the 13 MB executable.

## Running on any device

### Windows (no Python needed)
```bash
git clone https://github.com/PyMite6941/cyberlab.git
cd cyberlab
./cyberlab.sh           # uses dist/cyberterminal.exe automatically
# or: ./cyberlab.sh --binary
```

### Linux / macOS (Python required, or build your own binary)
The `.exe` is Windows-only. On Linux/macOS, either:

**Option A — Python/source mode (no build needed):**
```bash
git clone https://github.com/PyMite6941/cyberlab.git
cd cyberlab
./cyberlab.sh --install   # creates .venv via uv, installs package
./cyberlab.sh --python    # runs from source
```

**Option B — Build a native binary on your machine:**
```bash
git clone https://github.com/PyMite6941/cyberlab.git
cd cyberlab
./cyberlab.sh --install   # installs uv + PyInstaller into .venv
# .venv now has pyinstaller; build the onefile binary:
.venv/bin/pyinstaller --onefile --windowed --name cyberterminal \
  --distpath dist _pyinstaller_entry.py
./cyberlab.sh             # picks up dist/cyberterminal
```

## Binary portability

`dist/cyberterminal.exe` is fully self-contained. Copy just that one file to any
Windows machine and run it — no installation, no dependencies, no network.

```bash
cp dist/cyberterminal.exe /mnt/c/Users/You/Desktop/
# on the target machine, just double-click cyberterminal.exe
```

## Modes

| Mode | What it installs | Needs Python? | Best for |
|------|-----------------|---------------|----------|
| `binary` | `dist/cyberterminal.exe` only | No | End users, air-gapped machines |
| `python` | `.venv` + source package | Yes | Developers, contributors |
| `both` | Both of the above | Yes | Full setup (default) |

```bash
./install.py --mode binary    # verify dist/ exists (no Python needed)
./install.py --mode python    # venv only, no binary build
./install.py --mode both      # venv + binary (default)
```
