"""Smoke test for the terminal backend and simulators, no window needed.

Drives CyberTerminalGUI (the cmd.Cmd behind the Tk window) and the simulator
shells the way the windows do, one line at a time, and checks:
- simulators never read the console; lines typed in a tool window reach them
- tool commands and `run <lab>` open the right tool window
- a fresh install starts with no progress, and `submit` records progress
- the simulator detection / cracking fixes
- the main window reads typed commands correctly (skipped with no display)

    python3 tests/smoke_terminal.py
"""

import builtins
import contextlib
import io
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
HOME = tempfile.mkdtemp()
os.environ["CYBERTERMINAL_HOME"] = HOME  # keep real progress untouched

import src.core.docs as docs  # noqa: E402

docs.is_online = lambda timeout=2.0: False  # no network probe; patched before terminal imports it


def no_console(*args, **kwargs):
    raise AssertionError("read from the console")


builtins.input = no_console
sys.stdin = type("NoStdin", (), {"readline": no_console, "read": no_console})()

import src.terminal as terminal  # noqa: E402

failures = 0


def check(ok, label):
    global failures
    failures += not ok
    print(f"{'PASS' if ok else 'FAIL'}  {label}")


def new_term():
    out = io.StringIO()
    return terminal.CyberTerminalGUI(output_callback=out.write), out


def send(term, out, line):
    """Run one line the way TerminalWindow._on_enter does; return its output."""
    start = out.tell()
    with contextlib.redirect_stdout(out):
        stop = term.onecmd(line)
    out.seek(start)
    text = out.read()
    return stop, text


# --- simulators take their input from the tool window, never the console ---
for tool in sorted(terminal.TOOL_SHELLS):
    try:
        shell = terminal.TOOL_SHELLS[tool]()
        text, stop = terminal.run_tool_line(shell, "help")
        _, quit_stop = terminal.run_tool_line(shell, "quit")
        check(text.strip() and "Unknown syntax" not in text and not stop and quit_stop,
              f"{tool}: takes lines from its window; quit closes it")
    except AssertionError as e:
        check(False, f"{tool}: {e}")

text, _ = terminal.run_tool_line(terminal.BurpShell(), "targets")
check("Endpoints" in text, "burp: a typed line reaches the simulator")
text, _ = terminal.run_tool_line(terminal.BurpShell(), "progress")
check("Unknown syntax: progress" in text, "cmd's own messages are captured for the window")

opened = []
terminal._launch_tool_window = opened.append  # no Tk in this test
term, out = new_term()
send(term, out, "nmap")
send(term, out, "run burp-01")
send(term, out, "osint")  # offline: refuses
terminal.is_online = lambda timeout=2.0: True
send(term, out, "osint")
terminal.is_online = lambda timeout=2.0: False
check(opened == ["nmap", "burp", "osint"], f"tool commands and run <lab> open tool windows ({opened})")

# --- progress ---
term, out = new_term()
_, text = send(term, out, "progress")
check("0/26" in text, f"fresh install starts with no progress ({text.strip()})")
send(term, out, "tutorial net-nmap-01")
_, text = send(term, out, "submit done")
check("Marked as completed" in text, "tutorial <id> selects it for submit")
_, text = send(term, out, "progress")
saved = json.loads((Path(HOME) / "progress.json").read_text())
check("1/26" in text and saved["completed"] == ["net-nmap-01"], "submit saves progress in CYBERTERMINAL_HOME")
term2, out2 = new_term()
_, text = send(term2, out2, "progress")
check("1/26" in text, "progress survives a restart")
for cmd_ in ("tutorials", "next", "focus web-sqli-01", "difficulty easy"):
    _, text = send(term, out, cmd_)
    check("Error" not in text and "has no attribute" not in text, f"'{cmd_}' runs")

# --- simulator fixes ---
from src.modules.auth import AuthShell, analyze_spray  # noqa: E402
from src.modules.hydra import simulate_crack  # noqa: E402
from src.modules.siem import SIEMShell, analyze_brute, analyze_escalate, analyze_scan  # noqa: E402
from src.modules.sqlmap import run_sqlmap_test  # noqa: E402

r = simulate_crack("192.168.1.10", "ssh", "admin")
check(r["found"] and r["password"] == "admin", "hydra cracks admin over ssh")
check(analyze_spray(AuthShell().events)["source"] == "10.0.0.99", "auth finds the spraying IP")
siem = SIEMShell().events
check(analyze_brute(siem)["source"] == "10.0.0.99", "siem finds the brute-force source")
check(analyze_scan(siem)["is_port_scan"], "siem finds the port scan")
check(any(u == "user1" for u, _ in analyze_escalate(siem)["unexpected_users"]), "siem flags user1's sudo")
check(run_sqlmap_test("http://lab.local/")["vulnerable_count"] == 0, "sqlmap: no parameters, nothing reported")
check(run_sqlmap_test("http://lab.local/search?q=x")["vulnerable_count"] == 1, "sqlmap: reports the q parameter")

# --- main window: typed commands are read and echoed once ---
import time  # noqa: E402
import tkinter as tk  # noqa: E402

try:
    win = terminal.TerminalWindow()
except tk.TclError as e:
    print(f"SKIP  main window checks (no display: {e})")
else:
    win.root.withdraw()
    PROMPT = terminal.CyberTerminalGUI.prompt

    def type_and_run(line):
        win.text.insert("end-1c", line)
        win._on_return(None)
        deadline = time.time() + 5
        while not win.awaiting_input and time.time() < deadline:
            win.root.update()
            time.sleep(0.01)
        win.root.update()
        return win.text.get("1.0", "end-1c")

    buf = type_and_run("help")
    lines = buf.splitlines()
    check("yberterminal" not in buf and lines.count(PROMPT + "help") == 1,
          "main window: 'help' is read as help and echoed once")
    check("burp" in buf.split(PROMPT + "help", 1)[1], "main window: help output appears below the command")
    check(lines[-1] == PROMPT and win.awaiting_input, "main window: a fresh prompt is the last line")
    buf = type_and_run("nosuchcmd")
    check("Unknown syntax: nosuchcmd" in buf, "main window: typos are reported in the window")
    win.root.destroy()

print(f"\n{failures} failure(s)")
raise SystemExit(1 if failures else 0)
