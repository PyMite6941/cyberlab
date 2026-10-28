"""cyberterminal — emulated terminal for offline cybersecurity practice.

A real-feeling terminal window: type directly in the buffer (no separate
entry box), lines are iterable like a real terminal, and every tool
(burp, wireshark, nmap, sqlmap, hydra, nikto, cookie, webscan, osint,
auth, siem) launches in its own window with fully simulated, randomized
packets/traffic - nothing touches the network.
"""

from __future__ import annotations

import cmd
import shlex
import sys
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, font as tkfont
from pathlib import Path

from src.core import lab_registry, track_registry
from src.core.docs import (
    is_online, get_docs_for_tool, get_all_docs, download_doc,
    get_offline_docs, get_hint_for_tool, is_tool_available,
)
from src.modules.auth import run_auth
from src.modules.burp import run_burp
from src.modules.hydra import run_hydra
from src.modules.nikto import run_nikto
from src.modules.nmap import run_nmap
from src.modules.cookie import run_cookie
from src.modules.webscan import run_webscan
from src.modules.osint import run_osint_shell
from src.modules.siem import run_siem
from src.modules.sqlmap import run_sqlmap
from src.modules.wireshark import run_wireshark
from src.tutorials.manager import TutorialManager

# Self-register modules (scenarios/challenges register at import)
import src.modules.auth  # noqa: F401
import src.modules.burp  # noqa: F401
import src.modules.hydra  # noqa: F401
import src.modules.nikto  # noqa: F401
import src.modules.nmap  # noqa: F401
import src.modules.cookie  # noqa: F401
import src.modules.webscan  # noqa: F401
import src.modules.osint  # noqa: F401
import src.modules.siem  # noqa: F401
import src.modules.sqlmap  # noqa: F401
import src.modules.wireshark  # noqa: F401


ASCII_LOGO = r"""
  ____  __   __ ____  _____ ____  _        _    ____  
 / ___| \ \ / /| __ )| ____|  _ \| |      / \  | __ ) 
| |      \ V / |  _ \|  _| | |_) | |     / _ \ |  _ \ 
| |___    | |  | |_) | |___|  _ <| |___ / ___ \| |_) |
 \____|   |_|  |____/|_____|_| \_\_____/_/   \_\____/ 
       
  CYBERLAB - offline cybersecurity practice
"""

class CyberTerminalGUI(cmd.Cmd):
    """The cmd.Cmd backend logic for cyberterminal."""

    prompt = "cyberterminal> "

    def __init__(self, output_callback=None) -> None:
        super().__init__()
        self.output_callback = output_callback
        self.manager = TutorialManager()
        self._selected_tutorial = None
        self.intro = self._build_banner()

    def _build_banner(self) -> str:
        status = "ONLINE" if is_online() else "OFFLINE"
        return (
            f"{ASCII_LOGO}\n"
            f"Network: {status}  |  Type 'help' or '?' for commands. "
            f"Type 'exit' or 'quit' to leave.\n"
        )

    def _write(self, text: str) -> None:
        if self.output_callback:
            self.output_callback(text)
        else:
            print(text, end="")

    def _writeln(self, text: str = "") -> None:
        self._write(text + "\n")

    # ---------- commands ----------

    def do_help(self, arg: str) -> None:
        """Show terminal commands or open the tutorial search webpage.

        usage: help
        usage: help <command>
        usage: help web        # opens HTML tutorial search page
        """
        arg = arg.strip().lower()
        if arg in ("web", "html", "search", "tutorials"):
            self._open_tutorial_webpage()
            return
        if arg:
            method = getattr(self, f"do_{arg}", None)
            if method:
                self._writeln(method.__doc__ or f"No help for '{arg}'.")
            else:
                self._writeln(f"Unknown command: {arg}")
            return

        self._writeln("cyberterminal commands:")
        self._writeln()
        cmds = [
            ("help", "show this help | help web  -> open tutorial search page"),
            ("tutorials", "list available tutorials"),
            ("tracks", "list learning tracks"),
            ("difficulty <easy|medium|hard|all>", "filter tutorials by difficulty"),
            ("focus <id>", "focus on one tutorial at a time"),
            ("next", "show next recommended tutorial"),
            ("tutorial <id>", "show a tutorial's steps"),
            ("labs", "list available practice labs"),
            ("run <id>", "run a guided lab by id"),
            ("submit <answer>", "submit an answer for the selected challenge"),
            ("progress", "show completion progress"),
            ("docs", "documentation: list, search, download, status"),
            ("burp", "launch intercepting proxy (real or simulated)"),
            ("wireshark", "launch packet capture (real or simulated)"),
            ("nmap", "launch network scanner (real or simulated)"),
            ("sqlmap", "launch SQL injection tool (real or simulated)"),
            ("hydra", "launch password cracker (real or simulated)"),
            ("nikto", "launch web vuln scanner (real or simulated)"),
            ("clear", "clear the screen"),
            ("cat", "display the contents of a file"),
            ("grep", "search for a pattern in a file"),
            ("exit / quit", "leave the terminal"),
        ]
        for name, desc in cmds:
            self._writeln(f"  {name:<35} {desc}")
        self._writeln()
        self._writeln("Type 'help web' to browse tutorials in a browser.")
        self._writeln("All traffic is simulated locally. Nothing touches the network.")

    def _open_tutorial_webpage(self) -> None:
        """Open the HTML tutorial search page."""
        import webbrowser
        html_path = Path(__file__).resolve().parent / "tutorials" / "index.html"
        if html_path.exists():
            webbrowser.open(f"file://{html_path}")
            self._writeln(f"Opened tutorial search page: {html_path}")
        else:
            self._writeln("Tutorial search page not found.")

    def do_tutorials(self, arg: str) -> None:
        """List available tutorials."""
        tutorials = self.manager.list_tutorials()
        if not tutorials:
            self._writeln("No tutorials registered.")
            return
        self._writeln("Tutorials:")
        self._writeln()
        for t in tutorials:
            status = "[COMPLETED]" if self.manager.is_completed(t.get("id", "")) else ""
            self._writeln(
                f"  {t.get('id',''):<30} [{t.get('category',''):<8}] "
                f"{t.get('difficulty',''):<6} {t.get('title','')} {status}"
            )
            self._writeln(f"    {t.get('description','')}")
        self._writeln()
        self._writeln("Use: tutorial <id>   to view steps")
        self._writeln("     help web        to open the search webpage")

    def do_tracks(self, arg: str) -> None:
        """List learning tracks."""
        tracks = track_registry.list_tracks()
        if not tracks:
            self._writeln("No tracks registered yet.")
            return
        self._writeln("Learning tracks:")
        self._writeln()
        for track in tracks:
            self._writeln(f"  {track.id}: {track.title}")
            self._writeln(f"    {track.description}")
            tuts = track_registry.list_tutorials(track.id)
            for t in tuts:
                self._writeln(f"      - {t.id}: {t.title}")
        self._writeln()

    def do_difficulty(self, arg: str) -> None:
        """Filter tutorials by difficulty.

        usage: difficulty <easy|medium|hard|all>
        """
        diff = arg.strip().lower()
        if diff not in ("easy", "medium", "hard", "all"):
            self._writeln("usage: difficulty <easy|medium|hard|all>")
            return
        tutorials = self.manager.list_tutorials()
        if diff != "all":
            tutorials = [t for t in tutorials if t.get("difficulty") == diff]
        self._writeln(f"Tutorials (difficulty={diff}):")
        self._writeln()
        for t in tutorials:
            self._writeln(f"  {t.get('id',''):<30} {t.get('title','')} [{t.get('difficulty','')}]")
        self._writeln()

    def do_focus(self, arg: str) -> None:
        """Focus on one tutorial at a time.

        usage: focus <id>
        """
        tid = arg.strip()
        if not tid:
            self._writeln("usage: focus <id>")
            return
        t = self.manager.get_tutorial(tid)
        if not t:
            self._writeln(f"Unknown tutorial: {tid}")
            return
        self._selected_tutorial = tid
        self._writeln(f"Focused on: {tid} — {t.get('title','')}")
        self._writeln(f"  {t.get('description','')}")
        self._writeln("Steps:")
        for i, step in enumerate(t.get("steps", []), 1):
            self._writeln(f"  {i}. {step.get('description','')}  ({step.get('command','')})")
        self._writeln()

    def do_next(self, arg: str) -> None:
        """Show next recommended tutorial."""
        tutorials = self.manager.list_tutorials()
        if not tutorials:
            self._writeln("No tutorials available.")
            return
        for t in tutorials:
            if not self.manager.is_completed(t.get("id", "")):
                self._writeln("Next recommended tutorial:")
                self._writeln(f"  {t.get('id','')}: {t.get('title','')}")
                self._writeln(f"  {t.get('description','')}")
                self._writeln(f"  Difficulty: {t.get('difficulty','')}")
                return
        self._writeln("All tutorials completed!")

    def do_tutorial(self, arg: str) -> None:
        """Show a tutorial's steps.

        usage: tutorial <id>
        """
        tid = arg.strip()
        if not tid:
            self._writeln("usage: tutorial <id>")
            return
        t = self.manager.get_tutorial(tid)
        if not t:
            self._writeln(f"Unknown tutorial: {tid}")
            return
        self._writeln(f"Tutorial: {t.get('id','')} — {t.get('title','')}")
        self._writeln(f"  Category: {t.get('category','')}  Difficulty: {t.get('difficulty','')}")
        self._writeln(f"  Module: {t.get('module','')}")
        self._writeln(f"  {t.get('description','')}")
        self._writeln()
        self._writeln("Steps:")
        for i, step in enumerate(t.get("steps", []), 1):
            self._writeln(f"  {i}. {step.get('description','')}")
            cmd_ = step.get("command", "")
            if cmd_:
                self._writeln(f"     Command: {cmd_}")
            notes = step.get("notes", "")
            if notes:
                self._writeln(f"     Notes: {notes}")
        self._writeln()
        self._writeln("Use 'submit <answer>' to submit your answer when done.")

    def do_labs(self, arg: str) -> None:
        """List available practice labs."""
        labs = lab_registry.list()
        if not labs:
            self._writeln("No labs registered.")
            return
        self._writeln("Practice labs:")
        self._writeln()
        for lab in labs:
            self._writeln(f"  {lab.id}: {lab.title}")
            self._writeln(f"    {lab.description}")
        self._writeln()
        self._writeln("Use: run <id>  to start a lab")

    def do_run(self, arg: str) -> None:
        """Run a guided lab by id.

        usage: run <id>
        """
        lid = arg.strip()
        if not lid:
            self._writeln("usage: run <id>")
            return
        lab = lab_registry.get(lid)
        if not lab:
            self._writeln(f"Unknown lab: {lid}")
            return
        self._writeln(f"Running lab: {lab.title}")
        self._writeln(lab.description)
        self._writeln()
        try:
            lab.run()
        except Exception as e:
            self._writeln(f"Lab error: {e}")

    def do_submit(self, arg: str) -> None:
        """Submit an answer for the selected challenge.

        usage: submit <answer>
        """
        answer = arg.strip()
        if not answer:
            self._writeln("usage: submit <answer>")
            return
        if not self._selected_tutorial:
            self._writeln("No tutorial selected. Use 'focus <id>' or 'tutorial <id>' first.")
            return
        from src.core.challenge import registry as challenge_registry
        challenge = challenge_registry.get(self._selected_tutorial)
        if challenge:
            result = challenge.verify(answer)
            if result.correct:
                self._writeln(f"Correct! {result.feedback}")
                self.manager.mark_completed(self._selected_tutorial)
            else:
                self._writeln(f"Incorrect. {result.feedback}")
        else:
            self._writeln(f"Answer submitted for {self._selected_tutorial}: {answer}")
            self.manager.mark_completed(self._selected_tutorial)
            self._writeln("Marked as completed.")

    def do_progress(self, arg: str) -> None:
        """Show completion progress."""
        tutorials = self.manager.list_tutorials()
        total = len(tutorials)
        completed = sum(1 for t in tutorials if self.manager.is_completed(t.get("id", "")))
        pct = (completed / total * 100) if total else 0
        self._writeln(f"Progress: {completed}/{total} tutorials completed ({pct:.0f}%)")
        self._writeln()

    def do_docs(self, arg: str) -> None:
        """Documentation: list, search, download, status.

        usage: docs
        usage: docs list
        usage: docs search <term>
        usage: docs download <tool>
        usage: docs status
        """
        parts = shlex.split(arg)
        if not parts or parts[0] == "list":
            docs = get_all_docs()
            self._writeln("Available documentation:")
            self._writeln()
            for d in docs:
                online = "ONLINE" if d.get("online") else "OFFLINE"
                self._writeln(f"  {d.get('tool',''):<12} [{online}] {d.get('title','')}")
            self._writeln()
        elif parts[0] == "search":
            if len(parts) < 2:
                self._writeln("usage: docs search <term>")
                return
            term = parts[1]
            docs = get_all_docs()
            found = [d for d in docs if term.lower() in d.get("title", "").lower()
                     or term.lower() in d.get("tool", "").lower()]
            if not found:
                self._writeln(f"No docs matching '{term}'.")
            for d in found:
                self._writeln(f"  {d.get('tool','')}: {d.get('title','')}")
        elif parts[0] == "download":
            if len(parts) < 2:
                self._writeln("usage: docs download <tool>")
                return
            tool = parts[1]
            ok = download_doc(tool)
            if ok:
                self._writeln(f"Downloaded docs for {tool}.")
            else:
                self._writeln(f"Could not download docs for {tool} (may be offline-only).")
        elif parts[0] == "status":
            status = "ONLINE" if is_online() else "OFFLINE"
            self._writeln(f"Network status: {status}")
            for tool in ["burp", "wireshark", "nmap", "sqlmap", "hydra", "nikto",
                         "cookie", "webscan", "osint", "auth", "siem"]:
                avail = is_tool_available(tool)
                self._writeln(f"  {tool:<12} {'available' if avail else 'offline-only'}")
        else:
            self._writeln("usage: docs [list|search <term>|download <tool>|status]")

    def do_burp(self, arg: str) -> None:
        """Launch simulated intercepting proxy (BurpSuite-style) in its own window."""
        self._writeln("Launching BurpSuite simulator in a new window...")
        _launch_tool_window("burp", run_burp, {"target": "http://lab.local"})

    def do_wireshark(self, arg: str) -> None:
        """Launch simulated packet capture (Wireshark-style) in its own window."""
        self._writeln("Launching Wireshark simulator in a new window...")
        _launch_tool_window("wireshark", run_wireshark, {})

    def do_nmap(self, arg: str) -> None:
        """Launch simulated network scanner (Nmap-style) in its own window."""
        self._writeln("Launching Nmap simulator in a new window...")
        _launch_tool_window("nmap", run_nmap, {})

    def do_sqlmap(self, arg: str) -> None:
        """Launch simulated SQL injection tool (SQLmap-style) in its own window."""
        self._writeln("Launching SQLmap simulator in a new window...")
        _launch_tool_window("sqlmap", run_sqlmap, {})

    def do_hydra(self, arg: str) -> None:
        """Launch simulated password cracker (Hydra-style) in its own window."""
        self._writeln("Launching Hydra simulator in a new window...")
        _launch_tool_window("hydra", run_hydra, {})

    def do_nikto(self, arg: str) -> None:
        """Launch simulated web vulnerability scanner (Nikto-style) in its own window."""
        self._writeln("Launching Nikto simulator in a new window...")
        _launch_tool_window("nikto", run_nikto, {})

    def do_cookie(self, arg: str) -> None:
        """Cookie security is a learning category, not a runnable tool.

        Use: tutorials  to see cookie tutorials
             tutorial web-cookie-01  to view steps
        """
        self._writeln("Cookie security is a learning category, not a runnable tool.")
        self._writeln("  tutorials             list all tutorials")
        self._writeln("  tutorial web-cookie-01  view cookie security tutorial steps")
        self._writeln("  help web               browse tutorials in a browser")

    def do_webscan(self, arg: str) -> None:
        """Web scanning is a learning category, not a runnable tool.

        Use: tutorials  to see web scan tutorials
             tutorial web-webscan-01  to view steps
        """
        self._writeln("Web scanning is a learning category, not a runnable tool.")
        self._writeln("  tutorials             list all tutorials")
        self._writeln("  tutorial web-webscan-01  view web scanning tutorial steps")
        self._writeln("  help web               browse tutorials in a browser")

    def do_osint(self, arg: str) -> None:
        """OSINT is a learning category, not a runnable tool.

        Use: tutorials  to see OSINT tutorials
             tutorial osint-domain-01  to view steps
        """
        self._writeln("OSINT is a learning category, not a runnable tool.")
        self._writeln("  tutorials          list all tutorials")
        self._writeln("  tutorial osint-domain-01  view OSINT domain reconnaissance steps")
        self._writeln("  help web           browse tutorials in a browser")

    def do_auth(self, arg: str) -> None:
        """Auth is a learning category, not a runnable tool.

        Use: tutorials  to see auth tutorials
             tutorial auth-password-spray-01  to view steps
        """
        self._writeln("Authentication is a learning category, not a runnable tool.")
        self._writeln("  tutorials              list all tutorials")
        self._writeln("  tutorial auth-password-spray-01  view auth tutorial steps")
        self._writeln("  help web               browse tutorials in a browser")

    def do_siem(self, arg: str) -> None:
        """SIEM is a learning category, not a runnable tool.

        Use: tutorials  to see SIEM tutorials
             tutorial siem-brute-force-01  to view steps
        """
        self._writeln("SIEM is a learning category, not a runnable tool.")
        self._writeln("  tutorials             list all tutorials")
        self._writeln("  tutorial siem-brute-force-01  view SIEM tutorial steps")
        self._writeln("  help web              browse tutorials in a browser")

    def do_cat(self, arg: str) -> None:
        """Display the contents of a file.

        usage: cat <file>
        """
        path = arg.strip()
        if not path:
            self._writeln("usage: cat <file>")
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                self._writeln(f.read())
        except FileNotFoundError:
            self._writeln(f"cat: {path}: No such file or directory")
        except IsADirectoryError:
            self._writeln(f"cat: {path}: Is a directory")
        except Exception as e:
            self._writeln(f"cat: {path}: {e}")

    def do_grep(self, arg: str) -> None:
        """Search for a pattern in a file.

        usage: grep <pattern> <file>
        """
        parts = shlex.split(arg)
        if len(parts) < 2:
            self._writeln("usage: grep <pattern> <file>")
            return
        pattern, path = parts[0], parts[1]
        try:
            import re
            rx = re.compile(pattern)
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                for i, line in enumerate(f, 1):
                    if rx.search(line):
                        self._writeln(f"{i}:{line.rstrip()}")
        except FileNotFoundError:
            self._writeln(f"grep: {path}: No such file or directory")
        except re.error as e:
            self._writeln(f"grep: invalid pattern: {e}")
        except Exception as e:
            self._writeln(f"grep: {path}: {e}")

    def do_clear(self, arg: str) -> None:
        """Clear the terminal screen."""
        if self.output_callback:
            self.output_callback("__CLEAR__")
        else:
            import os
            os.system("cls" if sys.platform == "win32" else "clear")

    def do_quit(self, arg: str) -> None:
        """Leave the terminal."""
        self._writeln("Goodbye.")
        if self.output_callback:
            self.output_callback("__QUIT__")
        return True

    def do_exit(self, arg: str) -> None:
        return self.do_quit(arg)

    def emptyline(self) -> None:
        pass


# ---------------------------------------------------------------------------
# Tool window launcher (each tool gets its own local Toplevel window)
# ---------------------------------------------------------------------------

import subprocess

def _find_real_tool(tool: str) -> str | None:
    """Look for a real installed tool executable.

    Checks common install locations and PATH. Returns the path if found,
    else None.
    """
    import shutil
    # Check PATH first
    found = shutil.which(tool)
    if found:
        return found

    # Common Windows install paths
    if sys.platform == "win32":
        candidates = {
            "wireshark": [
                "C:/Program Files/Wireshark/Wireshark.exe",
                "C:/Program Files (x86)/Wireshark/Wireshark.exe",
            ],
            "nmap": [
                "C:/Program Files (x86)/Nmap/nmap.exe",
                "C:/Program Files/Nmap/nmap.exe",
            ],
            "burpsuite": [
                "C:/Program Files/Burp Suite Community/burpsuite.exe",
                "C:/Program Files/PortSwigger/burpsuite.exe",
            ],
        }
        for path in candidates.get(tool, []):
            if Path(path).exists():
                return path

    return None


def _launch_tool_window(name: str, runner, ns_kwargs: dict) -> None:
    """Launch a tool in its own Toplevel window.

    Tries to launch the real installed tool first; falls back to the
    simulated version if the real tool is not found.
    """
    import argparse

    real_exe = _find_real_tool(name)

    win = tk.Toplevel()
    win.title(f"cyberterminal — {name}")
    win.geometry("900x600")
    win.configure(bg="#0a0a0a")

    # Output area
    text = scrolledtext.ScrolledText(
        win, bg="#0a0a0a", fg="#00ff00",
        insertbackground="#00ff00", font=("Consolas", 10),
        wrap=tk.WORD, padx=10, pady=10, bd=0, highlightthickness=0,
    )
    text.pack(fill=tk.BOTH, expand=True)
    text.configure(state=tk.DISABLED)

    def append(text_str: str) -> None:
        text.configure(state=tk.NORMAL)
        text.insert(tk.END, text_str)
        text.see(tk.END)
        text.configure(state=tk.DISABLED)

    if real_exe:
        # Launch the real tool as a subprocess
        append(f"[cyberterminal] Found real {name} at: {real_exe}\n")
        append(f"[cyberterminal] Launching {name} (real tool)...\n\n")

        def run_real() -> None:
            try:
                proc = subprocess.Popen(
                    [real_exe],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                )
                for line in proc.stdout:
                    win.after(0, lambda l=line: append(l))
                proc.wait()
                win.after(0, lambda: append(f"\n[cyberterminal] {name} exited with code {proc.returncode}\n"))
            except Exception as e:
                win.after(0, lambda: append(f"\n[cyberterminal] Error launching {name}: {e}\n"))
                win.after(0, lambda: append(f"[cyberterminal] Falling back to simulated {name}...\n\n"))
                run_simulated()

        def run_simulated() -> None:
            old_stdout = sys.stdout

            class Cap:
                def __init__(self, cb):
                    self.cb = cb
                    self.buf = ""
                def write(self, s):
                    self.buf += s
                    while "\n" in self.buf:
                        part, self.buf = self.buf.split("\n", 1)
                        win.after(0, lambda p=part: append(p + "\n"))
                    return len(s)
                def flush(self):
                    if self.buf:
                        win.after(0, lambda: append(self.buf))
                        self.buf = ""

            cap = Cap(append)
            sys.stdout = cap
            try:
                runner(argparse.Namespace(**ns_kwargs))
            finally:
                sys.stdout = old_stdout
                if cap.buf:
                    win.after(0, lambda: append(cap.buf))

        threading.Thread(target=run_real, daemon=True).start()
    else:
        # No real tool found — launch simulated version
        append(f"[cyberterminal] {name} not installed on this machine.\n")
        append(f"[cyberterminal] Launching simulated {name} instead...\n\n")
        install_hint = {
            "wireshark": "Install: winget install WiresharkFoundation.Wireshark  (or brew install wireshark / apt install wireshark)",
            "nmap": "Install: winget install Insecure.Nmap  (or brew install nmap / apt install nmap)",
            "burpsuite": "Install: winget install PortSwigger.BurpSuiteCommunity  (or download from portswigger.net)",
            "sqlmap": "Install: git clone https://github.com/sqlmapproject/sqlmap.git  (or brew install sqlmap / apt install sqlmap)",
            "hydra": "Install: brew install hydra  (or apt install hydra)",
            "nikto": "Install: brew install nikto  (or apt install nikto)",
        }.get(name, "")
        if install_hint:
            append(f"  {install_hint}\n")
        append("\n")

        old_stdout = sys.stdout

        class Cap:
            def __init__(self, cb):
                self.cb = cb
                self.buf = ""
            def write(self, s):
                self.buf += s
                while "\n" in self.buf:
                    part, self.buf = self.buf.split("\n", 1)
                    win.after(0, lambda p=part: append(p + "\n"))
                return len(s)
            def flush(self):
                if self.buf:
                    win.after(0, lambda: append(self.buf))
                    self.buf = ""

        cap = Cap(append)
        sys.stdout = cap
        try:
            runner(argparse.Namespace(**ns_kwargs))
        finally:
            sys.stdout = old_stdout
            if cap.buf:
                win.after(0, lambda: append(cap.buf))

    # Input line at bottom (typewriter style within the tool window)
    input_frame = tk.Frame(win, bg="#0a0a0a")
    input_frame.pack(fill=tk.X, side=tk.BOTTOM)

    prompt = tk.Label(
        input_frame, text=f"{name}> ", bg="#0a0a0a", fg="#00cc00",
        font=("Consolas", 10), anchor="w",
    )
    prompt.pack(side=tk.LEFT, padx=(10, 0), pady=5)

    entry = tk.Entry(
        input_frame, bg="#0a0a0a", fg="#00ff00",
        insertbackground="#00ff00", font=("Consolas", 10),
        bd=0, highlightthickness=1, highlightcolor="#00cc00",
    )
    entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10), pady=5)
    entry.focus_set()

    # Close handler
    def on_close() -> None:
        win.destroy()

    win.protocol("WM_DELETE_WINDOW", on_close)
    return win


# ---------------------------------------------------------------------------
# Emulated terminal window (typewriter-style input in the buffer)
# ---------------------------------------------------------------------------

class TerminalWindow:
    """Tkinter window hosting cyberterminal with typewriter-style input."""

    def __init__(self) -> None:
        self.root = tk.Tk()
        self.root.title("cyberterminal — offline cybersecurity practice")
        self.root.geometry("1100x700")
        self.root.minsize(800, 500)

        # Hacker theme colors
        self.bg_color = "#0a0a0a"
        self.fg_color = "#00ff00"
        self.accent_color = "#00cc00"
        self.dim_color = "#004400"

        self.root.configure(bg=self.bg_color)

        # State
        self.term = CyberTerminalGUI(output_callback=self._append_output)
        self.command_history: list[str] = []
        self.history_index = 0
        self.input_start = "1.0"  # index where current input line begins

        self._build_ui()
        self._setup_terminal()

    def _build_ui(self) -> None:
        # Menu bar
        menubar = tk.Menu(self.root, bg=self.bg_color, fg=self.fg_color)
        self.root.config(menu=menubar)

        file_menu = tk.Menu(menubar, tearoff=0, bg=self.bg_color, fg=self.fg_color)
        file_menu.add_command(label="Clear", command=self._clear_terminal)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self._quit)
        menubar.add_cascade(label="File", menu=file_menu)

        view_menu = tk.Menu(menubar, tearoff=0, bg=self.bg_color, fg=self.fg_color)
        view_menu.add_command(label="Help", command=self._show_help)
        view_menu.add_command(label="Tutorials Web", command=self._open_web)
        menubar.add_cascade(label="View", menu=view_menu)

        # Header bar with gear/styles icon (top right)
        header = tk.Frame(self.root, bg=self.bg_color)
        header.pack(fill=tk.X, side=tk.TOP)
        self.gear_btn = tk.Label(
            header, text="\u2699  Styles", bg=self.bg_color,
            fg=self.accent_color, font=("Consolas", 10, "bold"), cursor="hand2",
        )
        self.gear_btn.pack(side=tk.RIGHT, padx=10, pady=5)
        self.gear_btn.bind("<Button-1>", self._open_style_menu)

        # Main terminal output + input buffer (typewriter style, no entry box)
        self.term_font = tkfont.Font(family="Consolas", size=11)
        self.text = scrolledtext.ScrolledText(
            self.root,
            bg=self.bg_color,
            fg=self.fg_color,
            insertbackground=self.fg_color,
            font=self.term_font,
            wrap=tk.WORD,
            padx=10,
            pady=10,
            bd=0,
            highlightthickness=0,
        )
        self.text.pack(fill=tk.BOTH, expand=True)
        self.text.configure(state=tk.NORMAL)

        # Status bar at very bottom
        self.status_bar = tk.Label(
            self.root, text="Ready", bg="#0d0d0d", fg="#666666",
            font=("Consolas", 9), anchor="w", bd=1, relief=tk.SUNKEN,
        )
        self.status_bar.pack(fill=tk.X, side=tk.BOTTOM)

        # Bindings — typewriter input directly in the text buffer
        self.text.bind("<Return>", self._on_return)
        self.text.bind("<BackSpace>", self._on_backspace)
        self.text.bind("<Key>", self._on_key)
        self.text.bind("<Up>", self._on_up)
        self.text.bind("<Down>", self._on_down)
        self.text.bind("<Tab>", self._on_tab)
        self.text.focus_set()

    def _setup_terminal(self) -> None:
        self._append_output(self.term.intro)
        self._append_output("\n")
        self._start_input_line()
        self._update_status()

    # ----- typewriter input management -----

    def _start_input_line(self) -> None:
        """Place the prompt at the end of the buffer and mark input start."""
        self.text.insert(tk.END, "cyberterminal> ")
        self.text.see(tk.END)
        # input_start points to the first char the user can type (after prompt)
        self.input_start = self.text.index(tk.INSERT)

    def _get_input(self) -> str:
        """Read what the user has typed on the current input line."""
        return self.text.get(self.input_start, tk.END).rstrip("\n")

    def _clear_input(self) -> None:
        """Clear the current input line (after the prompt)."""
        self.text.delete(self.input_start, tk.END)

    def _append_output(self, text: str) -> None:
        if text == "__CLEAR__":
            self._clear_terminal()
            return
        if text == "__QUIT__":
            self.root.after(100, self.root.quit)
            return
        # Always append output at the end of the buffer
        self.text.insert(tk.END, text)
        self.text.see(tk.END)

    def _clear_terminal(self) -> None:
        self.text.delete("1.0", tk.END)
        self._append_output(self.term.intro)
        self._start_input_line()

    def _update_status(self) -> None:
        online = is_online()
        self.status_bar.config(
            text=f"{'ONLINE' if online else 'OFFLINE'}  |  "
                 f"Type 'help' for commands  |  "
                 f"Docs: {'available' if online else 'offline mode'}"
        )

    def _open_style_menu(self, event=None) -> None:
        """Open a small popup to change terminal colors/styles."""
        popup = tk.Toplevel(self.root)
        popup.title("Styles")
        popup.configure(bg=self.bg_color)
        popup.geometry("300x200")
        popup.transient(self.root)
        popup.grab_set()

        tk.Label(
            popup, text="Terminal Styles", bg=self.bg_color,
            fg=self.accent_color, font=("Consolas", 12, "bold"),
        ).pack(pady=(15, 10))

        def set_theme(bg, fg, accent):
            self.bg_color = bg
            self.fg_color = fg
            self.accent_color = accent
            self.root.configure(bg=bg)
            self.text.configure(bg=bg, fg=fg, insertbackground=fg)
            self.status_bar.configure(bg="#0d0d0d" if bg == "#0a0a0a" else bg)
            self.gear_btn.configure(bg=bg, fg=accent)
            popup.destroy()

        themes = [
            ("Green (default)", "#0a0a0a", "#00ff00", "#00cc00"),
            ("Amber", "#0a0a0a", "#ffaa00", "#ff8800"),
            ("Blue", "#0a0a0a", "#00aaaa", "#0088cc"),
            ("Matrix", "#000000", "#00ff00", "#008800"),
        ]
        for name, bg, fg, accent in themes:
            tk.Button(
                popup, text=name, bg="#1a1a1a", fg="#ffffff",
                font=("Consolas", 10),
                command=lambda b=bg, f=fg, a=accent: set_theme(b, f, a),
            ).pack(pady=3, padx=20, fill=tk.X)

    # ----- key event handlers (typewriter feel) -----

    def _on_key(self, event) -> str:
        # Prevent typing before the input line start
        if self.text.compare(tk.INSERT, "<", self.input_start):
            self.text.mark_set(tk.INSERT, tk.END)
            return "break"
        return None  # allow normal typing

    def _on_backspace(self, event) -> str:
        if self.text.compare(tk.INSERT, "<=", self.input_start):
            return "break"  # cannot delete the prompt
        return None  # allow normal backspace

    def _on_return(self, event) -> str:
        line = self._get_input().strip()
        self.text.insert(tk.END, "\n")
        self.text.see(tk.END)
        self.command_history.append(line)
        self.history_index = len(self.command_history)

        # Execute in thread so GUI never freezes
        threading.Thread(target=self._run_command, args=(line,), daemon=True).start()
        return "break"

    def _on_up(self, event) -> str:
        if not self.command_history:
            return "break"
        self._clear_input()
        if self.history_index > 0:
            self.history_index -= 1
        self.text.insert(self.input_start, self.command_history[self.history_index])
        return "break"

    def _on_down(self, event) -> str:
        if not self.command_history:
            return "break"
        self._clear_input()
        if self.history_index < len(self.command_history) - 1:
            self.history_index += 1
            self.text.insert(self.input_start, self.command_history[self.history_index])
        else:
            self.history_index = len(self.command_history)
        return "break"

    def _on_tab(self, event) -> str:
        text = self._get_input()
        if not text:
            return "break"
        matches = []
        for c in ["help", "tutorials", "tracks", "difficulty", "focus", "next",
                  "tutorial", "labs", "run", "submit", "progress", "docs",
                  "burp", "wireshark", "nmap", "sqlmap", "hydra", "nikto",
                  "clear", "cat", "grep", "exit"]:
            if c.startswith(text):
                matches.append(c)
        if len(matches) == 1:
            self._clear_input()
            self.text.insert(self.input_start, matches[0] + " ")
        return "break"

    def _run_command(self, line: str) -> None:
        old_stdout = sys.stdout
        try:
            class OutputCapture:
                def __init__(self, cb):
                    self.cb = cb
                    self.buf = ""
                def write(self, s):
                    self.buf += s
                    while "\n" in self.buf:
                        part, self.buf = self.buf.split("\n", 1)
                        self.root.after(0, lambda p=part: self._append_output(p + "\n"))
                    return len(s)
                def flush(self):
                    if self.buf:
                        self.root.after(0, lambda: self._append_output(self.buf))
                        self.buf = ""

            cap = OutputCapture(self._append_output)
            sys.stdout = cap
            try:
                stop = self.term.onecmd(line)
            finally:
                sys.stdout = old_stdout
                if cap.buf:
                    self.root.after(0, lambda: self._append_output(cap.buf))

            if stop:
                self.root.after(100, self.root.quit)
        except SystemExit:
            self.root.after(100, self.root.quit)
        except Exception as e:
            self.root.after(0, lambda: self._append_output(f"Error: {e}\n"))

        # Start a fresh input line after the command finishes
        self.root.after(0, self._start_input_line)
        self.root.after(0, self._update_status)

    def _show_help(self) -> None:
        self.term.do_help("")
        self._append_output("\n")

    def _open_web(self) -> None:
        self.term.do_help("web")

    def _quit(self) -> None:
        if messagebox.askokcancel("Quit", "Exit cyberterminal?"):
            self.root.quit()

    def run(self) -> int:
        self.root.protocol("WM_DELETE_WINDOW", self._quit)
        self.root.mainloop()
        return 0


# Backward-compat alias
CyberTerminal = CyberTerminalGUI


def main(argv=None) -> int:
    """Entry point for the windowed cyberterminal."""
    app = TerminalWindow()
    return app.run()


if __name__ == "__main__":
    raise SystemExit(main())
