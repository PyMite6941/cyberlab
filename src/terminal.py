"""cyberterminal — emulated terminal for offline cybersecurity practice.

A real-feeling terminal window: type directly in the buffer (no separate
entry box), lines are iterable like a real terminal, and every tool
(burp, wireshark, nmap, sqlmap, hydra, nikto, cookie, webscan, osint,
auth, siem) launches in its own window with fully simulated, randomized
packets/traffic - nothing touches the network.
"""

from __future__ import annotations

import cmd
import contextlib
import io
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
from src.modules.auth import AuthShell
from src.modules.burp import BurpShell
from src.modules.hydra import HydraShell
from src.modules.nikto import NiktoShell
from src.modules.nmap import NmapShell
from src.modules.cookie import CookieShell
from src.modules.webscan import WebScanShell
from src.modules.osint import OsintShell
from src.modules.siem import SIEMShell
from src.modules.sqlmap import SqlmapShell
from src.modules.wireshark import WiresharkShell
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

    # Looks like the Linux shell security tools are used from, with a fixed
    # lab user so every learner (and every tutorial screenshot) sees the same.
    prompt = "student@cyberlab:~$ "

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
            ("burp", "launch simulated intercepting proxy (own window)"),
            ("wireshark", "launch simulated packet capture (own window)"),
            ("nmap", "launch simulated network scanner (own window)"),
            ("sqlmap", "launch simulated SQL injection tool (own window)"),
            ("hydra", "launch simulated password cracker (own window)"),
            ("nikto", "launch simulated web vulnerability scanner (own window)"),
            ("cookie", "launch simulated cookie security scanner (own window)"),
            ("webscan", "launch simulated website scanner (own window)"),
            ("osint", "launch simulated OSINT tool (online only)"),
            ("auth", "launch simulated authentication security lab (own window)"),
            ("siem", "launch simulated SIEM log analysis lab (own window)"),
            ("clear", "clear the screen"),
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
        self._selected_tutorial = tid
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
            _launch_tool_window(lab.module)
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
        _launch_tool_window("burp")

    def do_wireshark(self, arg: str) -> None:
        """Launch simulated packet capture (Wireshark-style) in its own window."""
        self._writeln("Launching Wireshark simulator in a new window...")
        _launch_tool_window("wireshark")

    def do_nmap(self, arg: str) -> None:
        """Launch simulated network scanner (Nmap-style) in its own window."""
        self._writeln("Launching Nmap simulator in a new window...")
        _launch_tool_window("nmap")

    def do_sqlmap(self, arg: str) -> None:
        """Launch simulated SQL injection tool (SQLmap-style) in its own window."""
        self._writeln("Launching SQLmap simulator in a new window...")
        _launch_tool_window("sqlmap")

    def do_hydra(self, arg: str) -> None:
        """Launch simulated password cracker (Hydra-style) in its own window."""
        self._writeln("Launching Hydra simulator in a new window...")
        _launch_tool_window("hydra")

    def do_nikto(self, arg: str) -> None:
        """Launch simulated web vulnerability scanner (Nikto-style) in its own window."""
        self._writeln("Launching Nikto simulator in a new window...")
        _launch_tool_window("nikto")

    def do_cookie(self, arg: str) -> None:
        """Launch simulated cookie security scanner in its own window."""
        self._writeln("Launching Cookie security scanner in a new window...")
        _launch_tool_window("cookie")

    def do_webscan(self, arg: str) -> None:
        """Launch simulated website scanner in its own window."""
        self._writeln("Launching Website scanner in a new window...")
        _launch_tool_window("webscan")

    def do_osint(self, arg: str) -> None:
        """Launch simulated OSINT tool (online only)."""
        if not is_online():
            self._writeln("OSINT requires network access. You are currently OFFLINE.")
            self._writeln("Connect to the internet and try again.")
            return
        self._writeln("Launching OSINT simulator in a new window...")
        _launch_tool_window("osint")

    def do_auth(self, arg: str) -> None:
        """Launch simulated authentication security lab in its own window."""
        self._writeln("Launching Authentication security lab in a new window...")
        _launch_tool_window("auth")

    def do_siem(self, arg: str) -> None:
        """Launch simulated SIEM log analysis lab in its own window."""
        self._writeln("Launching SIEM log analysis lab in a new window...")
        _launch_tool_window("siem")

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

# Simulator shells by command name (also the `module` of each lab).
TOOL_SHELLS = {
    "auth": AuthShell,
    "burp": BurpShell,
    "cookie": CookieShell,
    "hydra": HydraShell,
    "nikto": NiktoShell,
    "nmap": NmapShell,
    "osint": OsintShell,
    "siem": SIEMShell,
    "sqlmap": SqlmapShell,
    "webscan": WebScanShell,
    "wireshark": WiresharkShell,
}


def run_tool_line(shell: cmd.Cmd, line: str) -> tuple[str, bool]:
    """Run one line in a simulator shell; return (output, whether it quit).

    The simulators are cmd.Cmd shells. Their cmdloop() reads the console, not
    a window, so the tool window feeds them one line at a time instead.
    """
    out = io.StringIO()
    shell.stdout = out  # cmd's own messages, e.g. "*** Unknown syntax"
    with contextlib.redirect_stdout(out):  # the simulators' print() calls
        stop = shell.postcmd(shell.onecmd(shell.precmd(line)), line)
    return out.getvalue(), bool(stop)


def _launch_tool_window(name: str) -> None:
    """Launch a simulator tool in its own Toplevel window."""
    shell = TOOL_SHELLS[name]()
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

    def append(text_str: str) -> None:
        text.configure(state=tk.NORMAL)
        text.insert(tk.END, text_str)
        text.see(tk.END)
        text.configure(state=tk.DISABLED)

    def on_enter(event) -> str:
        line = entry.get().strip()
        entry.delete(0, tk.END)
        if not line:
            return "break"
        append(f"{name}> {line}\n")
        output, stop = run_tool_line(shell, line)
        append(output)
        if stop:
            win.after(300, win.destroy)
        return "break"

    entry.bind("<Return>", on_enter)
    if shell.intro:
        append(shell.intro if shell.intro.endswith("\n") else shell.intro + "\n")

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
        # Commands run on a worker thread; their output is handed to the Tk
        # thread so it lands in order with print() output and the next prompt.
        self.term = CyberTerminalGUI(output_callback=self._post_output)
        self.command_history: list[str] = []
        self.history_index = 0
        self.awaiting_input = False  # a prompt is showing and accepts typing

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
    # The prompt and what the user types sit on the last line of the buffer.
    # The "input_start" mark sits right after the prompt (left gravity, so
    # typed text goes after it). The mark used to sit before the prompt, so
    # every command was read as "yberterminal> <command>" and failed.

    def _start_input_line(self) -> None:
        """Show a fresh prompt on a new last line."""
        if self.awaiting_input:
            return
        if self.text.compare("end-1c", "!=", "end-1c linestart"):
            self.text.insert("end-1c", "\n")
        self.text.insert("end-1c", self.term.prompt)
        self.text.mark_set("input_start", "end-1c")
        self.text.mark_gravity("input_start", tk.LEFT)
        self.text.mark_set(tk.INSERT, "end-1c")
        self.text.see(tk.END)
        self.awaiting_input = True

    def _get_input(self) -> str:
        """Read what the user has typed after the prompt."""
        return self.text.get("input_start", "end-1c")

    def _clear_input(self) -> None:
        """Clear what the user has typed after the prompt."""
        self.text.delete("input_start", "end-1c")

    def _post_output(self, text: str) -> None:
        """Queue output for the Tk thread (safe to call from the command thread)."""
        self.root.after(0, self._append_output, text)

    def _append_output(self, text: str) -> None:
        if text == "__CLEAR__":
            self._clear_terminal()
            return
        if text == "__QUIT__":
            self.root.after(100, self.root.quit)
            return
        if self.awaiting_input:
            # A prompt is showing: put the output on the lines above it.
            if not text.endswith("\n"):
                text += "\n"
            self.text.insert("input_start linestart", text)
        else:
            self.text.insert("end-1c", text)
        self.text.see(tk.END)

    def _clear_terminal(self) -> None:
        self.text.configure(state=tk.NORMAL)
        self.text.delete("1.0", tk.END)
        prompt_was_showing = self.awaiting_input
        self.awaiting_input = False
        self._append_output(self.term.intro)
        if prompt_was_showing:  # cleared from the menu; a command run will re-prompt itself
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
        if not event.char:
            return None  # arrows, modifiers, shortcuts
        if not self.awaiting_input:
            return "break"  # a command is still running
        # Typing anywhere above the prompt types at the end of the input line
        if self.text.compare(tk.INSERT, "<", "input_start"):
            self.text.mark_set(tk.INSERT, "end-1c")
        return None  # allow normal typing

    def _on_backspace(self, event) -> str:
        if not self.awaiting_input or self.text.compare(tk.INSERT, "<=", "input_start"):
            return "break"  # cannot delete the prompt or past output
        return None  # allow normal backspace

    def _on_return(self, event) -> str:
        if not self.awaiting_input:
            return "break"  # a command is still running
        line = self._get_input().strip()
        self.awaiting_input = False
        # The prompt and the typed line stay in the buffer as the command's echo.
        self.text.insert("end-1c", "\n")
        if not line:
            self._start_input_line()
            return "break"
        self.command_history.append(line)
        self.history_index = len(self.command_history)

        # Execute in thread so GUI never freezes
        threading.Thread(target=self._run_command, args=(line,), daemon=True).start()
        return "break"

    def _on_up(self, event) -> str:
        if not self.command_history or not self.awaiting_input:
            return "break"
        self._clear_input()
        if self.history_index > 0:
            self.history_index -= 1
        self.text.insert("input_start", self.command_history[self.history_index])
        return "break"

    def _on_down(self, event) -> str:
        if not self.command_history or not self.awaiting_input:
            return "break"
        self._clear_input()
        if self.history_index < len(self.command_history) - 1:
            self.history_index += 1
            self.text.insert("input_start", self.command_history[self.history_index])
        else:
            self.history_index = len(self.command_history)
        return "break"

    def _on_tab(self, event) -> str:
        if not self.awaiting_input:
            return "break"
        text = self._get_input()
        if not text:
            return "break"
        matches = []
        for c in ["help", "tutorials", "tracks", "difficulty", "focus", "next",
                  "tutorial", "labs", "run", "submit", "progress", "docs",
                  "burp", "wireshark", "nmap", "sqlmap", "hydra", "nikto",
                  "cookie", "webscan", "osint", "auth", "siem", "clear", "exit"]:
            if c.startswith(text):
                matches.append(c)
        if len(matches) == 1:
            self._clear_input()
            self.text.insert("input_start", matches[0] + " ")
        return "break"

    def _run_command(self, line: str) -> None:
        old_stdout = sys.stdout
        try:
            # Inside this class `self` is the capture, not the window: it
            # used to call self.root / self._append_output, which made every
            # print() from a command raise AttributeError.
            class OutputCapture:
                def __init__(self, cb):
                    self.cb = cb
                    self.buf = ""
                def write(self, s):
                    self.buf += s
                    while "\n" in self.buf:
                        part, self.buf = self.buf.split("\n", 1)
                        self.cb(part + "\n")
                    return len(s)
                def flush(self):
                    if self.buf:
                        self.cb(self.buf)
                        self.buf = ""

            cap = OutputCapture(self._post_output)
            sys.stdout = cap
            self.term.stdout = cap  # cmd's own messages, e.g. "*** Unknown syntax"
            try:
                stop = self.term.onecmd(line)
            finally:
                sys.stdout = old_stdout
                cap.flush()

            if stop:
                self.root.after(100, self.root.quit)
        except SystemExit:
            self.root.after(100, self.root.quit)
        except Exception as e:
            self._post_output(f"Error: {e}\n")  # format now; `e` is cleared after this block

        # Start a fresh input line once the queued output has been shown
        self.root.after(0, self._start_input_line)
        self.root.after(0, self._update_status)

    def _show_help(self) -> None:
        self.term.do_help("")
        self._post_output("\n")

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
