"""Custom interactive shell environment (terminator-like) for cyberlab tools.

Provides a persistent in-app terminal where users can run cyberlab commands,
browse tutorials, and launch the Burp/Wireshark simulators. All offline.
"""

from __future__ import annotations

import argparse
import cmd
import shlex
import sys
import webbrowser
from pathlib import Path
from typing import Optional

from cyberlab.cli import build_parser
from cyberlab.modules.burp import run_burp
from cyberlab.modules.wireshark import run_wireshark
from cyberlab.tutorials.manager import TutorialManager


BANNER = r"""
  ____  _               _       ____                _   
 |  _ \| |             | |     / __ \              | |  
 | |_) | |__   ___  ___| |_   | |  | |_   _  __ _  | |_ 
 |  _ /| '_ \ / _ \/ __| __|  | |  | | | | |/ _` | | __|
 | | \ | | | |  __/ (__| |_   | |__| | |_| | (_| | | |_ 
 |_|  \_\._|  \___|\___|\__|   \____/ \__,_|\__,_|  \__|

cyberlab custom shell - offline cybersecurity practice environment
Type 'help' or '?' for commands. Type 'exit' or 'quit' to leave.
"""


class CyberlabShell(cmd.Cmd):
    """A custom CLI environment with its own command set."""

    intro = BANNER
    prompt = "cyberlab> "

    def __init__(self) -> None:
        super().__init__()
        self.manager = TutorialManager()
        self._cli_parser = build_parser()
        self.last_output: Optional[str] = None

    # ---------- built-in shell commands ----------

    def do_help(self, arg: str) -> None:
        """Show available shell commands or open the tutorial search webpage.

        usage: help
        usage: help <command>
        usage: help web        # opens HTML tutorial search page
        """
        arg = arg.strip().lower()
        if arg in ("web", "html", "search", "tutorials"):
            self._open_tutorial_webpage()
            return
        if arg:
            # Show help for a specific command
            method = getattr(self, f"do_{arg}", None)
            if method:
                print(method.__doc__ or f"No help for '{arg}'.")
            else:
                print(f"Unknown command: {arg}")
            return

        print("Available commands:")
        print()
        cmds = [
            ("help", "show this help | help web  -> open tutorial search page"),
            ("tutorials", "list available tutorials"),
            ("tutorial <id>", "show a tutorial's steps"),
            ("run <id>", "run a guided lab by id (e.g. run burp-01)"),
            ("labs", "list available labs"),
            ("burp", "launch simulated intercepting proxy"),
            ("wireshark", "launch simulated packet capture"),
            ("cli <args>", "run a raw cyberlab CLI command (e.g. cli labs)"),
            ("clear", "clear the screen"),
            ("exit / quit", "leave the shell"),
        ]
        for name, desc in cmds:
            print(f"  {name:<20} {desc}")
        print()
        print("Type 'help web' to browse tutorials in a browser.")

    def do_tutorials(self, arg: str) -> None:
        """List tutorials. Optionally filter by search text.

        usage: tutorials
        usage: tutorials <search text>
        """
        results = self.manager.search(arg) if arg else self.manager.all()
        if not results:
            print("No tutorials found.")
            return
        print("Tutorials:")
        print()
        for t in results:
            print(f"  {t.id:<18} [{t.category:<8}] {t.title}")
            print(f"                   {t.description}")
        print()
        print("Use: tutorial <id>   to view steps")
        print("     help web        to open the search webpage")

    def do_tutorial(self, arg: str) -> None:
        """Show the steps of a tutorial.

        usage: tutorial <id>
        Example: tutorial burp-basics
        """
        t = self.manager.get(arg.strip())
        if not t:
            print(f"Unknown tutorial: {arg}")
            print("Run 'tutorials' to list available tutorials.")
            return
        print(f"=== {t.title} ===")
        print(f"Module: {t.module}  |  Category: {t.category}")
        print(t.description)
        print()
        for i, step in enumerate(t.steps, 1):
            print(f"  {i}. {step.description}")
            print(f"     $ {step.command}")
            if step.notes:
                print(f"     # {step.notes}")
            print()

    def do_run(self, arg: str) -> None:
        """Run a guided lab by ID.

        usage: run <id>
        Example: run burp-01
        """
        from cyberlab.core import registry
        scenario = registry.get(arg.strip())
        if scenario is None:
            print(f"Unknown lab: {arg}")
            print("Run 'labs' to see available labs.")
            return
        print(f"=== {scenario.title} ===")
        print(scenario.description)
        print()
        scenario.run()

    def do_labs(self, arg: str) -> None:
        """List available practice labs."""
        from cyberlab.core import registry
        scenarios = registry.list()
        if not scenarios:
            print("No labs registered yet.")
            return
        print("Available labs:")
        print()
        print(f"{'ID':<12} {'Module':<14} {'Title'}")
        print("-" * 40)
        for s in scenarios:
            tags = f" [{','.join(s.tags)}]" if s.tags else ""
            print(f"{s.id:<12} {s.module:<14} {s.title}{tags}")
        print()

    def do_burp(self, arg: str) -> None:
        """Launch the simulated intercepting proxy (BurpSuite-style).

        usage: burp [--target URL]
        """
        parser = argparse.ArgumentParser(prog="burp")
        parser.add_argument("--target", default="http://lab.local")
        try:
            args = parser.parse_args(shlex.split(arg))
        except SystemExit:
            return
        run_burp(args)

    def do_wireshark(self, arg: str) -> None:
        """Launch the simulated packet capture (Wireshark-style).

        usage: wireshark [--packets N] [--export FILE]
        """
        parser = argparse.ArgumentParser(prog="wireshark")
        parser.add_argument("--packets", type=int, default=25)
        parser.add_argument("--export", metavar="FILE")
        try:
            args = parser.parse_args(shlex.split(arg))
        except SystemExit:
            return
        run_wireshark(args)

    def do_cli(self, arg: str) -> None:
        """Run a raw cyberlab CLI command inside the shell.

        usage: cli <args>
        Example: cli labs
                 cli burp --help
        """
        if not arg.strip():
            print("usage: cli <args>")
            return
        try:
            argv = shlex.split(arg)
            self._cli_parser.parse_args(argv)
        except SystemExit:
            return

    def do_clear(self, arg: str) -> None:
        """Clear the screen."""
        import os
        os.system("cls" if sys.platform == "win32" else "clear")

    def do_exit(self, arg: str) -> None:
        """Leave the shell."""
        print("Goodbye.")
        return True

    def do_quit(self, arg: str) -> None:
        """Leave the shell."""
        return self.do_exit(arg)

    def emptyline(self) -> None:
        # Do nothing on empty line
        pass

    # ---------- helpers ----------

    def _open_tutorial_webpage(self) -> None:
        html_path = Path(__file__).resolve().parent.parent / "tutorials" / "index.html"
        if not html_path.exists():
            print(f"Tutorial webpage not found: {html_path}")
            return
        url = html_path.as_uri()
        try:
            webbrowser.open(url, new=2)
            print(f"Opened tutorial search page: {url}")
        except Exception as e:
            print(f"Could not open browser: {e}")
            print(f"Open manually: {url}")


def main(argv=None) -> int:
    shell = CyberlabShell()
    shell.cmdloop()
    return 0
