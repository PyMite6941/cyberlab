"""cyberterminal — custom emulated terminal for offline cybersecurity practice.

Running `cyberterminal` launches the emulated terminal shell directly. There is
no separate `cyberlab` command. All commands live inside the terminal:

    help            list commands | help web  -> open tutorial search page
    tutorials       list available tutorials (filter by track/difficulty)
    tutorial <id>   show a tutorial's steps
    tracks          list learning tracks
    difficulty <easy|medium|hard|all>  filter tutorials by difficulty
    labs            list available practice labs
    run <id>        run a guided lab by id
    submit <flag>   submit a flag for the selected tutorial
    progress        show completion progress
    burp            launch simulated intercepting proxy
    wireshark       launch simulated packet capture
    nmap            launch simulated network scanner
    sqlmap          launch simulated SQL injection tool
    hydra           launch simulated password cracker
    nikto           launch simulated web vulnerability scanner
    cookie          launch simulated cookie security scanner
    webscan         launch simulated website scanner
    auth            launch simulated authentication security lab
    siem            launch simulated SIEM log analysis lab
    clear           clear the screen
    exit / quit     leave the terminal

All traffic is simulated locally. Nothing touches the network.
"""

from __future__ import annotations

from typing import List, Optional

import argparse
import cmd
import shlex
import sys
import webbrowser
from pathlib import Path

from src.core import lab_registry, track_registry, get_progress, load_progress, record_submission
from src.core.docs import is_online, get_docs_for_tool, get_all_docs, download_doc, get_offline_docs, get_hint_for_tool, is_tool_available
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

# Import modules so their scenarios self-register.
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

def _get_banner() -> str:
    """Build banner with ASCII logo and online/offline status indicator."""
    status = "ONLINE" if is_online() else "OFFLINE"
    status_color = "\033[92m" if is_online() else "\033[93m"
    reset = "\033[0m"
    try:
        logo_path = Path(__file__).resolve().parent / "ascii_logo.txt"
        logo = logo_path.read_text(encoding="utf-8")
    except Exception:
        logo = ""
    return rf"""
{logo}
{reset}Network: {status_color}{status}{reset}  |  Type 'help' or '?' for commands. Type 'exit' or 'quit' to leave.
"""


class CyberTerminal(cmd.Cmd):
    """The custom emulated terminal. This IS the program."""

    prompt = "cyberterminal> "

    def __init__(self) -> None:
        super().__init__()
        self.intro = _get_banner()
        self.manager = TutorialManager()
        self._selected_tutorial: Optional[str] = None
        load_progress()

    # ---------- built-in terminal commands ----------

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
                print(method.__doc__ or f"No help for '{arg}'.")
            else:
                print(f"Unknown command: {arg}")
            return

        print("cyberterminal commands:")
        print()
        cmds = [
            ("help", "show this help | help web  -> open tutorial search page"),
            ("tutorials", "list available tutorials"),
            ("tracks", "list learning tracks"),
            ("difficulty <easy|medium|hard|all>", "filter tutorials by difficulty"),
            ("focus <id>", "focus on one tutorial at a time"),
            ("next", "show next recommended tutorial"),
            ("tutorial <id>", "show a tutorial's steps"),
            ("labs", "list available practice labs"),
            ("run <id>", "run a guided lab by id (e.g. run web-sqli-01)"),
            ("submit <flag>", "submit a flag for the selected tutorial"),
            ("progress", "show completion progress"),
            ("docs", "documentation: list, search, download, status"),
            ("burp", "launch simulated intercepting proxy"),
            ("wireshark", "launch simulated packet capture"),
            ("nmap", "launch simulated network scanner"),
            ("sqlmap", "launch simulated SQL injection tool"),
            ("hydra", "launch simulated password cracker"),
            ("nikto", "launch simulated web vulnerability scanner"),
            ("cookie", "launch simulated cookie security scanner"),
            ("webscan", "launch simulated website scanner"),
            ("osint", "launch simulated OSINT tool"),
            ("auth", "launch simulated authentication security lab"),
            ("siem", "launch simulated SIEM log analysis lab"),
            ("clear", "clear the screen"),
            ("exit / quit", "leave the terminal"),
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

    def do_labs(self, arg: str) -> None:
        """List available practice labs."""
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

    def do_run(self, arg: str) -> None:
        """Run a guided lab by ID.

        usage: run <id>
        Example: run burp-01
        """
        scenario = registry.get(arg.strip())
        if scenario is None:
            print(f"Unknown lab: {arg}")
            print("Run 'labs' to see available labs.")
            return
        print(f"=== {scenario.title} ===")
        print(scenario.description)
        print()
        scenario.run()

    def do_burp(self, arg: str) -> None:
        """Launch the simulated intercepting proxy (BurpSuite-style).

        usage: burp [--target URL]
        """
        parser = argparse.ArgumentParser(prog="burp", add_help=False)
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
        parser = argparse.ArgumentParser(prog="wireshark", add_help=False)
        parser.add_argument("--packets", type=int, default=25)
        parser.add_argument("--export", metavar="FILE")
        try:
            args = parser.parse_args(shlex.split(arg))
        except SystemExit:
            return
        run_wireshark(args)

    def do_tracks(self, arg: str) -> None:
        """List available learning tracks.

        usage: tracks
        """
        tracks = track_registry.list_tracks()
        if not tracks:
            print("No tracks registered yet.")
            return
        print("Learning tracks:")
        print()
        for tr in tracks:
            completed = track_registry.completed_count(tr.id)
            total = len(tr.tutorials)
            print(f"  {tr.id:<25} {tr.title}")
            print(f"                   {tr.description}")
            print(f"                   Progress: {completed}/{total} tutorials completed")
        print()

    def do_difficulty(self, arg: str) -> None:
        """Filter tutorials by difficulty.

        usage: difficulty
        usage: difficulty easy
        usage: difficulty medium
        usage: difficulty hard
        usage: difficulty all
        """
        diff = arg.strip().lower()
        if not diff or diff == "all":
            print("Current difficulty filter: all")
            print("Usage: difficulty <easy|medium|hard|all>")
            return
        if diff not in ("easy", "medium", "hard"):
            print(f"Unknown difficulty: {diff}")
            print("Valid: easy, medium, hard, all")
            return
        tuts = self.manager.by_difficulty(diff)
        if not tuts:
            print(f"No tutorials at {diff} difficulty.")
            return
        print(f"Tutorials at {diff} difficulty:")
        print()
        for t in tuts:
            completed = " [COMPLETED]" if track_registry.is_completed(t.id) else ""
            print(f"  {t.id:<25} [{t.track:<22}] {t.title}{completed}")
            print(f"                   {t.description}")
        print()

    def do_tutorials(self, arg: str) -> None:
        """List tutorials. Optionally filter by search text, track, or difficulty.

        usage: tutorials
        usage: tutorials <search text>
        usage: tutorials --track web-security
        usage: tutorials --difficulty easy
        """
        parser = argparse.ArgumentParser(prog="tutorials", add_help=False)
        parser.add_argument("--track", default=None)
        parser.add_argument("--difficulty", default=None)
        parser.add_argument("query", nargs="?")
        try:
            args_ns = parser.parse_args(shlex.split(arg))
        except SystemExit:
            return

        results = self.manager.search(
            args_ns.query or "",
            track=args_ns.track,
            difficulty=args_ns.difficulty,
        )
        if not results:
            print("No tutorials found.")
            print()
            print("Use: tracks          to list learning tracks")
            print("     difficulty <easy|medium|hard>  to filter by difficulty")
            print("     tutorial <id>   to view steps")
            return
        print("Tutorials:")
        print()
        for t in results:
            completed = " [COMPLETED]" if track_registry.is_completed(t.id) else ""
            print(f"  {t.id:<25} [{t.category:<8}] {t.difficulty:<8} {t.title}{completed}")
            print(f"                   {t.description}")
        print()
        print("Use: tutorial <id>   to view steps")
        print("     help web        to open the search webpage")

    def do_tutorial(self, arg: str) -> None:
        """Show the steps of a tutorial and select it for flag submission.

        usage: tutorial <id>
        Example: tutorial web-sqli-01
        """
        t = self.manager.get(arg.strip())
        if not t:
            print(f"Unknown tutorial: {arg}")
            print("Run 'tutorials' to list available tutorials.")
            return
        # Progress gating: medium requires easy complete, hard requires medium complete
        if t.difficulty == "medium":
            easy_done = any(
                track_registry.is_completed(e.id) for e in self.manager.all() if e.difficulty == "easy"
            )
            if not easy_done:
                print(f"Locked: '{t.title}' requires completing an 'easy' tutorial first.")
                print("Complete an easy tutorial, then return here.")
                print()
                easy_tuts = self.manager.by_difficulty("easy")
                print("Available easy tutorials:")
                for et in easy_tuts[:5]:
                    print(f"  {et.id}: {et.title}")
                return
        elif t.difficulty == "hard":
            medium_done = any(
                track_registry.is_completed(e.id) for e in self.manager.all() if e.difficulty == "medium"
            )
            if not medium_done:
                print(f"Locked: '{t.title}' requires completing a 'medium' tutorial first.")
                print("Complete a medium tutorial, then return here.")
                print()
                medium_tuts = self.manager.by_difficulty("medium")
                print("Available medium tutorials:")
                for mt in medium_tuts[:5]:
                    print(f"  {mt.id}: {mt.title}")
                return
        self._selected_tutorial = t.id
        print(f"=== {t.title} ===")
        print(f"Module: {t.module}  |  Category: {t.category}")
        print(f"Vulnerability: {t.vulnerability}  |  Difficulty: {t.difficulty}")
        print(f"Track: {t.track}")
        print(t.description)
        print()
        for i, step in enumerate(t.steps, 1):
            print(f"  {i}. {step.description}")
            print(f"     $ {step.command}")
            if step.notes:
                print(f"     # {step.notes}")
            print()
        if t.flag:
            print(f"Submit your flag with:  submit <flag>")
        print()

    def do_labs(self, arg: str) -> None:
        """List available practice labs."""
        scenarios = lab_registry.list()
        if not scenarios:
            print("No labs registered yet.")
            return
        print("Available labs:")
        print()
        print(f"{'ID':<25} {'Module':<14} {'Title'}")
        print("-" * 55)
        for s in scenarios:
            tags = f" [{','.join(s.tags)}]" if s.tags else ""
            print(f"{s.id:<25} {s.module:<14} {s.title}{tags}")
        print()

    def do_run(self, arg: str) -> None:
        """Run a guided lab by ID.

        usage: run <id>
        Example: run web-sqli-01
        """
        scenario = lab_registry.get(arg.strip())
        if scenario is None:
            print(f"Unknown lab: {arg}")
            print("Run 'labs' to see available labs.")
            return
        print(f"=== {scenario.title} ===")
        print(scenario.description)
        print()
        scenario.run()

    def do_submit(self, arg: str) -> None:
        """Submit a flag for the selected tutorial.

        usage: submit <flag>
        Example: submit <your-answer>
        """
        if not self._selected_tutorial:
            print("No tutorial selected. Use 'tutorial <id>' first.")
            return
        if not arg.strip():
            print("usage: submit <flag>")
            return
        correct = record_submission(self._selected_tutorial, arg.strip())
        if correct:
            print("Correct! Tutorial completed.")
            self.do_next("")
        else:
            print("Incorrect flag. Try again.")

    def do_progress(self, arg: str) -> None:
        """Show completion progress."""
        prog = get_progress()
        print("Progress:")
        print()
        print(f"  Completed: {prog['completed']} / {prog['total']} tutorials")
        print(f"  Percentage: {prog['percent']}%")
        print()

    def do_focus(self, arg: str) -> None:
        """Focus mode: show only one tutorial at a time.

        usage: focus <id>
        Example: focus web-sqli-01
        """
        t = self.manager.get(arg.strip())
        if not t:
            print(f"Unknown tutorial: {arg}")
            print("Run 'tutorials' to list available tutorials.")
            return
        self._selected_tutorial = t.id
        print("=" * 60)
        print(f"  FOCUS MODE: {t.title}")
        print("=" * 60)
        print(f"Module: {t.module}  |  Category: {t.category}")
        print(f"Difficulty: {t.difficulty}")
        print(f"Vulnerability: {t.vulnerability}")
        print()
        print(t.description)
        print()
        print("Steps:")
        for i, step in enumerate(t.steps, 1):
            print(f"  {i}. {step.description}")
            print(f"     $ {step.command}")
            if step.notes:
                print(f"     # {step.notes}")
            print()
        print("=" * 60)
        print(f"Type 'submit <flag>' when complete, or 'focus' to exit focus mode.")
        print("=" * 60)

    def do_next(self, arg: str) -> None:
        """Show the next recommended tutorial based on your progress."""
        all_tuts = self.manager.all()
        if not all_tuts:
            print("No tutorials available.")
            return

        completed_ids = set()
        for t in all_tuts:
            if track_registry.is_completed(t.id):
                completed_ids.add(t.id)

        if not completed_ids:
            print("No tutorials completed yet.")
            print("Start with an 'easy' tutorial:")
            easy = self.manager.by_difficulty("easy")
            for t in easy[:3]:
                print(f"  {t.id}: {t.title}")
            print()
            print("Use 'tutorial <id>' to view a tutorial's steps.")
            return

        difficulty_order = {"easy": 1, "medium": 2, "hard": 3}
        next_tuts = []
        for t in all_tuts:
            if t.id not in completed_ids:
                if t.difficulty == "easy":
                    next_tuts.append(t)
                elif t.difficulty == "medium" and any(
                    track_registry.is_completed(e.id) for e in all_tuts if e.difficulty == "easy"
                ):
                    next_tuts.append(t)
                elif t.difficulty == "hard" and any(
                    track_registry.is_completed(e.id) for e in all_tuts if e.difficulty == "medium"
                ):
                    next_tuts.append(t)

        if not next_tuts:
            print("All available tutorials are complete! Great job.")
            return

        next_tuts.sort(key=lambda t: (difficulty_order.get(t.difficulty, 99), t.track, t.id))

        print("Next recommended tutorial:")
        print()
        t = next_tuts[0]
        print(f"  {t.id}: {t.title}")
        print(f"    Module: {t.module}  |  Category: {t.category}")
        print(f"    Difficulty: {t.difficulty}")
        print(f"    Description: {t.description}")
        print()
        print(f"Type 'tutorial {t.id}' to view steps, or 'focus {t.id}' for focus mode.")

    def do_docs(self, arg: str) -> None:
        """Manage documentation: list, search, download, status.

        usage: docs                    # list all documentation
        usage: docs search <text>      # search documentation
        usage: docs download <id>      # download a specific doc (requires online)
        usage: docs download-all       # download all docs (requires online)
        usage: docs status             # show online/offline status and doc availability
        usage: docs <tool>             # show docs for a specific tool (nmap, sqlmap, hydra, nikto, burp, wireshark, auth, siem)
        """
        parts = shlex.split(arg)
        if not parts:
            self._docs_list()
            return
        cmd = parts[0].lower()
        if cmd == "search" and len(parts) > 1:
            self._docs_search(" ".join(parts[1:]))
        elif cmd == "download" and len(parts) > 1:
            self._docs_download(parts[1])
        elif cmd == "download-all":
            self._docs_download_all()
        elif cmd == "status":
            self._docs_status()
        else:
            self._docs_for_tool(parts[0])

    def _docs_list(self) -> None:
        """List all available documentation."""
        docs_list = get_all_docs()
        online = is_online()
        print(f"Documentation catalog ({len(docs_list)} docs)  |  Network: {'ONLINE' if online else 'OFFLINE'}")
        print()
        print(f"{'ID':<20} {'Title':<35} {'Tool':<12} {'Status'}")
        print("-" * 75)
        for d in docs_list:
            status = "cached" if d["available_offline"] else ("downloadable" if online else "unavailable")
            print(f"{d['id']:<20} {d['title']:<35} {d['tool']:<12} {status}")
        print()
        print("Usage: docs download <id>   to download a doc")
        print("       docs download-all    to download all docs (requires online)")
        print("       docs search <text>   to search documentation")
        print("       docs <tool>          to show docs for a specific tool")

    def _docs_search(self, query: str) -> None:
        """Search documentation by title, tool, or description."""
        q = query.lower()
        results = [d for d in get_all_docs() if q in d["title"].lower() or q in d["tool"].lower() or q in d["description"].lower()]
        if not results:
            print(f"No documentation matching '{query}'.")
            return
        print(f"Documentation search results for '{query}': ({len(results)} found)")
        print()
        print(f"{'ID':<20} {'Title':<35} {'Tool':<12} {'Status'}")
        print("-" * 75)
        for d in results:
            status = "cached" if d["available_offline"] else ("downloadable" if is_online() else "unavailable")
            print(f"{d['id']:<20} {d['title']:<35} {d['tool']:<12} {status}")
        print()

    def _docs_download(self, doc_id: str) -> None:
        """Download a specific documentation doc."""
        doc = next((d for d in get_all_docs() if d["id"] == doc_id), None)
        if not doc:
            print(f"Documentation not found: {doc_id}")
            print("Use 'docs' to list available documentation.")
            return
        if doc["available_offline"]:
            print(f"'{doc_id}' is already cached locally.")
            return
        if not is_online():
            print("Cannot download: network is OFFLINE.")
            print("Connect to the internet and try again, or use cached docs only.")
            return
        print(f"Downloading {doc['title']}...")
        if download_doc(doc):
            print(f"Downloaded: {doc['title']} -> cached locally")
        else:
            print(f"Failed to download: {doc['title']}")

    def _docs_download_all(self) -> None:
        """Download all documentation."""
        if not is_online():
            print("Cannot download: network is OFFLINE.")
            return
        docs_list = get_all_docs()
        to_download = [d for d in docs_list if not d["available_offline"]]
        if not to_download:
            print("All documentation is already cached locally.")
            return
        print(f"Downloading {len(to_download)} documentation files...")
        for d in to_download:
            if download_doc(d):
                print(f"  [OK] {d['title']}")
            else:
                print(f"  [FAIL] {d['title']}")
        print(f"Download complete. {len(get_offline_docs())}/{len(docs_list)} docs cached.")

    def _docs_status(self) -> None:
        """Show online/offline status and documentation availability."""
        online = is_online()
        all_docs = get_all_docs()
        offline_docs = get_offline_docs()
        print("Documentation Status")
        print("=" * 50)
        print(f"Network: {'ONLINE' if online else 'OFFLINE'}")
        print(f"Docs cached: {len(offline_docs)} / {len(all_docs)}")
        print()
        print("Per-tool documentation availability:")
        tools = ["burp", "wireshark", "nmap", "sqlmap", "hydra", "nikto", "cookie", "webscan", "osint", "auth", "siem"]
        for tool in tools:
            tool_docs = get_docs_for_tool(tool)
            if not tool_docs:
                continue
            cached = [d for d in tool_docs if d["available_offline"]]
            status = "cached" if cached else ("downloadable" if online else "unavailable")
            print(f"  {tool:<12} {tool_docs[0]['title']:<35} {status}")
        print()
        print("Usage: docs download <id>   to download a specific doc")
        print("       docs download-all    to download all docs (requires online)")
        print("       docs search <text>   to search documentation")
        print("       docs <tool>          to show docs for a specific tool")

    def _docs_for_tool(self, tool: str) -> None:
        """Show documentation for a specific tool."""
        tool_docs = get_docs_for_tool(tool)
        if not tool_docs:
            print(f"No documentation available for tool: {tool}")
            print("Available tools: burp, wireshark, nmap, sqlmap, hydra, nikto, cookie, webscan, osint, auth, siem")
            return
        online = is_online()
        print(f"Documentation for '{tool}': ({len(tool_docs)} doc(s))  |  Network: {'ONLINE' if online else 'OFFLINE'}")
        print()
        for d in tool_docs:
            status = "cached" if d["available_offline"] else ("downloadable" if online else "unavailable")
            print(f"  {d['id']:<20} {d['title']}")
            print(f"                    {d['description']}")
            print(f"                    Status: {status}")
            print()
        print("Hint:", get_hint_for_tool(tool))

    def do_burp(self, arg: str) -> None:
        """Launch the simulated intercepting proxy (BurpSuite-style).

        usage: burp [--target URL]
        """
        parser = argparse.ArgumentParser(prog="burp", add_help=False)
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
        parser = argparse.ArgumentParser(prog="wireshark", add_help=False)
        parser.add_argument("--packets", type=int, default=25)
        parser.add_argument("--export", metavar="FILE")
        try:
            args = parser.parse_args(shlex.split(arg))
        except SystemExit:
            return
        run_wireshark(args)

    def do_auth(self, arg: str) -> None:
        """Launch the simulated authentication security lab.

        usage: auth
        """
        run_auth(argparse.Namespace())

    def do_siem(self, arg: str) -> None:
        """Launch the simulated SIEM log analysis lab.

        usage: siem
        """
        run_siem(argparse.Namespace())

    def do_nmap(self, arg: str) -> None:
        """Launch the simulated Nmap network scanner.

        usage: nmap
        """
        run_nmap(argparse.Namespace())

    def do_sqlmap(self, arg: str) -> None:
        """Launch the simulated SQLmap injection tool.

        usage: sqlmap
        """
        run_sqlmap(argparse.Namespace())

    def do_hydra(self, arg: str) -> None:
        """Launch the simulated Hydra password cracker.

        usage: hydra
        """
        run_hydra(argparse.Namespace())

    def do_nikto(self, arg: str) -> None:
        """Launch the simulated Nikto web scanner.

        usage: nikto
        """
        run_nikto(argparse.Namespace())

    def do_cookie(self, arg: str) -> None:
        """Launch the simulated cookie security scanner.

        usage: cookie
        """
        run_cookie(argparse.Namespace())

    def do_webscan(self, arg: str) -> None:
        """Launch the simulated website scanner.

        usage: webscan
        """
        run_webscan(argparse.Namespace())

    def do_osint(self, arg: str) -> None:
        """Launch the simulated OSINT tool.

        usage: osint
        """
        run_osint_shell(argparse.Namespace())

    def do_clear(self, arg: str) -> None:
        """Clear the screen."""
        import os
        os.system("cls" if sys.platform == "win32" else "clear")

    def do_exit(self, arg: str) -> None:
        """Leave the terminal."""
        print("Goodbye.")
        return True

    def do_quit(self, arg: str) -> None:
        """Leave the terminal."""
        return self.do_exit(arg)

    def emptyline(self) -> None:
        pass

    # ---------- helpers ----------

    def _open_tutorial_webpage(self) -> None:
        html_path = Path(__file__).resolve().parent / "tutorials" / "index.html"
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
    terminal = CyberTerminal()
    terminal.cmdloop()
    return 0
