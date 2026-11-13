"""The guided, interactive menu — `cyberlab` with no arguments, or `cyberlab menu`.

A plain text menu so a student who has never seen the tool can pick a track,
open a challenge, read its goal, ask for hints and submit an answer without
knowing any subcommands. The scriptable subcommands (list/start/submit/...)
still do the same things for anyone who prefers them.
"""

from __future__ import annotations

import textwrap
from typing import List, Optional

from cyberlab.challenges import Challenge, ordered
from cyberlab.workspace import Workspace

TRACK_NAMES = {
    "web": "Web Application Security",
    "network": "Network Forensics",
    "logs": "Log Analysis",
}
TRACK_BLURB = {
    "web": "Attack a small website running on your own machine (use Firefox or curl).",
    "network": "Analyse captured traffic in Wireshark or tshark and report what you find.",
    "logs": "Dig through real log files with grep and spot the attack.",
}

WELCOME = """\
Welcome to cyberlab — a hacking practice range that runs entirely on this
machine. Nothing you do here touches the real network.

Pick a challenge below. Each one tells you the goal and where to look; you
solve it with real tools, then submit your answer here. Stuck? Ask for a hint.
"""


def _wrap(text: str, indent: str = "  ") -> str:
    return textwrap.fill(text, width=78, initial_indent=indent, subsequent_indent=indent)


def _ask(prompt: str) -> Optional[str]:
    """Read a line; return None on Ctrl-D/Ctrl-C (treated as 'go back / quit')."""
    try:
        return input(prompt).strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return None


def _print_menu(ws: Workspace, challenges: List[Challenge]) -> None:
    solved = sum(ws.is_solved(c.id) for c in challenges)
    print(f"\n=== cyberlab — {solved}/{len(challenges)} solved ===\n")
    last_track = None
    for i, c in enumerate(challenges, 1):
        if c.track != last_track:
            last_track = c.track
            print(f"  {TRACK_NAMES.get(c.track, c.track.title())}")
            print(f"  {TRACK_BLURB.get(c.track, '')}")
        mark = "x" if ws.is_solved(c.id) else " "
        print(f"    {i:>2}. [{mark}] {c.difficulty:<7} {c.title}")
    print("\n  Type a number to open a challenge, 'p' for your progress report, 'q' to quit.")


def _open(ws: Workspace, c: Challenge) -> None:
    print(f"\n--- {c.title}  [{TRACK_NAMES.get(c.track, c.track)}, {c.difficulty}] ---\n")
    print(_wrap(c.goal))
    try:
        details = c.setup(ws)
    except RuntimeError as e:
        print(f"\n  Could not set this challenge up: {e}")
        return
    if details:
        print("\n" + "\n".join("  " + line for line in details.splitlines()))
    if c.tools:
        print(f"\n  Tools that help: {', '.join(c.tools)}")
    if ws.is_solved(c.id):
        print("\n  You've already solved this one.")

    seen_hints = 0
    while True:
        print("\n  [s] submit an answer   [h] hint   [i] show this again   [b] back to the menu")
        choice = _ask("  > ")
        if choice is None or choice == "b":
            return
        choice = choice.lower()
        if choice == "s":
            answer = _ask("  answer> ")
            if not answer:
                continue
            if c.check(ws, answer):
                ws.mark_solved(c.id)
                print("\n  Correct! Challenge solved.")
                return
            print("\n  Not quite — keep going, or ask for a hint.")
        elif choice == "h":
            if not c.hints:
                print("\n  No hints for this one.")
                continue
            seen_hints = min(seen_hints + 1, len(c.hints))
            for n in range(seen_hints):
                print(f"\n  Hint {n + 1}/{len(c.hints)}:")
                print(_wrap(c.hints[n], indent="    "))
            if seen_hints == len(c.hints):
                print("\n  That's every hint for this challenge.")
        elif choice == "i":
            _open_reshow(c, details)
        else:
            print("  Please type s, h, i or b.")


def _open_reshow(c: Challenge, details: str) -> None:
    print(f"\n{_wrap(c.goal)}")
    if details:
        print("\n" + "\n".join("  " + line for line in details.splitlines()))


def run_menu(ws: Workspace) -> int:
    print(WELCOME)
    while True:
        challenges = ordered()
        _print_menu(ws, challenges)
        choice = _ask("\n> ")
        if choice is None or choice.lower() in ("q", "quit", "exit"):
            print("\nBye. Your progress is saved; run 'cyberlab' again any time.")
            return 0
        if choice.lower() in ("p", "progress", "report"):
            from cyberlab import report
            print("\n" + report.as_text(report.build(ws)))
            print("  To hand this in, run:  cyberlab report --name \"Your Name\" -o report.txt")
            continue
        if choice.isdigit() and 1 <= int(choice) <= len(challenges):
            _open(ws, challenges[int(choice) - 1])
        else:
            print("  Please type a challenge number, 'p', or 'q'.")
