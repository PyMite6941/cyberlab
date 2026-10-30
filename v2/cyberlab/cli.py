"""The `cyberlab` command.

    cyberlab list                   challenges and your progress
    cyberlab start <id>             set up a challenge and show its goal
    cyberlab submit <id> <answer>   check an answer
    cyberlab hint <id>              next hint for a challenge
    cyberlab stop                   stop every running target
    cyberlab report [-o FILE]       progress summary to hand in
    cyberlab reset                  stop targets and delete your workspace
"""

from __future__ import annotations

import argparse
import difflib
import shutil
import sys
import textwrap
from typing import List, Optional

from cyberlab import __version__, report, targets
from cyberlab.challenges import REGISTRY, Challenge, ordered
from cyberlab.workspace import Workspace


def _wrap(text: str, indent: str = "  ") -> str:
    return textwrap.fill(text, width=78, initial_indent=indent, subsequent_indent=indent)


def _find(challenge_id: str) -> Optional[Challenge]:
    challenge = REGISTRY.get(challenge_id)
    if challenge is None:
        print(f"No challenge called '{challenge_id}'.", file=sys.stderr)
        close = difflib.get_close_matches(challenge_id, REGISTRY, n=3)
        if close:
            print(f"Did you mean: {', '.join(close)}?", file=sys.stderr)
        print("Run 'cyberlab list' to see them all.", file=sys.stderr)
    return challenge


def cmd_list(ws: Workspace, args: argparse.Namespace) -> int:
    challenges = ordered()
    solved = sum(ws.is_solved(c.id) for c in challenges)
    print(f"{'':4}{'ID':<13} {'TRACK':<9} {'LEVEL':<8} TITLE")
    for c in challenges:
        mark = "x" if ws.is_solved(c.id) else " "
        print(f"[{mark}] {c.id:<13} {c.track:<9} {c.difficulty:<8} {c.title}")
    print(f"\n{solved}/{len(challenges)} solved. Start one with: cyberlab start <id>")
    running = [name for name in list(ws.state["targets"]) if targets.running(ws, name)]
    if running:
        print(f"Running targets: {', '.join(running)} (stop them with: cyberlab stop)")
    return 0


def cmd_start(ws: Workspace, args: argparse.Namespace) -> int:
    c = _find(args.id)
    if c is None:
        return 2
    try:
        details = c.setup(ws)
    except RuntimeError as e:
        print(f"Couldn't set up {c.id}: {e}", file=sys.stderr)
        return 1
    print(f"{c.title}  [{c.track}, {c.difficulty}]\n")
    print(_wrap(c.goal))
    if details:
        print("\n" + "\n".join("  " + line for line in details.splitlines()))
    if c.tools:
        print(f"\n  Tools that help: {', '.join(c.tools)}")
    print(f"\n  Submit with:  cyberlab submit {c.id} <answer>")
    print(f"  Stuck?        cyberlab hint {c.id}")
    if ws.is_solved(c.id):
        print("\n  (You've already solved this one.)")
    return 0


def cmd_submit(ws: Workspace, args: argparse.Namespace) -> int:
    c = _find(args.id)
    if c is None:
        return 2
    answer = " ".join(args.answer)
    if c.check(ws, answer):
        ws.mark_solved(c.id)
        solved = sum(ws.is_solved(x.id) for x in REGISTRY.values())
        print(f"Correct! {c.id} solved. ({solved}/{len(REGISTRY)} solved)")
        return 0
    print(f"Not quite. Keep going, or try: cyberlab hint {c.id}")
    return 1


def cmd_hint(ws: Workspace, args: argparse.Namespace) -> int:
    c = _find(args.id)
    if c is None:
        return 2
    if not c.hints:
        print("No hints for this one.")
        return 0
    seen = ws.next_hint_index(c.id)
    shown = min(seen + 1, len(c.hints))
    for i, hint in enumerate(c.hints[:shown], 1):
        print(f"Hint {i}/{len(c.hints)}:")
        print(_wrap(hint))
    if shown == len(c.hints) and seen >= len(c.hints):
        print("\nThat's every hint for this challenge.")
    ws.record_hint(c.id, shown)
    return 0


def cmd_stop(ws: Workspace, args: argparse.Namespace) -> int:
    stopped = targets.stop_all(ws)
    print(f"Stopped: {', '.join(stopped)}" if stopped else "Nothing was running.")
    return 0


def cmd_report(ws: Workspace, args: argparse.Namespace) -> int:
    data = report.build(ws, name=args.name)
    text = report.as_json(data) if args.json else report.as_text(data)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(text)
        print(f"Saved your report to {args.output}")
    else:
        sys.stdout.write(text)
    if not args.name:
        print(f"(Reported as '{data['student']}'. Use --name \"Your Name\" if that's not you.)",
              file=sys.stderr)
    return 0


def cmd_reset(ws: Workspace, args: argparse.Namespace) -> int:
    if not args.yes:
        reply = input(f"Delete {ws.home} and all your progress? Type 'yes' to confirm: ")
        if reply.strip().lower() != "yes":
            print("Cancelled.")
            return 1
    targets.stop_all(ws)
    shutil.rmtree(ws.home, ignore_errors=True)
    print(f"Deleted {ws.home}. Your next command starts a fresh workspace.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cyberlab",
        description="Offline cyber range: vulnerable targets on 127.0.0.1, attacked with real tools.",
    )
    parser.add_argument("--version", action="version", version=f"cyberlab {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="<command>")

    sub.add_parser("list", help="challenges and your progress").set_defaults(func=cmd_list)
    p = sub.add_parser("start", help="set up a challenge and show its goal")
    p.add_argument("id")
    p.set_defaults(func=cmd_start)
    p = sub.add_parser("submit", help="check an answer")
    p.add_argument("id")
    p.add_argument("answer", nargs="+")
    p.set_defaults(func=cmd_submit)
    p = sub.add_parser("hint", help="next hint for a challenge")
    p.add_argument("id")
    p.set_defaults(func=cmd_hint)
    sub.add_parser("stop", help="stop every running target").set_defaults(func=cmd_stop)
    p = sub.add_parser("report", help="progress summary to hand in")
    p.add_argument("--name", help="your name as it should appear (default: your login name)")
    p.add_argument("-o", "--output", metavar="FILE", help="save the report to FILE instead of printing it")
    p.add_argument("--json", action="store_true", help="machine-readable JSON instead of text")
    p.set_defaults(func=cmd_report)
    p = sub.add_parser("reset", help="stop targets and delete your workspace")
    p.add_argument("--yes", action="store_true", help="don't ask for confirmation")
    p.set_defaults(func=cmd_reset)
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return 0
    try:
        return args.func(Workspace(), args)
    except KeyboardInterrupt:
        print()
        return 130
