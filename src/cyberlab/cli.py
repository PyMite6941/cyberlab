"""cyberlab command-line interface.

All traffic is simulated locally. Nothing touches the network, so the CLI works
fully offline once dependencies are installed.
"""

from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from cyberlab.core import registry

# Import modules so their scenarios self-register.
import cyberlab.modules.burp  # noqa: F401
import cyberlab.modules.wireshark  # noqa: F401


def _cmd_labs(args: argparse.Namespace) -> int:
    scenarios = registry.list()
    if not scenarios:
        print("No labs registered yet.")
        return 0

    print("Available labs:")
    print()
    header = f"{'ID':<12} {'Module':<14} {'Title'}"
    print(header)
    print("-" * len(header))
    for s in scenarios:
        tags = f" [{','.join(s.tags)}]" if s.tags else ""
        print(f"{s.id:<12} {s.module:<14} {s.title}{tags}")
    print()
    print("Run a lab with:  cyberlab run <id>")
    print("Open a tool:     cyberlab burp   |  cyberlab wireshark")
    return 0


def _cmd_run(args: argparse.Namespace) -> int:
    scenario = registry.get(args.id)
    if scenario is None:
        print(f"Unknown lab: {args.id}")
        print("Run 'cyberlab labs' to see available labs.")
        return 1
    print(f"=== {scenario.title} ===")
    print(scenario.description)
    print()
    return scenario.run()


def _cmd_burp(args: argparse.Namespace) -> int:
    from cyberlab.modules.burp import run_burp
    return run_burp(args)


def _cmd_wireshark(args: argparse.Namespace) -> int:
    from cyberlab.modules.wireshark import run_wireshark
    return run_wireshark(args)


def _cmd_tutorial(args: argparse.Namespace) -> int:
    from cyberlab.tutorials.manager import TutorialManager
    m = TutorialManager()
    t = m.get(args.id)
    if not t:
        print(f"Unknown tutorial: {args.id}")
        print("Run 'cyberlab shell' then 'tutorials' to list available tutorials.")
        return 1
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
    return 0


def _cmd_shell(args: argparse.Namespace) -> int:
    from cyberlab.shell import main as shell_main
    return shell_main()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cyberlab",
        description="Offline cybersecurity practice labs (BurpSuite + Wireshark simulators).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # labs
    p_labs = sub.add_parser("labs", help="List available practice labs.")
    p_labs.set_defaults(func=_cmd_labs)

    # run
    p_run = sub.add_parser("run", help="Run a guided lab by ID.")
    p_run.add_argument("id", help="Lab ID (see 'cyberlab labs').")
    p_run.set_defaults(func=_cmd_run)

    # burp
    p_burp = sub.add_parser(
        "burp", help="Simulated intercepting proxy (BurpSuite-style), offline."
    )
    p_burp.add_argument(
        "--target",
        default="http://lab.local",
        help="Simulated target base URL.",
    )
    p_burp.set_defaults(func=_cmd_burp)

    # wireshark
    p_ws = sub.add_parser(
        "wireshark", help="Simulated packet capture (Wireshark-style), offline."
    )
    p_ws.add_argument(
        "--packets",
        type=int,
        default=25,
        help="Number of simulated packets to generate.",
    )
    p_ws.add_argument(
        "--export",
        metavar="FILE",
        help="Export the capture to a pcap file.",
    )
    p_ws.set_defaults(func=_cmd_wireshark)

    # shell
    p_shell = sub.add_parser("shell", help="Launch the custom interactive shell environment.")
    p_shell.set_defaults(func=_cmd_shell)

    # tutorial
    p_tut = sub.add_parser("tutorial", help="Show the steps of a tutorial by ID.")
    p_tut.add_argument("id", help="Tutorial ID (see 'cyberlab shell' -> 'tutorials').")
    p_tut.set_defaults(func=_cmd_tutorial)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
