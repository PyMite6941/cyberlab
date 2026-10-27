"""Simulated Hydra password cracking tool, fully offline.

Simulates password brute-force attacks against mock authentication services.
No real network connections or credential stuffing is performed.

To launch from cyberterminal:

    cyberterminal> hydra
    cyberterminal> hydra --target 192.168.1.10 --service ssh --userlist users.txt
    cyberterminal> hydra --target lab.local --service http-post --user admin
"""

from __future__ import annotations

import argparse
import cmd
import shlex
import random
from typing import Optional


# Simulated credential database
CREDENTIAL_DB: dict[str, dict[str, str]] = {
    "admin": {"password": "admin", "service": "ssh"},
    "admin": {"password": "password", "service": "http"},
    "user1": {"password": "password123", "service": "ssh"},
    "user1": {"password": "welcome1", "service": "ftp"},
    "root": {"password": "toor", "service": "ssh"},
    "test": {"password": "test", "service": "http"},
    "guest": {"password": "guest", "service": "ftp"},
}


def simulate_crack(target: str, service: str, username: str,
                   wordlist: Optional[list[str]] = None,
                   seed: int = 42) -> dict:
    """Simulate a password cracking attempt.

    Args:
        target: Target host/IP.
        service: Service being attacked (ssh, ftp, http, etc.).
        username: Username to crack.
        wordlist: Optional list of passwords to try.
        seed: Random seed for deterministic output.

    Returns:
        A dict with crack results including found credentials and attempts.
    """
    rng = random.Random(seed)

    if wordlist is None:
        wordlist = ["password", "123456", "admin", "welcome", "letmein",
                    "login", "qwerty", "abc123", "monkey", "dragon",
                    "password1", "password123", "root", "toor", "guest",
                    "changeme", "secret", "master", "michael", "shadow"]

    attempts: list[dict] = []
    found = False
    found_password = ""

    # Determine if this credential exists in our simulated DB
    cred = CREDENTIAL_DB.get(username)
    actual_password = cred.get("password") if cred else None
    service_match = cred and cred.get("service") == service

    for pwd in wordlist:
        attempts.append({
            "password": pwd,
            "result": "failure",
        })
        if service_match and pwd == actual_password:
            found = True
            found_password = pwd
            attempts[-1]["result"] = "success"
            break
        elif rng.random() < 0.001:
            # Rare false positive
            found = True
            found_password = pwd
            attempts[-1]["result"] = "success (possible false positive)"
            break

    return {
        "target": target,
        "service": service,
        "username": username,
        "wordlist_size": len(wordlist),
        "attempts": attempts,
        "attempts_made": len(attempts),
        "found": found,
        "password": found_password,
    }


def format_crack_result(result: dict) -> str:
    """Format Hydra results as human-readable output."""
    lines: list[str] = []
    lines.append("=" * 60)
    lines.append("Hydra simulator (offline)")
    lines.append("=" * 60)
    lines.append("")
    lines.append(f"Target: {result['target']}")
    lines.append(f"Service: {result['service']}")
    lines.append(f"Username: {result['username']}")
    lines.append(f"Wordlist size: {result['wordlist_size']}")
    lines.append(f"Attempts made: {result['attempts_made']}")
    lines.append("")

    if result["found"]:
        lines.append("[+] Credential found!")
        lines.append(f"    Username: {result['username']}")
        lines.append(f"    Password: {result['password']}")
        lines.append(f"    Service: {result['service']}")
    else:
        lines.append("[-] No valid credentials found.")
        lines.append("    Try a different wordlist or target.")

    lines.append("")
    lines.append("Recent attempts:")
    lines.append("-" * 40)
    for a in result["attempts"][-10:]:
        marker = "[+]" if a["result"] == "success" else "[-]"
        lines.append(f"  {marker} {a['password']}: {a['result']}")

    lines.append("=" * 60)
    return "\n".join(lines)


class HydraShell(cmd.Cmd):
    intro = "=== cyberterminal Hydra simulator (offline) ===\nType 'help' or '?' to list commands. Type 'quit' to exit.\n"
    prompt = "hydra> "

    def __init__(self) -> None:
        super().__init__()
        self.last_result: Optional[dict] = None

    def do_crack(self, arg: str) -> None:
        """Attempt password cracking.

        usage: crack <target> <service> <user> [--wordlist <file>]
        Example: crack 192.168.1.10 ssh admin
                 crack lab.local http-post admin --wordlist passwords.txt
        """
        parser = argparse.ArgumentParser(prog="crack", add_help=False)
        parser.add_argument("target")
        parser.add_argument("service")
        parser.add_argument("user")
        parser.add_argument("--wordlist", default=None)
        try:
            args = parser.parse_args(shlex.split(arg))
        except SystemExit:
            return
        wordlist = None
        if args.wordlist:
            try:
                with open(args.wordlist, "r", encoding="utf-8") as f:
                    wordlist = [line.strip() for line in f if line.strip()]
            except OSError:
                print(f"Could not read wordlist: {args.wordlist}")
                wordlist = None
        result = simulate_crack(args.target, args.service, args.user, wordlist)
        self.last_result = result
        print(format_crack_result(result))

    def do_quit(self, arg: str) -> None:
        print("Goodbye.")
        return True

    def do_exit(self, arg: str) -> None:
        return self.do_quit(arg)

    def emptyline(self) -> None:
        pass


def run_hydra(args: argparse.Namespace) -> int:
    shell = HydraShell()
    shell.cmdloop()
    return 0


# Self-register tutorials with the track registry
from src.core.track import registry as _track_registry  # noqa: E402
from src.core.track import Tutorial as _Tutorial  # noqa: F401


def _hydra_lab() -> int:
    return run_hydra(argparse.Namespace())


_track_registry.register_tutorial(
    _Tutorial(
        id="auth-hydra-01",
        title="Password Brute-Force with Hydra",
        category="auth",
        module="hydra",
        description="Simulate password brute-force attacks against SSH/HTTP/FTP.",
        vulnerability="weak_credentials",
        difficulty="medium",
        track="authentication-security",
        ai_enabled=True,
    )
)