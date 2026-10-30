"""A small read-only filesystem for the cyberterminal shell.

Backs ``ls``, ``ll``, ``cd``, ``pwd`` and ``cat`` in the main window so the
``student@cyberlab:~$`` prompt behaves like the Linux shell it looks like.
Everything lives in memory and nothing can be written. The only real files it
shows are the packet captures the Wireshark challenges generate, and only
their names and sizes.

Layout::

    /etc/hostname, /etc/os-release, /etc/passwd
    /home/student (~)
        README.txt
        tutorials/<id>.txt   one briefing per tutorial, from tutorials/data.json
        captures/*.pcap      files in src/data/captures/
    /tmp
"""

from __future__ import annotations

import posixpath
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Union

USER = "student"
HOST = "cyberlab"
HOME = f"/home/{USER}"
MTIME = "Jan 15 09:00"  # same day as the simulated logs

README = """Welcome to cyberlab.

Everything on this machine is simulated: the filesystem is read-only and
nothing you run here touches a real network.

  tutorials/   one briefing per tutorial, e.g. cat tutorials/web-sqli-01.txt
  captures/    packet captures used by the Wireshark challenges

Type 'help' for the lab's commands, or 'next' for where to start.
"""


@dataclass
class File:
    read: Callable[[], str]
    size: Callable[[], int]
    binary: bool = False


@dataclass
class Dir:
    entries: Callable[[], Dict[str, "Node"]]


Node = Union[File, Dir]


def _text(content: str) -> File:
    return File(read=lambda: content, size=lambda: len(content.encode()))


def _tutorial_briefing(t: dict) -> str:
    lines = [
        f"{t.get('id', '')} - {t.get('title', '')}",
        f"Difficulty: {t.get('difficulty', '')}   Track: {t.get('track', '')}   Tool: {t.get('module', '')}",
        "",
        t.get("description", ""),
        "",
        "Steps:",
    ]
    for i, step in enumerate(t.get("steps", []), 1):
        lines.append(f"  {i}. {step.get('description', '')}")
        if step.get("command"):
            lines.append(f"     $ {step['command']}")
        if step.get("notes"):
            lines.append(f"     # {step['notes']}")
    return "\n".join(lines) + "\n"


def _tutorials() -> Dict[str, Node]:
    from src.tutorials.manager import load_tutorials
    return {f"{t['id']}.txt": _text(_tutorial_briefing(t)) for t in load_tutorials() if t.get("id")}


def _captures() -> Dict[str, Node]:
    from src.core.challenge import CAPTURES_DIR
    out: Dict[str, Node] = {}
    for p in sorted(CAPTURES_DIR.glob("*")):
        if p.is_file():
            size = p.stat().st_size
            out[p.name] = File(read=lambda: "", size=lambda s=size: s, binary=True)
    return out


def _build_tree() -> Dir:
    etc = {
        "hostname": _text(f"{HOST}\n"),
        "os-release": _text('NAME="CyberLab Linux"\nVERSION="1.0 (simulated)"\nID=cyberlab\n'),
        "passwd": _text(
            "root:x:0:0:root:/root:/bin/bash\n"
            f"{USER}:x:1000:1000:Student,,,:{HOME}:/bin/bash\n"
        ),
    }
    home = {
        "README.txt": _text(README),
        "tutorials": Dir(entries=_tutorials),
        "captures": Dir(entries=_captures),
    }
    root = {
        "etc": Dir(entries=lambda: etc),
        "home": Dir(entries=lambda: {USER: Dir(entries=lambda: home)}),
        "tmp": Dir(entries=lambda: {}),
    }
    return Dir(entries=lambda: root)


class VirtualFS:
    """The shell's current directory plus the read-only commands over the tree."""

    def __init__(self) -> None:
        self.root = _build_tree()
        self.cwd = HOME
        self.oldpwd = HOME

    # ----- paths -----

    def resolve(self, path: str) -> str:
        """Absolute, normalized path for what the user typed."""
        if path in ("", "~"):
            return HOME
        if path.startswith("~/"):
            path = HOME + path[1:]
        elif not path.startswith("/"):
            path = posixpath.join(self.cwd, path)
        path = posixpath.normpath(path)
        return "/" + path.lstrip("/")  # normpath keeps a leading "//"

    def lookup(self, abspath: str) -> Optional[Node]:
        node: Node = self.root
        for part in abspath.split("/"):
            if not part:
                continue
            if not isinstance(node, Dir):
                return None
            node = node.entries().get(part)
            if node is None:
                return None
        return node

    def display_cwd(self) -> str:
        """The current directory as the prompt shows it (~ for home)."""
        if self.cwd == HOME or self.cwd.startswith(HOME + "/"):
            return "~" + self.cwd[len(HOME):]
        return self.cwd

    # ----- commands (each returns the text to print) -----

    def pwd(self) -> str:
        return self.cwd + "\n"

    def cd(self, arg: str) -> str:
        target = self.oldpwd if arg == "-" else self.resolve(arg)
        node = self.lookup(target)
        if node is None:
            return f"bash: cd: {arg}: No such file or directory\n"
        if not isinstance(node, Dir):
            return f"bash: cd: {arg}: Not a directory\n"
        self.oldpwd, self.cwd = self.cwd, target
        return target + "\n" if arg == "-" else ""

    def ls(self, args: List[str], long: bool = False, all_: bool = False) -> str:
        paths = []
        for a in args:
            if a.startswith("-") and len(a) > 1:
                long = long or "l" in a
                all_ = all_ or "a" in a
            else:
                paths.append(a)
        paths = paths or ["."]
        out: List[str] = []
        for i, path in enumerate(paths):
            node = self.lookup(self.resolve(path))
            if node is None:
                out.append(f"ls: cannot access '{path}': No such file or directory")
                continue
            if isinstance(node, File):
                out.append(self._entry(path, node, long))
                continue
            if len(paths) > 1:
                out.append(("" if i == 0 else "\n") + f"{path}:")
            entries = sorted(node.entries().items())
            if all_:
                entries = [(".", node), ("..", Dir(entries=dict))] + entries
            shown = [self._entry(name, n, long) for name, n in entries]
            if long:
                out.extend(shown)
            elif shown:
                out.append("  ".join(shown))
        return "\n".join(out) + "\n" if out else ""

    def cat(self, args: List[str]) -> str:
        if not args:
            return "cat: missing file operand\n"
        out = []
        for path in args:
            node = self.lookup(self.resolve(path))
            if node is None:
                out.append(f"cat: {path}: No such file or directory\n")
            elif isinstance(node, Dir):
                out.append(f"cat: {path}: Is a directory\n")
            elif node.binary:
                out.append(f"cat: {path}: binary packet capture; analyze it in the "
                           "wireshark tool ('challenge list')\n")
            else:
                out.append(node.read())
        return "".join(out)

    @staticmethod
    def _entry(name: str, node: Node, long: bool) -> str:
        is_dir = isinstance(node, Dir)
        display = name + ("/" if is_dir and name not in (".", "..") else "")
        if not long:
            return display
        perms = "dr-xr-xr-x" if is_dir else "-r--r--r--"
        size = 4096 if is_dir else node.size()
        return f"{perms} 1 {USER} {USER} {size:>6} {MTIME} {display}"


# Commands that would change the filesystem: answered with "Read-only file system".
WRITE_COMMANDS = {"touch", "mkdir", "rmdir", "rm", "mv", "cp", "nano", "vim", "vi", "chmod", "chown", "ln"}
