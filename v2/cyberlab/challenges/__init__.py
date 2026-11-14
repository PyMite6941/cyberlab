"""Challenge definitions and the registry the CLI reads.

A challenge is one file in this package that defines a Challenge and calls
register(). To add one: copy an existing file, change the fields, setup()
and (if the answer isn't a flag) check(), and import it at the bottom here.

Every challenge also carries its debrief: what the student just did, why it
matters outside the lab, the commands worth keeping, and how to defend against
it. `cyberlab submit` prints it on a correct answer and `cyberlab learn <id>`
shows it again. A challenge without one fails the tests.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Tuple

from cyberlab.workspace import Workspace


@dataclass
class Challenge:
    id: str
    title: str
    track: str        # web, network, logs ...
    difficulty: str   # easy, medium, hard
    goal: str         # one or two sentences shown by `start`
    hints: List[str] = field(default_factory=list)
    tools: List[str] = field(default_factory=list)  # suggested real tools
    # The debrief (see the module docstring).
    learned: str = ""                                # what you just did
    real_world: str = ""                             # why it matters
    defend: List[str] = field(default_factory=list)  # how to prevent or detect it
    ap_unit: str = ""
    ap_topic: str = ""
    ap_skill: List[str] = field(default_factory=list)

    def setup(self, ws: Workspace) -> str:
        """Start targets / write files; return what the student needs to know."""
        return ""

    def check(self, ws: Workspace, answer: str) -> bool:
        """Default: the answer is this challenge's flag."""
        return ws.matches_flag(self.id, answer)

    def snippets(self, ws: Workspace) -> List[Tuple[str, str]]:
        """(what it does, command) pairs for the debrief, filled in with this
        student's real port and file paths so they can be pasted as they are."""
        return []


REGISTRY: Dict[str, Challenge] = {}
TRACK_ORDER = ["web", "network", "passwords", "logs"]
DIFFICULTY_ORDER = ["easy", "medium", "hard"]


def register(challenge: Challenge) -> Challenge:
    if challenge.id in REGISTRY:
        raise ValueError(f"duplicate challenge id: {challenge.id}")
    REGISTRY[challenge.id] = challenge
    return challenge


def ordered() -> List[Challenge]:
    def key(c: Challenge):
        track = TRACK_ORDER.index(c.track) if c.track in TRACK_ORDER else len(TRACK_ORDER)
        return (track, DIFFICULTY_ORDER.index(c.difficulty), c.id)
    return sorted(REGISTRY.values(), key=key)


# Each module registers its challenge on import.
from cyberlab.challenges import web_sqli  # noqa: E402,F401
from cyberlab.challenges import web_xss  # noqa: E402,F401
from cyberlab.challenges import net_http_creds  # noqa: E402,F401
from cyberlab.challenges import net_port_scan  # noqa: E402,F401
from cyberlab.challenges import net_dns_tunnel  # noqa: E402,F401
from cyberlab.challenges import dict_john  # noqa: E402,F401
from cyberlab.challenges import dict_hydra  # noqa: E402,F401
from cyberlab.challenges import web_gobuster  # noqa: E402,F401
from cyberlab.challenges import net_nmap  # noqa: E402,F401
from cyberlab.challenges import web_idor  # noqa: E402,F401
from cyberlab.challenges import web_log_forensics  # noqa: E402,F401
from cyberlab.challenges import web_session  # noqa: E402,F401
from cyberlab.challenges import web_upload  # noqa: E402,F401
