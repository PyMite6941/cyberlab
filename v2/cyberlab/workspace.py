"""The student's workspace: ~/cyberlab, its saved state, and the flags.

State lives in ~/cyberlab/.state.json (set CYBERLAB_HOME to use another
directory). It holds a random secret created on first use; every flag is
derived from that secret, so each student's flags are different and none are
stored anywhere in the repo.

The secret sits on the student's own machine, so a determined student could
read it and work out their flags. Flags are a deterrent against copying a
classmate's answer, not proof of work.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict


def default_home() -> Path:
    override = os.environ.get("CYBERLAB_HOME")
    return Path(override).expanduser() if override else Path.home() / "cyberlab"


class Workspace:
    def __init__(self, home: Path | None = None) -> None:
        self.home = Path(home) if home else default_home()
        self.state_path = self.home / ".state.json"
        self.state: Dict[str, Any] = self._load()
        if not self.state_path.exists():
            self.save()  # keep the new secret, so flags stay the same from now on

    # ----- state -----

    def _load(self) -> Dict[str, Any]:
        try:
            state = json.loads(self.state_path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            state = {}
        except (OSError, ValueError) as e:
            raise SystemExit(f"cyberlab: can't read {self.state_path}: {e}\n"
                             "Run 'cyberlab reset' to start over.")
        state.setdefault("version", 1)
        state.setdefault("secret", secrets.token_hex(32))
        state.setdefault("solved", {})
        state.setdefault("hints", {})
        state.setdefault("targets", {})
        return state

    def save(self) -> None:
        self.home.mkdir(parents=True, exist_ok=True)
        tmp = self.state_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.state, indent=2), encoding="utf-8")
        tmp.replace(self.state_path)

    def path(self, *parts: str) -> Path:
        """A path inside the workspace, creating its parent directory."""
        p = self.home.joinpath(*parts)
        p.parent.mkdir(parents=True, exist_ok=True)
        return p

    # ----- flags and answers -----

    def derive(self, label: str, length: int = 20) -> str:
        """A hex string unique to this workspace and label."""
        key = bytes.fromhex(self.state["secret"])
        return hmac.new(key, label.encode(), hashlib.sha256).hexdigest()[:length]

    def flag(self, challenge_id: str) -> str:
        return "FLAG{" + self.derive("flag:" + challenge_id) + "}"

    def matches_flag(self, challenge_id: str, answer: str) -> bool:
        return hmac.compare_digest(answer.strip().encode(), self.flag(challenge_id).encode())

    # ----- progress -----

    def is_solved(self, challenge_id: str) -> bool:
        return challenge_id in self.state["solved"]

    def mark_solved(self, challenge_id: str) -> None:
        self.state["solved"].setdefault(challenge_id, datetime.now(timezone.utc).isoformat(timespec="seconds"))
        self.save()

    def next_hint_index(self, challenge_id: str) -> int:
        """How many hints the student has already seen for a challenge."""
        return int(self.state["hints"].get(challenge_id, 0))

    def record_hint(self, challenge_id: str, seen: int) -> None:
        self.state["hints"][challenge_id] = seen
        self.save()
