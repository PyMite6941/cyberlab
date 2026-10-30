"""Tests for cyberlab v2. Standard library only:

    cd v2 && python3 -m unittest discover -s tests -v
"""

from __future__ import annotations

import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

V2 = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(V2))

from cyberlab import targets  # noqa: E402
from cyberlab.webapp import make_server  # noqa: E402
from cyberlab.workspace import Workspace  # noqa: E402

INJECTIONS = ["admin' --", "' OR 1=1 --", "' OR '1'='1' --"]


def post_login(port: int, username: str, password: str = "x"):
    """POST /login; return (status, body) without raising on 4xx/5xx."""
    data = urllib.parse.urlencode({"username": username, "password": password}).encode()
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/login", data=data, timeout=5) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def accepting(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.2):
            return True
    except OSError:
        return False


class TempHome(unittest.TestCase):
    def setUp(self) -> None:
        self.home = Path(tempfile.mkdtemp(prefix="cyberlab-test-"))
        self.addCleanup(shutil.rmtree, self.home, True)


class TestWorkspace(TempHome):
    def test_flag_is_stable_across_reloads(self):
        flag = Workspace(self.home).flag("web-sqli")
        self.assertRegex(flag, r"^FLAG\{[0-9a-f]{20}\}$")
        self.assertEqual(Workspace(self.home).flag("web-sqli"), flag)

    def test_flags_differ_per_student_and_challenge(self):
        other = Path(tempfile.mkdtemp(prefix="cyberlab-test-"))
        self.addCleanup(shutil.rmtree, other, True)
        ws = Workspace(self.home)
        self.assertNotEqual(ws.flag("web-sqli"), Workspace(other).flag("web-sqli"))
        self.assertNotEqual(ws.flag("web-sqli"), ws.flag("something-else"))

    def test_matches_flag(self):
        ws = Workspace(self.home)
        self.assertTrue(ws.matches_flag("web-sqli", "  " + ws.flag("web-sqli") + "\n"))
        self.assertFalse(ws.matches_flag("web-sqli", "FLAG{wrong}"))
        self.assertFalse(ws.matches_flag("web-sqli", ""))


class TestWebapp(TempHome):
    def setUp(self) -> None:
        super().setUp()
        self.ws = Workspace(self.home)
        self.server = make_server(0, self.ws)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)

    def test_listens_on_loopback_only(self):
        self.assertEqual(self.server.server_address[0], "127.0.0.1")

    def test_login_form(self):
        with urllib.request.urlopen(f"http://127.0.0.1:{self.port}/login", timeout=5) as r:
            self.assertIn('name="username"', r.read().decode())

    def test_wrong_password_is_rejected(self):
        status, body = post_login(self.port, "admin", "guess")
        self.assertEqual(status, 401)
        self.assertNotIn("FLAG{", body)

    def test_staff_login_works_but_has_no_flag(self):
        status, body = post_login(self.port, "alice", "wonderland")
        self.assertEqual(status, 200)
        self.assertIn("Welcome back, alice", body)
        self.assertNotIn("FLAG{", body)

    def test_sql_injection_logs_in_as_admin(self):
        for payload in INJECTIONS:
            with self.subTest(payload=payload):
                status, body = post_login(self.port, payload)
                self.assertEqual(status, 200)
                self.assertIn(self.ws.flag("web-sqli"), body)

    def test_quote_shows_a_database_error(self):
        status, body = post_login(self.port, "'")
        self.assertEqual(status, 500)
        self.assertIn("Database error", body)


class TestCli(TempHome):
    """End to end, the way a student runs it: separate processes."""

    def setUp(self) -> None:
        super().setUp()
        self.env = dict(os.environ, CYBERLAB_HOME=str(self.home), PYTHONPATH=str(V2))
        self.addCleanup(self.cyberlab, "stop")

    def cyberlab(self, *args: str, stdin: str = ""):
        return subprocess.run([sys.executable, "-m", "cyberlab", *args], input=stdin,
                              env=self.env, cwd=V2, capture_output=True, text=True, timeout=30)

    def start(self) -> int:
        r = self.cyberlab("start", "web-sqli")
        self.assertEqual(r.returncode, 0, r.stderr)
        return int(re.search(r"http://127\.0\.0\.1:(\d+)/login", r.stdout).group(1))

    def test_solve_web_sqli_end_to_end(self):
        port = self.start()
        status, body = post_login(port, "admin' --")
        flag = re.search(r"FLAG\{[0-9a-f]+\}", body).group(0)

        wrong = self.cyberlab("submit", "web-sqli", "FLAG{nope}")
        self.assertEqual(wrong.returncode, 1)
        self.assertIn("Not quite", wrong.stdout)

        right = self.cyberlab("submit", "web-sqli", flag)
        self.assertEqual(right.returncode, 0, right.stdout)
        self.assertIn("Correct", right.stdout)
        self.assertIn("[x] web-sqli", self.cyberlab("list").stdout)

    def test_start_twice_reuses_the_running_target(self):
        self.assertEqual(self.start(), self.start())

    def test_stop_stops_the_target(self):
        port = self.start()
        r = self.cyberlab("stop")
        self.assertIn("Stopped: webapp", r.stdout)
        deadline = time.monotonic() + 5
        while accepting(port) and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertFalse(accepting(port), "web app still listening after stop")
        self.assertIn("Nothing was running", self.cyberlab("stop").stdout)

    def test_hints_come_one_at_a_time(self):
        first = self.cyberlab("hint", "web-sqli").stdout
        self.assertIn("Hint 1/", first)
        self.assertNotIn("Hint 2/", first)
        self.assertIn("Hint 2/", self.cyberlab("hint", "web-sqli").stdout)

    def test_unknown_challenge_suggests_close_match(self):
        r = self.cyberlab("start", "web-sqlx")
        self.assertEqual(r.returncode, 2)
        self.assertIn("web-sqli", r.stderr)

    def test_reset_deletes_the_workspace(self):
        self.start()
        r = self.cyberlab("reset", "--yes")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse((self.home / ".state.json").exists())


@unittest.skipUnless(Path("/proc/self").exists(), "needs /proc (Linux) to tell processes apart")
class TestStopIsSafe(TempHome):
    def test_stop_never_kills_an_unrelated_process(self):
        sleeper = subprocess.Popen(["sleep", "30"])
        self.addCleanup(sleeper.kill)
        ws = Workspace(self.home)
        ws.state["targets"]["webapp"] = {"pid": sleeper.pid, "port": 1}  # e.g. a reused pid
        ws.save()
        self.assertEqual(targets.stop_all(ws), [])
        self.assertIsNone(sleeper.poll(), "stop killed a process that wasn't ours")


if __name__ == "__main__":
    unittest.main()
