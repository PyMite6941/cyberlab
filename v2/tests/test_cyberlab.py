"""Tests for cyberlab v2. Standard library only:

    cd v2 && python3 -m unittest discover -s tests -v
"""

from __future__ import annotations

import getpass
import json
import os
import re
import shlex
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
from unittest import mock

V2 = Path(__file__).resolve().parent.parent
REPO_ROOT = V2.parent
sys.path.insert(0, str(V2))

from cyberlab import report, targets  # noqa: E402
from cyberlab.challenges import REGISTRY, ordered  # noqa: E402
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


def get(port: int, path: str, cookies: str = ""):
    """GET a path (optionally with a Cookie header); return (status, body)."""
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}")
    if cookies:
        req.add_header("Cookie", cookies)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def post(port: int, path: str):
    """POST a path with an empty body; return (status, body)."""
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", data=b"", timeout=5) as r:
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

    # web-xss
    def test_plain_search_has_no_flag(self):
        status, body = get(self.port, "/search?q=widgets")
        self.assertEqual(status, 200)
        self.assertIn("widgets", body)
        self.assertNotIn("FLAG{", body)

    def test_script_payload_is_reflected_and_flags(self):
        for payload in ("<script>alert(1)</script>", "<img src=x onerror=alert(1)>"):
            with self.subTest(payload=payload):
                status, body = get(self.port, "/search?q=" + urllib.parse.quote(payload))
                self.assertEqual(status, 200)
                self.assertIn(payload, body)  # reflected unescaped
                self.assertIn(self.ws.flag("web-xss"), body)

    def test_escaped_search_would_not_flag(self):
        # If the student only types text (no real tag), there is no XSS and no flag.
        status, body = get(self.port, "/search?q=" + urllib.parse.quote("not a <tag"))
        self.assertNotIn("FLAG{", body)

    # web-idor
    def test_invoice_needs_a_session(self):
        status, body = get(self.port, "/invoice?id=1001")
        self.assertEqual(status, 401)
        self.assertNotIn("FLAG{", body)

    def test_own_invoice_has_no_flag(self):
        status, body = get(self.port, "/invoice?id=1002", cookies="session=ok")
        self.assertEqual(status, 200)
        self.assertIn("$420.00", body)
        self.assertNotIn("FLAG{", body)

    def test_idor_reads_the_admin_invoice(self):
        status, body = get(self.port, "/invoice?id=1001", cookies="session=ok")
        self.assertEqual(status, 200)
        self.assertIn(self.ws.flag("web-idor"), body)

    # web-cookie
    def test_staff_dashboard_has_no_flag(self):
        status, body = get(self.port, "/dashboard", cookies="session=ok; role=staff")
        self.assertEqual(status, 200)
        self.assertNotIn("FLAG{", body)

    def test_admin_role_cookie_unlocks_the_dashboard(self):
        status, body = get(self.port, "/dashboard", cookies="session=ok; role=admin")
        self.assertEqual(status, 200)
        self.assertIn(self.ws.flag("web-cookie"), body)

    def test_login_sets_the_role_cookie(self):
        with urllib.request.urlopen(f"http://127.0.0.1:{self.port}/login",
                                    data=urllib.parse.urlencode(
                                        {"username": "alice", "password": "wonderland"}).encode(),
                                    timeout=5) as r:
            cookies = r.headers.get_all("Set-Cookie") or []
        self.assertTrue(any("role=staff" in c for c in cookies))

    # web-upload
    def test_php_upload_is_rejected(self):
        status, body = post(self.port, "/upload?file=shell.php")
        self.assertEqual(status, 403)
        self.assertNotIn("FLAG{", body)

    def test_jpg_upload_is_accepted_without_a_flag(self):
        status, body = post(self.port, "/upload?file=cat.jpg")
        self.assertEqual(status, 200)
        self.assertNotIn("FLAG{", body)

    def test_phtml_bypasses_the_filter(self):
        for name in ("shell.phtml", "shell.php5", "x.pht"):
            with self.subTest(name=name):
                status, body = post(self.port, "/upload?file=" + name)
                self.assertEqual(status, 200)
                self.assertIn(self.ws.flag("web-upload"), body)


class TestChallenges(TempHome):
    def test_web_track_is_registered(self):
        for cid in ("web-sqli", "web-xss", "web-idor", "web-cookie", "web-upload"):
            self.assertIn(cid, REGISTRY)

    def test_every_challenge_flag_is_distinct(self):
        ws = Workspace(self.home)
        flags = [ws.flag(cid) for cid in REGISTRY]
        self.assertEqual(len(flags), len(set(flags)))


class TestCli(TempHome):
    """End to end, the way a student runs it: separate processes."""

    def setUp(self) -> None:
        super().setUp()
        self.env = dict(os.environ, CYBERLAB_HOME=str(self.home), PYTHONPATH=str(V2))
        self.addCleanup(self.cyberlab, "stop")

    def cyberlab(self, *args: str, stdin: str = ""):
        return subprocess.run([sys.executable, "-m", "cyberlab", *args], input=stdin,
                              env=self.env, cwd=REPO_ROOT, capture_output=True, text=True, timeout=30)

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


class TestReport(TempHome):
    def test_fresh_workspace(self):
        data = report.build(Workspace(self.home), name="Alex P")
        self.assertEqual((data["student"], data["solved"], data["total"]), ("Alex P", 0, len(REGISTRY)))
        self.assertTrue(all(not c["solved"] and c["hints_used"] == 0 for c in data["challenges"]))

    def test_solved_and_hints_are_reported(self):
        ws = Workspace(self.home)
        ws.record_hint("web-sqli", 99)  # more than exist: capped
        ws.mark_solved("web-sqli")
        row = next(c for c in report.build(ws)["challenges"] if c["id"] == "web-sqli")
        self.assertTrue(row["solved"] and row["solved_at"])
        self.assertEqual(row["hints_used"], row["hints_total"])
        self.assertIn("Solved 1 of", report.as_text(report.build(ws)))

    def test_default_name_is_the_login_name(self):
        self.assertEqual(report.build(Workspace(self.home))["student"], getpass.getuser())

    def test_workspace_id_is_stable_and_hides_the_secret(self):
        ws = Workspace(self.home)
        wid = report.workspace_id(ws)
        self.assertRegex(wid, r"^[0-9a-f]{10}$")
        self.assertEqual(report.workspace_id(Workspace(self.home)), wid)
        other = Path(tempfile.mkdtemp(prefix="cyberlab-test-"))
        self.addCleanup(shutil.rmtree, other, True)
        self.assertNotEqual(report.workspace_id(Workspace(other)), wid)
        data = report.build(ws)
        for text in (report.as_text(data), report.as_json(data)):
            self.assertNotIn(ws.state["secret"], text)
            self.assertNotIn(ws.state["secret"][:10], text)
            self.assertNotIn(ws.flag("web-sqli"), text)

    def test_cli_report_text_json_and_file(self):
        env = dict(os.environ, CYBERLAB_HOME=str(self.home), PYTHONPATH=str(V2))

        def run(*args):
            return subprocess.run([sys.executable, "-m", "cyberlab", "report", *args], env=env,
                                  cwd=V2, capture_output=True, text=True, timeout=30)

        r = run("--name", "Alex P")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("Student:    Alex P", r.stdout)
        self.assertIn("web-sqli", r.stdout)
        self.assertNotIn("--name", r.stderr)

        out = self.home / "alex.json"
        r = run("--name", "Alex P", "--json", "-o", str(out))
        self.assertIn(f"Saved your report to {out}", r.stdout)
        self.assertEqual(json.loads(out.read_text())["student"], "Alex P")

        self.assertIn("--name", run().stderr)  # no name given: says how to set one


import struct  # noqa: E402

from cyberlab import pcap  # noqa: E402
from cyberlab.challenges import REGISTRY as _REG  # noqa: E402


def read_pcap(path):
    """Minimal pcap reader: list of dicts with src/dst ip, proto, ports, flags,
    dns query name, and tcp payload. Enough to prove a challenge's answer is in
    the capture without any third-party library."""
    data = Path(path).read_bytes()
    assert struct.unpack("<I", data[:4])[0] == 0xA1B2C3D4, "bad pcap magic"
    out, off = [], 24
    while off < len(data):
        incl = struct.unpack("<I", data[off + 8:off + 12])[0]
        frame = data[off + 16:off + 16 + incl]
        off += 16 + incl
        assert frame[12:14] == b"\x08\x00", "not IPv4"
        ihl = (frame[14] & 0x0F) * 4
        proto = frame[23]
        src = ".".join(str(b) for b in frame[26:30])
        dst = ".".join(str(b) for b in frame[30:34])
        l4 = 14 + ihl
        rec = {"src": src, "dst": dst, "proto": proto,
               "sport": struct.unpack("!H", frame[l4:l4 + 2])[0],
               "dport": struct.unpack("!H", frame[l4 + 2:l4 + 4])[0],
               "flags": 0, "dns": None, "payload": b"",
               "icmp_type": None, "icmp_id": None, "icmp_seq": None}
        if proto == pcap.PROTO_ICMP:
            rec["icmp_type"] = frame[l4]
            rec["icmp_id"] = struct.unpack("!H", frame[l4 + 4:l4 + 6])[0]
            rec["icmp_seq"] = struct.unpack("!H", frame[l4 + 6:l4 + 8])[0]
        elif proto == pcap.PROTO_UDP and rec["dport"] == 53:
            q, i = [], l4 + 8 + 12  # skip UDP(8) + DNS header(12)
            while frame[i]:
                n = frame[i]; q.append(frame[i + 1:i + 1 + n].decode()); i += 1 + n
            rec["dns"] = ".".join(q)
        elif proto == pcap.PROTO_TCP:
            rec["flags"] = frame[l4 + 13]
            dataofs = (frame[l4 + 12] >> 4) * 4
            rec["payload"] = frame[l4 + dataofs:]
        out.append(rec)
    return out


class TestPcap(unittest.TestCase):
    def test_roundtrip(self):
        path = Path(tempfile.mkdtemp(prefix="cyberlab-test-")) / "c.pcap"
        self.addCleanup(shutil.rmtree, path.parent, True)
        pcap.write_pcap(str(path), [
            pcap.udp_dns(0.0, "10.0.0.5", "8.8.8.8", 5000, "google.com"),
            pcap.tcp_syn(0.1, "10.0.0.9", "10.0.0.5", 5001, 22),
            pcap.tcp_data(0.2, "10.0.0.5", "10.0.0.6", 5002, 80, "password=hunter2"),
        ])
        recs = read_pcap(path)
        self.assertEqual(recs[0]["dns"], "google.com")
        self.assertTrue(recs[1]["flags"] & pcap.SYN and not recs[1]["flags"] & pcap.ACK)
        self.assertIn(b"password=hunter2", recs[2]["payload"])


class TestNetworkChallenges(TempHome):
    def test_registered(self):
        for cid in ("net-http-creds", "net-port-scan", "net-dns-tunnel"):
            self.assertIn(cid, _REG)

    def test_http_creds_password_is_in_the_capture(self):
        ws = Workspace(self.home)
        c = _REG["net-http-creds"]
        out = c.setup(ws)
        path = out.split("Capture:", 1)[1].split("\n", 1)[0].strip()
        payloads = b"".join(r["payload"] for r in read_pcap(path))
        self.assertIn(c._password(ws).encode(), payloads)
        self.assertTrue(c.check(ws, c._password(ws)))
        self.assertTrue(c.check(ws, "  " + c._password(ws) + "\n"))
        self.assertFalse(c.check(ws, "N0rth-000000"))

    def test_port_scan_source_is_the_busiest_syn_sender(self):
        ws = Workspace(self.home)
        c = _REG["net-port-scan"]
        path = c.setup(ws).split("Capture:", 1)[1].split("\n", 1)[0].strip()
        from collections import defaultdict
        ports = defaultdict(set)
        for r in read_pcap(path):
            if r["proto"] == pcap.PROTO_TCP and r["flags"] & pcap.SYN and not r["flags"] & pcap.ACK:
                ports[r["src"]].add(r["dport"])
        busiest = max(ports, key=lambda ip: len(ports[ip]))
        self.assertEqual(busiest, c._scanner_ip(ws))
        self.assertTrue(c.check(ws, c._scanner_ip(ws)))
        self.assertFalse(c.check(ws, "10.0.0.1"))

    def test_dns_tunnel_domain_is_the_most_queried(self):
        ws = Workspace(self.home)
        c = _REG["net-dns-tunnel"]
        path = c.setup(ws).split("Capture:", 1)[1].split("\n", 1)[0].strip()
        from collections import Counter
        registered = Counter()
        for r in read_pcap(path):
            if r["dns"]:
                registered[".".join(r["dns"].split(".")[-2:])] += 1
        self.assertEqual(registered.most_common(1)[0][0], c._domain(ws))
        self.assertTrue(c.check(ws, c._domain(ws).upper() + "."))
        self.assertFalse(c.check(ws, "google.com"))


class TestLogChallenges(TempHome):
    """Each log challenge: the answer must be findable in the generated log,
    the way a student would grep for it."""

    def _log_path(self, cid):
        out = REGISTRY[cid].setup(Workspace(self.home))
        return Path(out.split("Log:", 1)[1].split("\n", 1)[0].strip())

    def test_ssh_brute_ip_is_the_busiest_failed_source(self):
        from collections import Counter
        c = REGISTRY["log-ssh-brute"]
        text = self._log_path("log-ssh-brute").read_text()
        fails = Counter(re.findall(r"Failed password .*? from ([0-9.]+)", text))
        self.assertEqual(fails.most_common(1)[0][0], c._attacker_ip(Workspace(self.home)))
        # and that IP eventually logs in
        self.assertIn(f"Accepted password for root from {c._attacker_ip(Workspace(self.home))}", text)
        self.assertTrue(c.check(Workspace(self.home), c._attacker_ip(Workspace(self.home))))
        self.assertFalse(c.check(Workspace(self.home), "10.0.0.20"))

    def test_web_scan_secret_path_is_the_only_scanner_200(self):
        c = REGISTRY["log-web-scan"]
        text = self._log_path("log-web-scan").read_text()
        hits = re.findall(r'curl.*', text)  # scanner lines use curl UA
        got200 = [re.search(r'"GET (\S+) HTTP/1.1" 200', ln) for ln in text.splitlines() if "curl" in ln]
        paths = [m.group(1) for m in got200 if m]
        self.assertEqual(paths, [c._secret_path(Workspace(self.home))])
        self.assertTrue(c.check(Workspace(self.home), c._secret_path(Workspace(self.home))))
        self.assertTrue(c.check(Workspace(self.home), c._secret_path(Workspace(self.home)).rstrip("/")))
        self.assertFalse(c.check(Workspace(self.home), "/admin"))

    def test_sudo_esc_user_is_the_non_admin_who_got_root(self):
        c = REGISTRY["log-sudo-esc"]
        text = self._log_path("log-sudo-esc").read_text()
        culprit = c._culprit(Workspace(self.home))
        self.assertRegex(text, rf"sudo: {culprit} : .*COMMAND=/bin/bash")
        self.assertIn(f"session opened for user root by {culprit}", text)
        for admin in ("alice", "dsingh"):
            self.assertNotRegex(text, rf"sudo: {admin} : .*COMMAND=/bin/bash")
        self.assertTrue(c.check(Workspace(self.home), culprit.upper()))
        self.assertFalse(c.check(Workspace(self.home), "alice"))


class TestIcmpChallenges(TempHome):
    """ICMP / smurf challenges: the answer must be present in the capture."""

    def _cap(self, cid):
        out = REGISTRY[cid].setup(Workspace(self.home))
        return read_pcap(out.split("Capture:", 1)[1].split("\n", 1)[0].strip())

    def test_icmp_echo_one_reply_from_the_responder(self):
        c = REGISTRY["net-icmp-echo"]
        replies = [r for r in self._cap("net-icmp-echo") if r["icmp_type"] == 0]
        self.assertEqual(len(replies), 1)
        self.assertEqual(replies[0]["src"], c._responder(Workspace(self.home)))
        self.assertTrue(c.check(Workspace(self.home), c._responder(Workspace(self.home))))
        self.assertFalse(c.check(Workspace(self.home), "198.51.100.99"))

    def test_smurf_victim_receives_all_the_replies(self):
        from collections import Counter
        c = REGISTRY["net-smurf-victim"]
        victim = c._victim(Workspace(self.home))
        recs = self._cap("net-smurf-victim")
        reply_dsts = Counter(r["dst"] for r in recs if r["icmp_type"] == 0)
        self.assertEqual(reply_dsts.most_common(1)[0][0], victim)
        # the victim is forged as the source of the broadcast requests, and never replies
        self.assertTrue(any(r["icmp_type"] == 8 and r["src"] == victim
                            and r["dst"].endswith(".255") for r in recs))
        self.assertNotIn(victim, [r["src"] for r in recs if r["icmp_type"] == 0])
        self.assertTrue(c.check(Workspace(self.home), victim))
        self.assertFalse(c.check(Workspace(self.home), "192.0.2.1"))

    def test_smurf_amp_distinct_reflector_count(self):
        c = REGISTRY["net-smurf-amp"]
        _, victim, reflectors = c._reflectors(Workspace(self.home))
        recs = self._cap("net-smurf-amp")
        reply_srcs = {r["src"] for r in recs if r["icmp_type"] == 0 and r["dst"] == victim}
        self.assertEqual(reply_srcs, set(reflectors))
        # replies == reflectors x requests (3)
        n_replies = sum(1 for r in recs if r["icmp_type"] == 0 and r["dst"] == victim)
        self.assertEqual(n_replies, len(reflectors) * 3)
        self.assertTrue(c.check(Workspace(self.home), str(len(reflectors))))
        self.assertFalse(c.check(Workspace(self.home), str(len(reflectors) + 1)))
        self.assertFalse(c.check(Workspace(self.home), "lots"))


class TestMenu(TempHome):
    """The guided menu, driven the way a student types into it."""

    def setUp(self) -> None:
        super().setUp()
        self.env = dict(os.environ, CYBERLAB_HOME=str(self.home), PYTHONPATH=str(V2))
        self.addCleanup(lambda: subprocess.run(
            [sys.executable, "-m", "cyberlab", "stop"], env=self.env, cwd=V2,
            capture_output=True, text=True, timeout=30))

    def menu(self, keys: str):
        return subprocess.run([sys.executable, "-m", "cyberlab", "menu"], input=keys,
                              env=self.env, cwd=V2, capture_output=True, text=True, timeout=30)

    def test_quit_shows_welcome_and_the_tracks(self):
        r = self.menu("q\n")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("Welcome to cyberlab", r.stdout)
        self.assertIn("Web Application Security", r.stdout)
        self.assertIn("Bye.", r.stdout)

    def test_ctrl_d_quits(self):
        r = self.menu("")  # empty stdin -> EOF at the first prompt
        self.assertEqual(r.returncode, 0)
        self.assertIn("Bye.", r.stdout)

    def test_bad_choice_is_rejected(self):
        r = self.menu("zzz\nq\n")
        self.assertIn("Please type a challenge number", r.stdout)

    def test_open_and_solve_a_challenge(self):
        order = [c.id for c in ordered()]
        n = order.index("net-http-creds") + 1
        pw = REGISTRY["net-http-creds"]._password(Workspace(self.home))
        r = self.menu(f"{n}\ns\n{pw}\nq\n")
        self.assertIn("Password in cleartext HTTP", r.stdout)   # opened it
        self.assertIn("Correct! Challenge solved.", r.stdout)
        # progress persisted
        listing = subprocess.run([sys.executable, "-m", "cyberlab", "list"], env=self.env,
                                 cwd=V2, capture_output=True, text=True, timeout=30).stdout
        self.assertIn("[x] net-http-creds", listing)

    def test_hint_is_shown_on_request(self):
        n = [c.id for c in ordered()].index("web-sqli") + 1
        r = self.menu(f"{n}\nh\nb\nq\n")
        self.assertIn("Hint 1/", r.stdout)


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


class TestDictJohn(TempHome):
    """Logic tests for the John the Ripper dictionary-attack challenge."""

    def _paths(self, ws, details):
        lines = details.splitlines()
        hash_path = lines[0].split("Hash file: ", 1)[1].strip()
        word_path = lines[1].split("Wordlist:  ", 1)[1].strip()
        return hash_path, word_path

    def test_setup_writes_wordlist_and_hash(self):
        ws = Workspace(self.home)
        c = REGISTRY["dict-john"]
        details = c.setup(ws)
        hash_path, word_path = self._paths(ws, details)
        self.assertTrue(Path(hash_path).exists(), hash_path)
        self.assertTrue(Path(word_path).exists(), word_path)

        # The password is in the wordlist.
        words = Path(word_path).read_text().split()
        pw = c._password(ws)
        self.assertIn(pw, words)

        # The hash is the MD5 of the password.
        line = Path(hash_path).read_text().strip()
        self.assertEqual(line, f"admin:{__import__('hashlib').md5(pw.encode()).hexdigest()}")

    def test_setup_quotes_paths_in_commands(self):
        ws = Workspace(self.home / "student files")
        c = REGISTRY["dict-john"]
        details = c.setup(ws)
        hash_path, word_path = self._paths(ws, details)
        commands = [shlex.split(line.strip()) for line in details.splitlines()
                    if line.strip().startswith("john ")]

        self.assertEqual(commands[0][2], f"--wordlist={word_path}")
        self.assertEqual(commands[0][3], hash_path)
        self.assertEqual(commands[1], ["john", "--show", hash_path])

    def test_check_accepts_correct_and_rejects_wrong(self):
        ws = Workspace(self.home)
        c = REGISTRY["dict-john"]
        pw = c._password(ws)
        self.assertTrue(c.check(ws, pw))
        self.assertTrue(c.check(ws, "  " + pw + "\n"))
        self.assertFalse(c.check(ws, "wrongpassword"))
        self.assertFalse(c.check(ws, ""))


class TestHttpAuth(TempHome):
    """Logic tests for the dictionary-attack login target (separate from web-sqli)."""

    def setUp(self):
        super().setUp()
        self.ws = Workspace(self.home)
        import cyberlab.httpauth as _ha

        self.server = _ha.make_server(0, self.ws)
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

    def test_correct_password_shows_the_flag(self):
        _, pw = __import__("cyberlab.httpauth", fromlist=["make_credentials"]).make_credentials(self.ws)
        status, body = post_login(self.port, "admin", pw)
        self.assertEqual(status, 200)
        self.assertIn(self.ws.flag("dict-hydra"), body)
        self.assertIn("Welcome back, admin", body)


class TestDictHydra(TempHome):
    """Logic tests for the Hydra dictionary-attack challenge."""

    def test_password_matches_httpauth_target(self):
        # dict-hydra and httpauth must derive the same password so Hydra's
        # recovered password is the answer this challenge expects.
        import cyberlab.httpauth as ha

        ws = Workspace(self.home)
        _, pw = ha.make_credentials(ws)
        c = REGISTRY["dict-hydra"]
        self.assertEqual(c._password(ws), pw)

    def test_setup_quotes_form_and_wordlist_for_the_shell(self):
        ws = Workspace(self.home / "student files")
        c = REGISTRY["dict-hydra"]
        with mock.patch("cyberlab.challenges.dict_hydra.targets.start", return_value=8091) as start:
            details = c.setup(ws)

        command = next(line.strip() for line in details.splitlines()
                       if line.strip().startswith("hydra "))
        args = shlex.split(command)
        form = "/login:username=^USER^&password=^PASS^:F=Invalid username or password"
        module_index = args.index("http-post-form")

        start.assert_called_once_with(ws, "httpauth")
        self.assertEqual(args[args.index("-P") + 1], str(ws.path("dict-hydra", "wordlist.txt")))
        self.assertEqual(args[module_index + 1], form)
        self.assertEqual(module_index + 2, len(args))

    def test_check_accepts_correct_and_rejects_wrong(self):
        ws = Workspace(self.home)
        c = REGISTRY["dict-hydra"]
        pw = c._password(ws)
        self.assertTrue(c.check(ws, pw))
        self.assertTrue(c.check(ws, "  " + pw + "\n"))
        self.assertFalse(c.check(ws, "wrongpassword"))
        self.assertFalse(c.check(ws, ""))


if __name__ == "__main__":
    unittest.main()
