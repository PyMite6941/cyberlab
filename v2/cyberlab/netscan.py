"""A host with services nobody remembers, for the nmap lab.

It listens on 127.0.0.1 only and is started by `cyberlab start` as its own
process:

    python3 -m cyberlab.netscan --port 9000 --home ~/cyberlab

`--port` is the bottom of a 100-port window. Three services live in it:

    <port>          the public website everyone knows about (HTTP)
    <port> + a      an old FTP server (answers with a 220 banner)
    <port> + b      a maintenance console (HTTP): its page shows the flag

a and b are different for each student, so the only way to find the last two
is to scan the window:

    nmap -sV -p <port>-<port+99> 127.0.0.1
"""

from __future__ import annotations

import argparse
import socket
import threading
import time
from http.server import ThreadingHTTPServer
from pathlib import Path
from typing import Callable, List, Tuple

from cyberlab import pages
from cyberlab.pages import HOST
from cyberlab.workspace import Workspace

WINDOW = 100  # ports scanned: base .. base + WINDOW - 1
FTP_BANNER = b"220 Northwind FTP server (vsFTPd 3.0.3) ready.\r\n"


def offsets(ws: Workspace) -> Tuple[int, int]:
    """Where in the window this student's FTP server and console sit (1..99, distinct)."""
    ftp = 1 + int(ws.derive("net-nmap:ftp", 8), 16) % (WINDOW - 1)
    console = 1 + int(ws.derive("net-nmap:console", 8), 16) % (WINDOW - 2)
    if console >= ftp:
        console += 1
    return ftp, console


class PublicSite(pages.LabHandler):
    server_version = "nginx/1.18.0"
    sys_version = ""
    site = "Northwind Traders"

    def do_GET(self) -> None:  # noqa: N802
        if self.path.split("?", 1)[0] == "/":
            self.send_page(200, "Welcome", "<p>Northwind Traders: speciality foods, shipped worldwide.</p>"
                           '<p class="muted">This is the only service this host is supposed to run.</p>')
        else:
            self.not_found()


class Console(pages.LabHandler):
    server_version = "Northwind-Maintenance/0.9"
    sys_version = ""
    site = "Northwind maintenance console"

    def do_GET(self) -> None:  # noqa: N802
        if self.path.split("?", 1)[0] != "/":
            self.not_found()
            return
        base = self.server.base_port  # type: ignore[attr-defined]
        window = f"{base}-{base + WINDOW - 1}"
        body = ("<p>Maintenance console. No login configured.</p>"
                + pages.flag_box(self.ws.flag("net-nmap"))
                + pages.challenge_lesson("net-nmap",
                    "What you found",
                    [f"Nobody told you port {self.port} existed. A scan asked every port in the "
                     "range whether anything was listening, and this answered. A service on an "
                     "unusual port isn't hidden, only unadvertised, and here it was left running "
                     "with no login at all.",
                     "This is step one of almost every real intrusion and every real audit: find "
                     "out what is actually listening, because it's rarely just what the owner "
                     "thinks. The old FTP server in the same range is the same story: its banner "
                     "gives away the exact software and version, which is what an attacker "
                     "looks up known vulnerabilities for."],
                    [("Which ports are open, and what's running on them",
                      f"nmap -sV -p {window} {HOST}"),
                     ("Read a service's banner by hand",
                      f"nc {HOST} <ftp-port>"),
                     ("No nmap? bash can knock on every port itself",
                      f"for p in $(seq {base} {base + WINDOW - 1}); do\n"
                      f"  (exec 3<>/dev/tcp/{HOST}/$p) 2>/dev/null && echo \"open: $p\"\n"
                      "done")],
                    submit="cyberlab submit net-nmap " + self.ws.flag("net-nmap")))
        self.send_page(200, "Console", body)


class FtpBanner:
    """Just enough FTP for a scanner: greet, refuse every command, hang up on QUIT."""

    def __init__(self, port: int) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind((HOST, port))  # no SO_REUSEADDR: a busy port must fail, not be shared
        self.sock.listen(16)
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self) -> None:
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    @staticmethod
    def _serve(conn: socket.socket) -> None:
        with conn:
            try:
                conn.settimeout(10)
                conn.sendall(FTP_BANNER)
                while True:
                    line = conn.recv(1024)
                    if not line:
                        return
                    if line.strip().upper().startswith(b"QUIT"):
                        conn.sendall(b"221 Goodbye.\r\n")
                        return
                    conn.sendall(b"530 Please login with USER and PASS.\r\n")
            except OSError:
                return

    def close(self) -> None:
        self.sock.close()


def _first_free(base: int, wanted: int, taken: List[int], open_at: Callable[[int], object]):
    """Open a service at base+wanted, or the next free port in the window."""
    for step in range(WINDOW - 1):
        offset = 1 + (wanted - 1 + step) % (WINDOW - 1)
        if base + offset in taken:
            continue
        try:
            return base + offset, open_at(base + offset)
        except OSError:
            continue
    raise OSError(f"no free port between {base + 1} and {base + WINDOW - 1}")


def start_services(base: int, ws: Workspace):
    """Start all three services. Returns ({"web": port, "ftp": port, "console": port}, close)."""
    def http(handler: type) -> Callable[[int], ThreadingHTTPServer]:
        def open_at(port: int) -> ThreadingHTTPServer:
            server = ThreadingHTTPServer((HOST, port), pages.bind(handler, ws))
            assert server.server_address[0] == HOST, "netscan must only listen on 127.0.0.1"
            server.base_port = base  # type: ignore[attr-defined]
            threading.Thread(target=server.serve_forever, daemon=True).start()
            return server
        return open_at

    ftp_offset, console_offset = offsets(ws)
    web = http(PublicSite)(base)
    base = web.base_port = web.server_address[1]  # the real port, if asked for port 0
    ftp_port, ftp = _first_free(base, ftp_offset, [], FtpBanner)
    console_port, console = _first_free(base, console_offset, [ftp_port], http(Console))

    def close() -> None:
        ftp.close()
        for server in (web, console):
            server.shutdown()
            server.server_close()

    return {"web": web.server_address[1], "ftp": ftp_port, "console": console_port}, close


def main() -> int:
    parser = argparse.ArgumentParser(description="cyberlab multi-service target (127.0.0.1 only)")
    parser.add_argument("--port", type=int, default=9000, help="bottom of the 100-port window")
    parser.add_argument("--home", type=str, default=None)
    args = parser.parse_args()
    ports, close = start_services(args.port, Workspace(Path(args.home) if args.home else None))
    print(f"listening on {HOST}: {ports}", flush=True)
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass
    finally:
        close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
