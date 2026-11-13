"""web-gobuster: find a directory nothing links to.

setup() starts the webdirs target (127.0.0.1 only) and writes a wordlist of
common directory names into the student's workspace. One of those names,
different for each student, is a forgotten directory holding a database
backup; the flag is inside the backup.

    gobuster dir -u http://127.0.0.1:<port> -w wordlist.txt

The answer is the flag, so the lab can also be solved with a curl loop over
the wordlist when gobuster isn't installed.
"""

from __future__ import annotations

import shlex
from typing import List, Tuple

from cyberlab import targets, wordlists
from cyberlab.challenges import Challenge, register
from cyberlab.workspace import Workspace


class WebGobuster(Challenge):
    def _wordlist(self, ws: Workspace) -> str:
        return shlex.quote(str(ws.home / "web-gobuster" / "wordlist.txt"))

    def setup(self, ws: Workspace) -> str:
        port = targets.start(ws, "webdirs")
        wl = ws.path("web-gobuster", "wordlist.txt")
        wl.write_text("\n".join(wordlists.directory_wordlist(ws)) + "\n", encoding="utf-8")
        return (
            f"Target: http://127.0.0.1:{port}/\n"
            f"Wordlist: {wl}\n"
            "Somewhere on this site is a directory that no page links to. Find it, "
            "look at what's in it, and submit the flag:\n"
            f"  gobuster dir -u http://127.0.0.1:{port} -w {self._wordlist(ws)}"
        )

    def snippets(self, ws: Workspace) -> List[Tuple[str, str]]:
        url = f"http://127.0.0.1:{targets.port_of(ws, 'webdirs')}"
        wl = self._wordlist(ws)
        return [
            ("Ask for every name in the wordlist and report what isn't a 404",
             f"gobuster dir -u {url} -w {wl}"),
            ("The same thing with curl, to see there's no magic in it",
             "while read -r word; do\n"
             f"  code=$(curl -s -o /dev/null -w '%{{http_code}}' {url}/$word)\n"
             "  [ \"$code\" != 404 ] && echo \"$code /$word\"\n"
             f"done < {wl}"),
            ("Always read robots.txt: it lists what the owner didn't want found",
             f"curl -s {url}/robots.txt"),
            ("Look for backup files by extension as well as directories",
             f"gobuster dir -u {url} -w {wl} -x sql,bak,zip,old"),
        ]


register(WebGobuster(
    id="web-gobuster",
    title="Find the forgotten directory with gobuster",
    track="web",
    difficulty="medium",
    goal=("The Northwind public site has a directory left over from a redesign. No page "
          "links to it. Find it by trying names from a wordlist, look inside, and submit "
          "the flag you find there."),
    hints=[
        "A web server answers every path with a status code. Ask for one that can't exist "
        "and one that does (/about): 404 and 200. Now you can test any name.",
        "gobuster does that for a whole wordlist: gobuster dir -u http://127.0.0.1:<port> "
        "-w <wordlist>. Read the Status column: 200 is readable, 403 exists but is locked.",
        "One 200 isn't linked from the home page and isn't empty. Open it in Firefox or with "
        "curl. It lists a file; the flag is inside that file.",
    ],
    tools=["gobuster", "curl", "Firefox"],
    learned=("You found a directory by guessing its name. The server answers 404 for "
             "paths that don't exist and something else for paths that do, so a wordlist "
             "and a loop map out everything on the site, linked or not. The directory held "
             "a database backup with the admin's API token in it."),
    real_world=("Real sites are full of leftovers: backup.zip, /old, /.git, /staging, a "
                "phpinfo page, an admin panel 'nobody knows about'. Attackers and scanners "
                "run these wordlists against every site on the internet, all day. A forgotten "
                "backup is often the whole breach, because it holds the database, the "
                "source code and the passwords in one download."),
    defend=[
        "Don't keep backups, dumps or old copies of the site inside the web root at all.",
        "Protect what must be there with real authentication. An unlinked URL isn't a secret.",
        "Turn off directory listings (autoindex) so finding a folder doesn't reveal its files.",
        "Watch the access log: thousands of 404s from one address in a minute is this attack.",
        "Run gobuster against your own site before someone else does.",
    ],
    ap_unit="Unit 5",
    ap_topic="5.1 Application and Data Vulnerabilities and Attacks",
    ap_skill=["Analyze Risk", "Detect Attacks"],
))
