"""web-xss: reflected cross-site scripting in the search box."""

from __future__ import annotations

from cyberlab import targets
from cyberlab.challenges import Challenge, register
from cyberlab.workspace import Workspace


class WebXss(Challenge):
    def setup(self, ws: Workspace) -> str:
        port = targets.start(ws, "webapp")
        return f"Target: http://127.0.0.1:{port}/search?q=widgets"


register(WebXss(
    id="web-xss",
    title="Reflected XSS in the search box",
    track="web",
    difficulty="easy",
    goal=("The catalog search echoes your query straight back into the page. Craft "
          "a search that makes the browser run your own markup. The page confirms it "
          "and shows a flag."),
    hints=[
        "Search for something, then view the page source. Where does your text land, and is it escaped?",
        "The query is dropped into the HTML as-is. Try closing the sentence with your own tag.",
        "A classic test payload is  <script>alert(1)</script>  as the q value "
        "(in a URL: /search?q=<script>alert(1)</script>).",
    ],
    tools=["Firefox", "curl"],
))
