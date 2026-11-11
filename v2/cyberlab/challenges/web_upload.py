"""web-upload: slip a webshell past a weak extension filter."""

from __future__ import annotations

from cyberlab import targets
from cyberlab.challenges import Challenge, register
from cyberlab.workspace import Workspace


class WebUpload(Challenge):
    def setup(self, ws: Workspace) -> str:
        port = targets.start(ws, "webapp")
        return (f"Target: POST http://127.0.0.1:{port}/upload?file=<name>\n"
                "Try:    curl -X POST 'http://127.0.0.1:<port>/upload?file=shell.php'")


register(WebUpload(
    id="web-upload",
    title="Upload filter bypass",
    track="web",
    difficulty="hard",
    goal=("The upload endpoint blocks PHP webshells, but the filter only checks for one "
          "exact extension. Get a file the server will execute as PHP past it. A "
          "successful upload shows a flag."),
    hints=[
        "Upload shell.php and read the rejection. Exactly what does it block?",
        "It blocks the literal .php extension. Apache runs several other extensions as PHP too.",
        "Try an alternate PHP extension such as .phtml: "
        "curl -X POST 'http://127.0.0.1:<port>/upload?file=shell.phtml'",
    ],
    tools=["curl"],
))
