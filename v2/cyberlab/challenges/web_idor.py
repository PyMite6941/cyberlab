"""web-idor: read another account's invoice by changing the id."""

from __future__ import annotations

from cyberlab import targets
from cyberlab.challenges import Challenge, register
from cyberlab.workspace import Workspace


class WebIdor(Challenge):
    def setup(self, ws: Workspace) -> str:
        port = targets.start(ws, "webapp")
        base = f"http://127.0.0.1:{port}"
        return (f"Target: {base}/login\n"
                "Log in as  alice / wonderland , then open 'Your invoice' (#1002).\n"
                "The admin's invoice is #1001.")


register(WebIdor(
    id="web-idor",
    title="IDOR: read the admin's invoice",
    track="web",
    difficulty="medium",
    goal=("Logged-in staff can view their own invoice at /invoice?id=1002. The admin's "
          "invoice (#1001) is off-limits in the UI, but the server never checks who owns "
          "the invoice you ask for. Read invoice #1001; its amount is the flag."),
    hints=[
        "After logging in, look at the URL of 'Your invoice'. What does the id number do?",
        "The server returns whatever invoice id you ask for, as long as you have a session cookie.",
        "Change the id in /invoice?id=1002 to 1001. In curl, send the session cookie: "
        "curl -b session=ok 'http://127.0.0.1:<port>/invoice?id=1001'",
    ],
    tools=["Firefox", "curl"],
))
