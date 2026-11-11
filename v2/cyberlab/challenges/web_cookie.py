"""web-cookie: become admin by editing a role cookie."""

from __future__ import annotations

from cyberlab import targets
from cyberlab.challenges import Challenge, register
from cyberlab.workspace import Workspace


class WebCookie(Challenge):
    def setup(self, ws: Workspace) -> str:
        port = targets.start(ws, "webapp")
        base = f"http://127.0.0.1:{port}"
        return (f"Target: {base}/login\n"
                "Log in as  alice / wonderland , then open the dashboard.")


register(WebCookie(
    id="web-cookie",
    title="Privilege escalation via a role cookie",
    track="web",
    difficulty="medium",
    goal=("When you log in, the site remembers your role in a cookie and trusts it on "
          "the dashboard. Get the admin dashboard, which shows a flag, without admin "
          "credentials."),
    hints=[
        "After logging in as alice, look at your cookies. Which one decides what you can see?",
        "The dashboard reads the role from the cookie instead of from the server's session.",
        "Set the role cookie to admin and reload /dashboard. In curl: "
        "curl -b 'session=ok; role=admin' 'http://127.0.0.1:<port>/dashboard'",
    ],
    tools=["Firefox", "curl"],
))
