"""web-sqli: bypass a login form with SQL injection."""

from __future__ import annotations

from cyberlab import targets
from cyberlab.challenges import Challenge, register
from cyberlab.workspace import Workspace


class WebSqli(Challenge):
    def setup(self, ws: Workspace) -> str:
        port = targets.start(ws, "webapp")
        return f"Target: http://127.0.0.1:{port}/login"


register(WebSqli(
    id="web-sqli",
    title="SQL injection: log in as admin",
    track="web",
    difficulty="easy",
    goal=("The Northwind staff portal checks logins with a SQL query. Log in as "
          "admin without knowing the password. The admin console shows a flag."),
    hints=[
        "Try a single quote (') as the username. What does the error tell you about how the query is built?",
        "The query is roughly: SELECT ... WHERE username = '<you>' AND password = '<you>'. "
        "Can you end the username string early and make the rest of the line a comment?",
        "In SQL, -- starts a comment. Try the username  admin' --  with any password.",
    ],
    tools=["Firefox", "curl", "sqlmap"],
))
