"""web-idor: read another user's record by changing an object identifier."""

from __future__ import annotations

from typing import List, Tuple

from cyberlab import targets
from cyberlab.challenges import Challenge, register
from cyberlab.workspace import Workspace


class WebIdor(Challenge):
    def setup(self, ws: Workspace) -> str:
        port = targets.start(ws, "webapp")
        return (f"Target: http://127.0.0.1:{port}/account?id=101\n"
                "The page simulates Alice's signed-in session. Change the record ID to "
                "view another user's data, then compare with /secure/account.")

    def snippets(self, ws: Workspace) -> List[Tuple[str, str]]:
        url = f"http://127.0.0.1:{targets.port_of(ws, 'webapp')}"
        return [
            ("Read the account assigned to Alice",
             f"curl -i '{url}/account?id=101'"),
            ("Change the object identifier in this local lab",
             f"curl -i '{url}/account?id=100'"),
            ("The corrected endpoint checks object ownership",
             f"curl -i '{url}/secure/account?id=100'"),
        ]


register(WebIdor(
    id="web-idor",
    title="IDOR: access another user's account",
    track="web",
    difficulty="easy",
    goal=("The page shows Alice's account record using an ID in the URL. Find the "
          "administrator's record by changing the ID, then submit the flag."),
    hints=[
        "The URL identifies Alice's record with id=101. Object identifiers are not "
        "authorization checks.",
        "Try the nearby account ID 100 in the provided local target.",
        "Compare /account?id=100 with /secure/account?id=100 to see the ownership check.",
    ],
    tools=["Firefox", "curl"],
    learned=("You changed the identifier for an object and the server returned someone "
             "else's record. Authentication tells the application who the requester is; "
             "authorization must separately decide whether that requester may access each "
             "specific object."),
    real_world=("Broken object-level authorization can expose invoices, profiles, "
                "medical records or private documents when an application trusts an ID "
                "from a URL or request body without checking ownership. The IDs need not "
                "be sequential for the underlying authorization mistake to exist."),
    defend=[
        "Check access on every object request: query the record using both its ID and the "
        "authenticated user's ownership or permission scope.",
        "Centralize authorization checks and test both allowed and denied user/object pairs.",
        "Return only the fields needed by the current view.",
        "Log and review repeated access-denied responses for suspicious enumeration.",
    ],
    ap_unit="Unit 5",
    ap_topic="5.2 Managerial Controls and Access Controls",
    ap_skill=["Analyze Risk", "Mitigate Risk"],
))
