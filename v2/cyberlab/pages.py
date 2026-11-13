"""Shared HTML for the targets: one page shell and the "what just happened" box.

Every target's success page ends with a lesson box: what the student's input
did, the commands that reproduce it, and where the fixed version lives. The
same content, in more depth, is what `cyberlab learn <id>` prints.
"""

from __future__ import annotations

import html
from http.server import BaseHTTPRequestHandler
from typing import Dict, Iterable, Optional, Sequence, Tuple

from cyberlab.workspace import Workspace

HOST = "127.0.0.1"  # targets never listen anywhere else

_SHELL = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title} - {site}</title>
<style>
 body {{ font-family: system-ui, sans-serif; max-width: 46rem; margin: 2.5rem auto;
        padding: 0 1rem; line-height: 1.5; color: #1c2430; }}
 header {{ border-bottom: 2px solid #2b5797; margin-bottom: 1.5rem; }}
 header a {{ color: #2b5797; text-decoration: none; font-weight: 600; font-size: 1.4rem; }}
 nav a {{ margin-right: 1rem; }}
 input {{ display: block; margin: .3rem 0 1rem; padding: .4rem; width: 16rem; }}
 button {{ padding: .4rem 1rem; }}
 table {{ border-collapse: collapse; }} td, th {{ padding: .2rem .8rem; text-align: left; }}
 pre {{ background: #f3f5f8; border: 1px solid #d5dbe3; padding: .6rem; overflow-x: auto;
       white-space: pre-wrap; word-break: break-word; }}
 .flag {{ font-family: monospace; font-size: 1.1rem; background: #e8f5e9;
         border: 1px solid #81c784; padding: .5rem; }}
 .error {{ color: #a00; font-family: monospace; }}
 .muted {{ color: #5b6675; }}
 .lesson {{ border-left: 4px solid #2b5797; background: #f7f9fc; padding: .2rem 1rem 1rem;
           margin-top: 2rem; }}
 .lesson h2 {{ font-size: 1.1rem; }} .lesson h3 {{ font-size: 1rem; margin-bottom: .2rem; }}
 .lesson ul {{ padding-left: 1.25rem; }}
</style></head>
<body><header><a href="/">{site}</a></header>
<h1>{title}</h1>
{body}
</body></html>
"""


def page(site: str, title: str, body: str) -> bytes:
    """A full HTML page. `body` is trusted HTML: escape anything from the student
    before it gets here, unless leaving it raw is the point of the lab."""
    return _SHELL.format(site=html.escape(site), title=html.escape(title), body=body).encode()


def flag_box(flag: str) -> str:
    return f'<p class="flag">{html.escape(flag)}</p>'


def lesson(heading: str, paragraphs: Iterable[str],
           snippets: Sequence[Tuple[str, str]] = (), submit: str = "", code: str = "",
           real_world: str = "", defend: Iterable[str] = (), ap_unit: str = "",
           ap_topic: str = "", ap_skill: Iterable[str] = ()) -> str:
    """The "what just happened" box. Everything is escaped here, so callers
    pass plain text (including whatever the student typed). `code` is shown
    as a block right after the first paragraph (the query that ran, say)."""
    out = ['<section class="lesson">', f"<h2>{html.escape(heading)}</h2>"]
    for i, paragraph in enumerate(paragraphs):
        out.append(f"<p>{html.escape(paragraph)}</p>")
        if i == 0 and code:
            out.append(f"<pre>{html.escape(code)}</pre>")
    for label, command in snippets:
        out.append(f"<h3>{html.escape(label)}</h3><pre>{html.escape(command)}</pre>")
    if submit:
        out.append(f"<h3>Next</h3><pre>{html.escape(submit)}</pre>")
    if real_world:
        out.append(f"<h3>Why it matters in practice</h3><p>{html.escape(real_world)}</p>")
    advice = list(defend)
    if advice:
        out.append("<h3>How to defend</h3><ul>")
        out.extend(f"<li>{html.escape(item)}</li>" for item in advice)
        out.append("</ul>")
    skills = ", ".join(ap_skill)
    if ap_unit and ap_topic:
        out.append(f"<h3>AP Cybersecurity alignment</h3><p>{html.escape(ap_unit)}: "
                   f"{html.escape(ap_topic)}<br>Skills: "
                   f"{html.escape(skills or 'Not specified')}</p>")
    out.append("</section>")
    return "".join(out)


def challenge_lesson(challenge_id: str, heading: str, paragraphs: Iterable[str],
                     snippets: Sequence[Tuple[str, str]] = (), submit: str = "",
                     code: str = "") -> str:
    """Render endpoint content with the challenge's shared impact and defense notes."""
    from cyberlab.challenges import REGISTRY

    challenge = REGISTRY[challenge_id]
    return lesson(
        heading, paragraphs, snippets, submit, code,
        real_world=challenge.real_world, defend=challenge.defend,
        ap_unit=challenge.ap_unit, ap_topic=challenge.ap_topic,
        ap_skill=challenge.ap_skill,
    )


class LabHandler(BaseHTTPRequestHandler):
    """Base for the HTTP targets: `site` names the pretend site, `ws` is bound
    by bind()."""

    site = "Lab"
    ws: Workspace

    @property
    def port(self) -> int:
        return self.server.server_address[1]

    @property
    def base_url(self) -> str:
        return f"http://{HOST}:{self.port}"

    def send_page(self, status: int, title: str, body: str,
                  headers: Optional[Dict[str, str]] = None) -> None:
        self.send_bytes(status, page(self.site, title, body), "text/html; charset=utf-8", headers)

    def send_bytes(self, status: int, data: bytes, content_type: str,
                   headers: Optional[Dict[str, str]] = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def not_found(self) -> None:
        self.send_page(404, "Not found", "<p>Not found.</p>")

    def do_HEAD(self) -> None:  # noqa: N802 - scanners (nmap, gobuster, nikto) send HEAD
        self.do_GET()


def bind(handler: type, ws: Workspace) -> type:
    """The handler class with this workspace attached."""
    return type("Bound" + handler.__name__, (handler,), {"ws": ws})
