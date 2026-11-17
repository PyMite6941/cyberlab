"""The learning page: one HTML file reviewing every challenge you've solved.

    cyberlab learn            writes ~/cyberlab/learn.html and opens it

Each solved challenge shows the vulnerability by name with a link to its
Wikipedia article, then the same debrief `cyberlab learn <id>` prints. Unsolved
challenges are listed by title only, so the page doesn't give answers away.
The page is a plain file with no scripts; only the Wikipedia links need internet.
"""

from __future__ import annotations

import html
from pathlib import Path

from cyberlab.challenges import Challenge, ordered
from cyberlab.workspace import Workspace

_STYLE = """
:root { --fg:#1c2430; --muted:#5b6675; --bg:#fff; --card:#f7f9fc; --line:#d5dbe3;
        --accent:#2b5797; --code:#f3f5f8; --vuln:#fff8e1; --vuln-line:#ffd54f; }
@media (prefers-color-scheme: dark) {
  :root { --fg:#e3e8ef; --muted:#9aa5b4; --bg:#14181f; --card:#1b212a; --line:#2e3744;
          --accent:#7aa7e8; --code:#10141a; --vuln:#2e2814; --vuln-line:#8a6d1a; }
}
body { font-family: system-ui, sans-serif; max-width: 48rem; margin: 2rem auto;
       padding: 0 1rem; line-height: 1.55; color: var(--fg); background: var(--bg); }
h1 { margin-bottom: .2rem; } a { color: var(--accent); }
.muted { color: var(--muted); }
nav ol { padding-left: 1.25rem; }
article { border-left: 4px solid var(--accent); background: var(--card);
          padding: .2rem 1rem 1rem; margin: 2rem 0; }
article h2 { margin-bottom: 0; } h3 { font-size: 1rem; margin: 1.2rem 0 .3rem; }
.vuln { background: var(--vuln); border: 1px solid var(--vuln-line); padding: .5rem .7rem; }
pre { background: var(--code); border: 1px solid var(--line); padding: .6rem;
      white-space: pre-wrap; word-break: break-word; }
ul { padding-left: 1.25rem; }
"""


def _e(text: str) -> str:
    return html.escape(text)


def _article(ws: Workspace, c: Challenge) -> str:
    solved = ws.state["solved"].get(c.id, "")[:10]
    out = [f'<article id="{_e(c.id)}">',
           f"<h2>{_e(c.title)}</h2>",
           f'<p class="muted">{_e(c.id)} · {_e(c.track)} · {_e(c.difficulty)}'
           f"{' · solved ' + _e(solved) if solved else ''}</p>",
           f'<p class="vuln"><strong>Vulnerability:</strong> {_e(c.vulnerability)}<br>'
           f'<a href="{_e(c.wiki)}" target="_blank" rel="noopener">'
           f"Read about it on Wikipedia</a></p>",
           f"<h3>What you did</h3><p>{_e(c.learned)}</p>",
           f"<h3>Why it matters in practice</h3><p>{_e(c.real_world)}</p>"]
    snippets = c.snippets(ws)
    if snippets:
        out.append("<h3>Commands to try</h3>")
        out.append('<p class="muted">Start the challenge first if its target isn\'t running: '
                   f"<code>cyberlab start {_e(c.id)}</code></p>")
        for label, command in snippets:
            out.append(f"<p>{_e(label)}</p><pre>{_e(command)}</pre>")
    if c.defend:
        out.append("<h3>How to defend</h3><ul>")
        out.extend(f"<li>{_e(item)}</li>" for item in c.defend)
        out.append("</ul>")
    if c.ap_unit and c.ap_topic:
        out.append(f"<h3>AP Cybersecurity</h3><p>{_e(c.ap_unit)}: {_e(c.ap_topic)}<br>"
                   f"Skills: {_e(', '.join(c.ap_skill) or 'Not specified')}</p>")
    out.append("</article>")
    return "\n".join(out)


def build(ws: Workspace) -> str:
    challenges = ordered()
    solved = [c for c in challenges if ws.is_solved(c.id)]
    todo = [c for c in challenges if not ws.is_solved(c.id)]
    body = [f"<h1>What you've learned</h1>",
            f'<p class="muted">{len(solved)} of {len(challenges)} challenges solved. '
            "Run <code>cyberlab learn</code> again after solving more to update this page.</p>"]
    if solved:
        body.append("<nav><ol>")
        body.extend(f'<li><a href="#{_e(c.id)}">{_e(c.vulnerability)}</a> '
                    f'<span class="muted">({_e(c.id)})</span></li>' for c in solved)
        body.append("</ol></nav>")
        body.extend(_article(ws, c) for c in solved)
    else:
        body.append("<p>Nothing solved yet. Start with <code>cyberlab start web-sqli</code>.</p>")
    if todo:
        body.append("<h2>Still to solve</h2><ul>")
        body.extend(f"<li><code>{_e(c.id)}</code> {_e(c.title)}</li>" for c in todo)
        body.append("</ul>")
    return ("<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\n"
            "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
            f"<title>cyberlab: what you've learned</title>\n<style>{_STYLE}</style></head>\n"
            "<body>\n" + "\n".join(body) + "\n</body></html>\n")


def write(ws: Workspace) -> Path:
    path = ws.path("learn.html")
    path.write_text(build(ws), encoding="utf-8")
    return path
