"""Debriefs: what each challenge's attack was, why it worked, and how it's defended.

A Lesson is unlocked once its challenge is solved (`cyberlab learn <id>`), and
the web target serves the same content at /learn/<id>. Each lesson answers
the same questions in the same order:

    1. What you attacked      which part of the system was the weak link
    2. How the attack works   step by step, with the real code or packets
    3. Why it was attackable  the mistake that made it possible
    4. How it's defended today
    5. Spot it as a defender  what the attack looks like in logs or traffic

and then ties the challenge to the AP Cybersecurity course framework and
lists online tutorials for going further. The lab itself stays offline: the
links are optional reading, nothing here fetches them.

Lesson bodies are lists of blocks: a str is a paragraph, Code is a code
listing, Bullets is a bulleted list. In Code, text between « and » is
highlighted as "this part came from the attacker".
"""

from __future__ import annotations

import html
import textwrap
from dataclasses import dataclass, field
from typing import Dict, List, Tuple, Union

from cyberlab.lessons.ced import CED, CED_SOURCE, CED_URL, UNITS


@dataclass
class Code:
    text: str
    caption: str = ""


@dataclass
class Bullets:
    items: List[str]


Block = Union[str, Code, Bullets]


@dataclass
class Lesson:
    id: str                       # the challenge id it debriefs
    title: str
    summary: str                  # one or two sentences: what the student just did
    attacked: List[Block]
    how: List[Block]
    why: List[Block]
    defend: List[Block]
    detect: List[Block] = field(default_factory=list)
    ced: List[str] = field(default_factory=list)                # framework codes, e.g. "5.1.B.4"
    links: List[Tuple[str, str]] = field(default_factory=list)  # (title, url) online tutorials


SECTIONS = [
    ("attacked", "What you attacked"),
    ("how", "How the attack works"),
    ("why", "Why it was attackable"),
    ("defend", "How it's defended today"),
    ("detect", "Spot it as a defender"),
]

LESSONS: Dict[str, Lesson] = {}


def register(lesson: Lesson) -> Lesson:
    if lesson.id in LESSONS:
        raise ValueError(f"duplicate lesson id: {lesson.id}")
    for code in lesson.ced:
        if code not in CED:
            raise ValueError(f"{lesson.id}: unknown framework code {code}")
    LESSONS[lesson.id] = lesson
    return lesson


def unlock_key(ws, challenge_id: str) -> str:
    """The key a target puts in its 'read the debrief' link once it's been exploited."""
    return ws.derive("learn:" + challenge_id, 12)


def unlocked(ws, challenge_id: str, key: str = "") -> bool:
    return ws.is_solved(challenge_id) or (bool(key) and key == unlock_key(ws, challenge_id))


# ----- plain text (the terminal) -----

def _plain(text: str) -> str:
    return text.replace("«", "").replace("»", "")


def _text_blocks(blocks: List[Block], width: int) -> List[str]:
    out: List[str] = []
    for block in blocks:
        if isinstance(block, Code):
            if block.caption:
                out.append(textwrap.fill(block.caption + ":", width, initial_indent="  ",
                                         subsequent_indent="  "))
            out.extend("      " + line for line in _plain(block.text).strip("\n").splitlines())
        elif isinstance(block, Bullets):
            for item in block.items:
                out.append(textwrap.fill(_plain(item), width, initial_indent="  - ",
                                         subsequent_indent="    "))
        else:
            out.append(textwrap.fill(_plain(block), width, initial_indent="  ",
                                     subsequent_indent="  "))
        out.append("")
    return out


def render_text(lesson: Lesson, width: int = 78) -> str:
    lines = [f"Debrief: {lesson.title}", "=" * min(width, 9 + len(lesson.title)), ""]
    lines.append(textwrap.fill(lesson.summary, width))
    lines.append("")
    for n, (attr, heading) in enumerate(SECTIONS, 1):
        blocks = getattr(lesson, attr)
        if not blocks:
            continue
        lines.append(f"{n}. {heading}")
        lines.append("")
        lines.extend(_text_blocks(blocks, width))
    if lesson.ced:
        lines.append("AP Cybersecurity connections")
        lines.append("")
        for code in lesson.ced:
            unit = UNITS[code[0]]
            lines.append(textwrap.fill(f"{code}  (Unit {code[0]}, {unit}) {CED[code]}", width,
                                       initial_indent="  ", subsequent_indent="      "))
        lines.append("")
        lines.append(textwrap.fill(f"Codes are from the {CED_SOURCE}; the wording here is a "
                                   "summary, not a quotation.", width, initial_indent="  ",
                                   subsequent_indent="  "))
        lines.append("")
    if lesson.links:
        lines.append("Go further (online, optional)")
        lines.append("")
        for title, url in lesson.links:
            lines.append(f"  - {title}")
            lines.append(f"    {url}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


# ----- HTML (the web target's /learn pages, and `cyberlab learn --html`) -----

STYLE = """
 :root { color-scheme: light dark; --fg:#1b1f24; --bg:#fbfbf9; --mut:#5c6570; --line:#d9dce1;
         --code:#f1f3f5; --hit:#ffd9a8; --acc:#0b5cad; --ok:#e6f4ea; }
 @media (prefers-color-scheme: dark) {
   :root { --fg:#e6e8eb; --bg:#15181c; --mut:#9aa4af; --line:#30363d; --code:#1e2329;
           --hit:#7a4b12; --acc:#6cb2ff; --ok:#16301f; } }
 body { font: 16px/1.55 system-ui, sans-serif; color: var(--fg); background: var(--bg);
        max-width: 46rem; margin: 2rem auto; padding: 0 1rem; }
 h1 { font-size: 1.6rem; margin-bottom: .2rem; } h2 { font-size: 1.15rem; margin-top: 2rem;
        border-bottom: 1px solid var(--line); padding-bottom: .2rem; }
 .lede { color: var(--mut); font-size: 1.05rem; }
 pre { background: var(--code); padding: .8rem; overflow-x: auto; border-radius: 6px;
       font: 13.5px/1.45 ui-monospace, monospace; }
 code { font-family: ui-monospace, monospace; font-size: .92em; }
 mark { background: var(--hit); color: inherit; border-radius: 3px; padding: 0 .1em; }
 .cap { color: var(--mut); font-size: .9rem; margin-bottom: -.5rem; }
 .ced td { vertical-align: top; padding: .3rem .6rem .3rem 0; border-top: 1px solid var(--line); }
 .ced td:first-child { white-space: nowrap; font-family: ui-monospace, monospace; }
 .note { color: var(--mut); font-size: .88rem; }
 .demo { border: 1px solid var(--line); border-radius: 8px; padding: .2rem 1rem 1rem; margin-top: 1.5rem; }
 .demo input { padding: .35rem; width: 15rem; max-width: 100%; font-family: ui-monospace, monospace; }
 .ok { background: var(--ok); padding: .5rem .7rem; border-radius: 6px; }
 a { color: var(--acc); } table { border-collapse: collapse; }
"""


def _html_inline(text: str) -> str:
    return html.escape(text, quote=False).replace("«", "<mark>").replace("»", "</mark>")


def _html_blocks(blocks: List[Block]) -> str:
    out = []
    for block in blocks:
        if isinstance(block, Code):
            if block.caption:
                out.append(f'<p class="cap">{_html_inline(block.caption)}</p>')
            out.append(f"<pre>{_html_inline(block.text.strip(chr(10)))}</pre>")
        elif isinstance(block, Bullets):
            out.append("<ul>" + "".join(f"<li>{_html_inline(i)}</li>" for i in block.items) + "</ul>")
        else:
            out.append(f"<p>{_html_inline(block)}</p>")
    return "\n".join(out)


def render_html_body(lesson: Lesson, demo_html: str = "") -> str:
    """The lesson as an HTML fragment. demo_html (already-safe HTML) is a live
    demonstration the web target adds after 'How it's defended today'."""
    parts = [f"<h1>Debrief: {html.escape(lesson.title)}</h1>",
             f'<p class="lede">{_html_inline(lesson.summary)}</p>']
    for n, (attr, heading) in enumerate(SECTIONS, 1):
        blocks = getattr(lesson, attr)
        if not blocks:
            continue
        parts.append(f"<h2>{n}. {heading}</h2>")
        parts.append(_html_blocks(blocks))
        if attr == "defend" and demo_html:
            parts.append(demo_html)
    if lesson.ced:
        parts.append("<h2>AP Cybersecurity connections</h2>")
        rows = "".join(
            f"<tr><td>{code}</td><td>{html.escape(CED[code])} "
            f'<span class="note">(Unit {code[0]}: {html.escape(UNITS[code[0]])})</span></td></tr>'
            for code in lesson.ced)
        parts.append(f'<table class="ced">{rows}</table>')
        parts.append(f'<p class="note">Codes are from the <a href="{CED_URL}">{html.escape(CED_SOURCE)}</a>; '
                     "the wording here is a summary, not a quotation.</p>")
    if lesson.links:
        parts.append("<h2>Go further (online, optional)</h2>")
        parts.append("<ul>" + "".join(
            f'<li><a href="{html.escape(url)}" rel="noreferrer">{html.escape(title)}</a></li>'
            for title, url in lesson.links) + "</ul>")
        parts.append('<p class="note">These open real websites, so they need internet. '
                     "Everything above works offline.</p>")
    return "\n".join(parts)


def render_html(lesson: Lesson, demo_html: str = "", nav_html: str = "") -> str:
    """A complete, self-contained HTML page (no external assets)."""
    return ("<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">"
            "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
            f"<title>{html.escape(lesson.title)} - cyberlab debrief</title>"
            f"<style>{STYLE}</style></head><body>{nav_html}"
            f"{render_html_body(lesson, demo_html)}</body></html>\n")


# Each module registers its lessons on import.
from cyberlab.lessons import web, network  # noqa: E402,F401
