"""Documentation catalog and online/offline detection system.

Provides:
- A catalog of available documentation for each tool/module
- Online/offline autodetection
- Document download from public domain sources (Project Gutenberg-style)
- Hint system that points to tutorial search
"""

from __future__ import annotations

import json
import os
import socket
import urllib.request
from pathlib import Path
from typing import Optional

DOCS_DIR = Path(__file__).resolve().parent.parent / "docs"
DOCS_DIR.mkdir(parents=True, exist_ok=True)

# Catalog of available documentation for each tool
# Each entry: id, title, tool, description, source_url, local_path, available_offline
DOCS_CATALOG: list[dict] = [
    {
        "id": "nmap-man",
        "title": "Nmap Manual",
        "tool": "nmap",
        "description": "Network exploration and security auditing tool manual",
        "source_url": "https://nmap.org/book/man.html",
        "local_path": "docs/nmap-man.txt",
        "available_offline": False,
    },
    {
        "id": "sqlmap-doc",
        "title": "SQLmap User Manual",
        "tool": "sqlmap",
        "description": "Automated SQL injection and database takeover tool documentation",
        "source_url": "https://github.com/sqlmapproject/sqlmap/wiki/Usage",
        "local_path": "docs/sqlmap-doc.txt",
        "available_offline": False,
    },
    {
        "id": "hydra-doc",
        "title": "Hydra Documentation",
        "tool": "hydra",
        "description": "Network logon cracker documentation",
        "source_url": "https://github.com/vanhauser-thc/thc-hydra",
        "local_path": "docs/hydra-doc.txt",
        "available_offline": False,
    },
    {
        "id": "cookie-doc",
        "title": "Cookie Security Documentation",
        "tool": "cookie",
        "description": "Cookie security attributes and analysis documentation",
        "source_url": "https://owasp.org/www-community/controls/Secure_Cookie_Attribute",
        "local_path": "docs/cookie-doc.txt",
        "available_offline": False,
    },
    {
        "id": "webscan-doc",
        "title": "Website Scanner Documentation",
        "tool": "webscan",
        "description": "Website vulnerability scanning methodology documentation",
        "source_url": "https://owasp.org/www-community/vulnerabilities/Improper_Input_Validation",
        "local_path": "docs/webscan-doc.txt",
        "available_offline": False,
    },
    {
        "id": "osint-doc",
        "title": "OSINT Framework Documentation",
        "tool": "osint",
        "description": "Open Source Intelligence techniques and methodology documentation",
        "source_url": "https://osintframework.com/",
        "local_path": "docs/osint-doc.txt",
        "available_offline": False,
    },
    {
        "id": "nikto-doc",
        "title": "Nikto Documentation",
        "tool": "nikto",
        "description": "Web server vulnerability scanner documentation",
        "source_url": "https://cirt.net/nikto2-docs/",
        "local_path": "docs/nikto-doc.txt",
        "available_offline": False,
    },
    {
        "id": "burp-doc",
        "title": "Burp Suite Documentation",
        "tool": "burp",
        "description": "Intercepting proxy documentation",
        "source_url": "https://portswigger.net/burp/documentation",
        "local_path": "docs/burp-doc.txt",
        "available_offline": False,
    },
    {
        "id": "wireshark-doc",
        "title": "Wireshark User Guide",
        "tool": "wireshark",
        "description": "Network protocol analyzer user guide",
        "source_url": "https://www.wireshark.org/docs/wsug_html_chunked/",
        "local_path": "docs/wireshark-doc.txt",
        "available_offline": False,
    },
    {
        "id": "auth-sec-guide",
        "title": "Authentication Security Guide",
        "tool": "auth",
        "description": "Authentication security best practices and attack techniques",
        "source_url": "https://owasp.org/www-community/controls/Authentication_Cheat_Sheet",
        "local_path": "docs/auth-sec-guide.txt",
        "available_offline": False,
    },
    {
        "id": "siem-guide",
        "title": "SIEM & Log Analysis Guide",
        "tool": "siem",
        "description": "Security Information and Event Management analysis guide",
        "source_url": "https://owasp.org/www-community/attacks/Brute_force_attack",
        "local_path": "docs/siem-guide.txt",
        "available_offline": False,
    },
]


def is_online(timeout: float = 2.0) -> bool:
    """Check if network is available by attempting to connect to a reliable host.

    Returns True if the network appears to be online, False otherwise.
    """
    try:
        socket.create_connection(("1.1.1.1", 53), timeout=timeout)
        return True
    except OSError:
        return False


def get_docs_for_tool(tool: str) -> list[dict]:
    """Return documentation entries available for a specific tool."""
    return [d for d in DOCS_CATALOG if d["tool"] == tool]


def get_all_docs() -> list[dict]:
    """Return all documentation entries."""
    return list(DOCS_CATALOG)


def download_doc(doc: dict) -> bool:
    """Download documentation from its source URL if online.

    Returns True if download succeeded, False otherwise.
    """
    if not is_online():
        return False
    try:
        req = urllib.request.Request(
            doc["source_url"],
            headers={"User-Agent": "cyberterminal/0.1 (educational)"},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            content = resp.read().decode("utf-8", errors="replace")
        local_path = DOCS_DIR / doc["local_path"]
        local_path.parent.mkdir(parents=True, exist_ok=True)
        local_path.write_text(content, encoding="utf-8")
        doc["available_offline"] = True
        return True
    except Exception:
        return False


def get_offline_docs() -> list[dict]:
    """Return docs that are available offline (already downloaded)."""
    return [d for d in DOCS_CATALOG if d["available_offline"]]


def get_hint_for_tool(tool: str) -> str:
    """Return a hint string pointing to the tutorial search for a tool."""
    hints = {
        "nmap": "Try: tutorials --track network-security  |  help web",
        "sqlmap": "Try: tutorials --track web-security  |  help web",
        "hydra": "Try: tutorials --track authentication-security  |  help web",
        "nikto": "Try: tutorials --track web-security  |  help web",
        "burp": "Try: tutorials --track web-security  |  help web",
        "wireshark": "Try: tutorials --track network-security  |  help web",
        "auth": "Try: tutorials --track authentication-security  |  help web",
        "siem": "Try: tutorials --track siem-logs  |  help web",
        "cookie": "Try: tutorials --track web-security  |  help web",
        "webscan": "Try: tutorials --track web-security  |  help web",
        "osint": "Try: tutorials --track osint  |  help web",
    }
    return hints.get(tool, "Try: help web")


def is_tool_available(tool: str) -> bool:
    """Check if a tool module is available."""
    available_tools = {
        "burp", "wireshark", "nmap", "sqlmap", "hydra", "nikto", "cookie", "webscan", "osint", "auth", "siem",
    }
    return tool in available_tools


__all__ = [
    "DOCS_DIR",
    "DOCS_CATALOG",
    "is_online",
    "get_docs_for_tool",
    "get_all_docs",
    "download_doc",
    "get_offline_docs",
    "get_hint_for_tool",
    "is_tool_available",
]
