"""web-upload: exploit a double-extension upload and compare safe validation."""

from __future__ import annotations

import shlex
import struct
import zlib
from typing import List, Tuple

from cyberlab import targets
from cyberlab.challenges import Challenge, register
from cyberlab.workspace import Workspace

_HTML_SAMPLE = (
    "<!doctype html><title>Northwind sample</title>"
    "<p>Synthetic profile image upload</p>\n"
).encode()

def _png_chunk(kind: bytes, data: bytes) -> bytes:
    return (struct.pack(">I", len(data)) + kind + data
            + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF))


_PNG_SAMPLE = (
    b"\x89PNG\r\n\x1a\n"
    + _png_chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 6, 0, 0, 0))
    + _png_chunk(b"IDAT", zlib.compress(b"\x00\xff\x00\x00\xff"))
    + _png_chunk(b"IEND", b"")
)


class WebUpload(Challenge):
    def setup(self, ws: Workspace) -> str:
        port = targets.start(ws, "webapp")
        html_path = ws.path("web-upload", "avatar.html")
        html_path.write_bytes(_HTML_SAMPLE)
        png_path = ws.path("web-upload", "pixel.png")
        png_path.write_bytes(_PNG_SAMPLE)
        return (f"Target: http://127.0.0.1:{port}/upload\n"
                f"Synthetic HTML sample: {html_path}\n"
                f"Valid one-pixel PNG sample: {png_path}\n"
                "Try the double-extension/MIME mismatch, then compare the safe endpoint.")

    def snippets(self, ws: Workspace) -> List[Tuple[str, str]]:
        url = f"http://127.0.0.1:{targets.port_of(ws, 'webapp')}"
        html_path = str(ws.home / "web-upload" / "avatar.html")
        png_path = str(ws.home / "web-upload" / "pixel.png")
        disguised = shlex.quote(
            f"file=@{html_path};type=image/jpeg;filename=avatar.jpg.html",
        )
        valid_png = shlex.quote(
            f"file=@{png_path};type=image/png;filename=avatar.png",
        )
        retrieve = (
            f"UPLOAD=$(curl -s -D - -o /dev/null -F {disguised} {url}/upload "
            "| grep -i '^Location:' | cut -d' ' -f2 | tr -d '\\r')\n"
            f"curl -i {url}$UPLOAD"
        )
        return [
            ("The vulnerable endpoint trusts the double extension and spoofed MIME type",
             f"curl -i -F {disguised} {url}/upload"),
            ("Upload it and retrieve the public file from the same origin",
             retrieve),
            ("The fixed endpoint rejects that same mismatched upload",
             f"curl -i -F {disguised} {url}/secure/upload"),
            ("A genuine image with matching type and file signature is accepted",
             f"curl -i -F {valid_png} {url}/secure/upload"),
        ]


register(WebUpload(
    id="web-upload",
    title="Unsafe upload: bypass an extension and MIME check",
    track="web",
    difficulty="medium",
    goal=("Upload the provided harmless HTML file as avatar.jpg.html while claiming it is "
          "image/jpeg. The vulnerable route serves it inline; the fixed route validates it."),
    hints=[
        "The sample file is HTML, even though a client can claim it is an image.",
        "A double extension ends in .html. The browser-supplied Content-Type is not proof "
        "of the file's actual contents.",
        "Try avatar.jpg.html with image/jpeg on /upload, then repeat against /secure/upload.",
    ],
    tools=["curl"],
    learned=("You uploaded harmless HTML using a double extension and a spoofed image MIME "
             "type. The vulnerable endpoint made it public and served it inline from the "
             "site's origin."),
    real_world=("User uploads can become a stored same-origin script or expose server files "
                "when an application trusts the submitted name or MIME type. An upload "
                "feature can turn a simple file into a way to attack other users who view it."),
    defend=[
        "Allowlist required file types; decode and re-encode images with a trusted parser. "
        "A magic-byte check alone is not full content validation.",
        "Store uploads outside the web root under server-generated names.",
        "Serve user content as an attachment from a separate origin, with nosniff headers.",
        "Apply size limits and restrict who can upload and retrieve files.",
    ],
    ap_unit="Unit 5",
    ap_topic="5.1 Application and Data Vulnerabilities and Attacks; 5.5 Protecting Applications",
    ap_skill=["Analyze Risk", "Mitigate Risk", "Detect Attacks"],
))
