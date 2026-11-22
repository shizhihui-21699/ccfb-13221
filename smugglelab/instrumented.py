"""Instrumented framing-differential detector.

The black-box engine (``engine.py``) can only *prove* desyncs that produce a
cross-connection leak, which in practice means the CL.TE / TE.CL / CL.CL /
TE.TE shapes.  The other ambiguity families in ``templates.py`` (bare-LF line
endings, chunk-size whitespace, chunk extensions, TE header-name whitespace,
...) usually cause a single-connection desync that does not survive to a second
connection, so a black box cannot confirm them without a lot of timing noise.

Because the lab runs both hops in-process, we can do better for the range:
drive each template through the live front end and ask whether the *back end
framed a request the front end did not*.  That is exact, non-statistical proof
of disagreement for every family.  This is clearly labelled "instrumented"
in the report; it validates the range and the templates, not a remote target.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from . import templates as T
from .lab import Lab
from .probe import new_nonce, run_probe

__all__ = ["TemplateVerdict", "diff_template", "diff_all"]


@dataclass
class TemplateVerdict:
    key: str
    family: str
    title: str
    why: str
    front_framed: list[str]
    back_framed: list[str]
    extra_at_back: list[str]
    desync: bool
    front_error: str | None = None
    back_error: str | None = None

    def as_dict(self) -> dict:
        return {
            "key": self.key,
            "family": self.family,
            "title": self.title,
            "why": self.why,
            "front_framed": self.front_framed,
            "back_framed": self.back_framed,
            "extra_at_back": self.extra_at_back,
            "desync": self.desync,
            "front_error": self.front_error,
            "back_error": self.back_error,
        }


def diff_template(lab: Lab, tmpl: T.Template, *, read_timeout: float = 0.4) -> TemplateVerdict:
    a = new_nonce("A")
    b = new_nonce("B")
    raw = tmpl.build(a, b)
    lab.reset()
    run_probe("127.0.0.1", lab.front_port, [raw], read_timeout=read_timeout)
    time.sleep(0.08)
    front = [r.target for r in lab.frames("front")]
    back = [r.target for r in lab.frames("back")]
    front_set = set(front)
    extra = [t for t in back if t not in front_set]
    return TemplateVerdict(
        key=tmpl.key,
        family=tmpl.family,
        title=tmpl.title,
        why=tmpl.why,
        front_framed=front,
        back_framed=back,
        extra_at_back=extra,
        desync=bool(extra),
    )


def diff_all(lab: Lab, *, keys: list[str] | None = None) -> list[TemplateVerdict]:
    templates = T.TEMPLATES
    if keys:
        templates = [T.TEMPLATES_BY_KEY[k] for k in keys if k in T.TEMPLATES_BY_KEY]
    return [diff_template(lab, t) for t in templates]
