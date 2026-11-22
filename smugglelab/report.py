"""Render a MatrixReport to a self-contained HTML page.

No external assets: styles, data and replay snippets are inlined so the file
opens anywhere.  The page is organised as

1. a summary with the headline numbers (detected / expected, false positives,
   false negatives) and a per-scenario verdict strip;
2. one card per scenario with the front/back dialects, the dialogs that matter,
   the detector verdicts and the reproducible samples;
3. a coverage appendix listing every ambiguity template and every wire shape.

Colors use semantic tokens so the page reads the same in light and dark mode
(the viewer's theme is respected; there is no manual toggle).
"""

from __future__ import annotations

import html
import json
from datetime import datetime, timezone

from . import templates as T
from .engine import WIRE_SHAPES
from .range import MatrixReport
from .samples import build_sample
from . import dialects as D

__all__ = ["render_html"]


def esc(s: object) -> str:
    return html.escape(str(s), quote=True)


def _badge(text: str, kind: str) -> str:
    return f'<span class="badge {kind}">{esc(text)}</span>'


def _dialect_card(d) -> str:
    flags = d.framing_flags()
    rows = "".join(
        f"<tr><td><code>{esc(k)}</code></td><td><code>{esc(v)}</code></td></tr>"
        for k, v in flags.items()
    )
    return (
        f'<div class="dialect"><div class="dialect-name">{esc(d.name)}</div>'
        f'<p>{esc(d.description)}</p>'
        f'<table class="kv">{rows}</table></div>'
    )


def _render_samples(shape_keys: list[str]) -> str:
    parts: list[str] = []
    for key in shape_keys:
        sample = build_sample(key)
        parts.append(
            f'<details class="sample"><summary>Reproduce: <code>{esc(key)}</code></summary>'
            f"<p>{esc(sample.description)}</p>"
            f'<h5>Wire transcript (\\r\\n shown literally)</h5>'
            f"<pre>{esc(sample.transcript())}</pre>"
            f"<h5>Python replay</h5>"
            f"<pre>{esc(sample.python_replay())}</pre>"
            f"</details>"
        )
    return "".join(parts)


def _render_blackbox(result) -> str:
    if not result.vulnerable:
        return (
            f'<div class="shape-row clean"><span class="shape-name">{esc(result.family)}</span>'
            f'<span class="shape-verdict">no cross-connection leak ({result.reproductions}/'
            f"{len(result.trials)} trials) — not confirmed</span></div>"
        )
    sample = build_sample(result.key)
    leak_examples = [t for t in result.trials if t.leaked_nonce][:1]
    ev = ""
    if leak_examples:
        t = leak_examples[0]
        resp = t.trigger_responses[0] if t.trigger_responses else None
        body = esc(resp.body_text()[:200]) if resp else "(no response body)"
        ev = (
            f'<div class="evidence"><div class="ev-label">trigger response on the fresh '
            f"connection (leaks the hidden marker):</div><pre>{body}</pre></div>"
        )
    return (
        f'<div class="shape-row vuln"><span class="shape-name">{esc(result.family)}</span>'
        f'<span class="shape-verdict">confirmed — leaked in {result.reproductions}/'
        f"{len(result.trials)} trials (confidence {result.confidence:.0%})</span></div>"
        f"<p class='why'>{esc(result.explanation)}</p>"
        f"{ev}"
        f"{_render_samples([result.key])}"
    )


def _render_instrumented(verdicts) -> str:
    rows = []
    for v in verdicts:
        cls = "vuln" if v.desync else "clean"
        if v.desync:
            extra = ", ".join(esc(t) for t in v.extra_at_back)
            detail = f"back end also framed: {extra}"
        else:
            detail = "both hops framed the same boundaries"
        rows.append(
            f'<tr class="{cls}"><td><code>{esc(v.key)}</code></td><td>{esc(v.family)}</td>'
            f"<td>{esc(v.title)}</td><td>{detail}</td></tr>"
        )
    return (
        '<div class="tablewrap"><table class="grid"><thead><tr><th>template</th><th>family</th>'
        "<th>ambiguity</th><th>framing differential</th></tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table></div>"
    )


def _scenario_card(run) -> str:
    sc = run.scenario
    if run.error:
        return (
            f'<section class="card"><h3>{esc(sc.title)}</h3>'
            f'<p class="err">scenario failed: {esc(run.error)}</p></section>'
        )
    bb = run.blackbox
    vuln_keys = [x.key for x in bb.vulnerable_results] if bb else []
    n_ins = len([v for v in run.instrumented if v.desync])
    verdict = (
        _badge("consistent (no desync)", "ok")
        if not vuln_keys and n_ins == 0
        else _badge(f"{len(vuln_keys)} wire shape(s), {n_ins} template(s) desync", "bad")
    )
    fp = run.fp_blackbox | run.fp_instrumented
    fn = run.fn_blackbox | run.fn_instrumented
    score = ""
    if fp or fn:
        score = (
            f'<p class="score-bad">against ground truth: '
            f'FP={esc(sorted(fp)) or "∅"} FN={esc(sorted(fn)) or "∅"}</p>'
        )
    else:
        score = '<p class="score-ok">matches ground truth exactly (no FP, no FN)</p>'

    front = D.get_dialect(sc.front)
    back = D.get_dialect(sc.back)

    shapes_html = "".join(_render_blackbox(x) for x in bb.results) if bb else ""
    return f"""
    <section class="card">
      <header class="card-head">
        <h3>{esc(sc.title)}</h3>
        {verdict}
      </header>
      <p class="story">{esc(sc.story)}</p>
      <div class="pipeline">
        <div class="hop">{_dialect_card(front)}<div class="hop-label">front end</div></div>
        <div class="arrow">→</div>
        <div class="hop">{_dialect_card(back)}<div class="hop-label">back end</div></div>
      </div>
      {score}
      <h4>Black-box response-queue oracle</h4>
      <p class="note">A shape is confirmed only when a hidden request executes on a
      <em>different</em> client connection than the attacker's, after the attacker's
      connection has closed. A negative control checks the range itself.</p>
      {shapes_html or '<p class="muted">no black-box shapes reported</p>'}
      <details class="instr">
        <summary>Instrumented framing differential (all {len(run.instrumented)} templates)</summary>
        <p class="note">Measured from the lab's own per-hop framing record. This can see
        every ambiguity family, including ones a remote target could not confirm without
        timing noise. It validates the range and the templates, not a remote target.</p>
        {_render_instrumented(run.instrumented)}
      </details>
    </section>
    """


def _coverage_tables() -> str:
    tmpl_rows = "".join(
        f"<tr><td><code>{esc(t.key)}</code></td><td>{esc(t.family)}</td>"
        f"<td>{esc(t.title)}</td><td>{esc(t.why)}</td></tr>"
        for t in T.TEMPLATES
    )
    shape_rows = "".join(
        f"<tr><td><code>{esc(s.key)}</code></td><td>{esc(s.family)}</td>"
        f"<td>{esc(s.title)}</td></tr>"
        for s in WIRE_SHAPES
    )
    flags_rows = ""
    for name in sorted(D.ALL_DIALECTS):
        f = D.ALL_DIALECTS[name].framing_flags()
        flags_rows += (
            f'<tr><td>{esc(name)}</td><td><code>{esc(json.dumps(f, sort_keys=True))}</code>'
            f"</td></tr>"
        )
    return f"""
    <section class="card appendix">
      <h3>Coverage appendix</h3>
      <h4>Ambiguity templates ({len(T.TEMPLATES)})</h4>
      <div class="tablewrap"><table class="grid"><thead><tr><th>key</th><th>family</th><th>ambiguity</th>
      <th>why it can split a request</th></tr></thead><tbody>{tmpl_rows}</tbody></table></div>
      <h4>Wire shapes the black-box oracle can confirm ({len(WIRE_SHAPES)})</h4>
      <div class="tablewrap"><table class="grid"><thead><tr><th>key</th><th>family</th><th>shape</th></tr></thead>
      <tbody>{shape_rows}</tbody></table></div>
      <h4>Dialect divergence flags</h4>
      <div class="tablewrap"><table class="grid"><thead><tr><th>dialect</th><th>framing-affecting flags</th></tr></thead>
      <tbody>{flags_rows}</tbody></table></div>
    </section>
    """


CSS = """
:root{
  --bg:#f7f8fa; --fg:#1a1d23; --muted:#5b6472; --card:#ffffff; --line:#dde1e7;
  --accent:#2f6fed; --bad:#c0392b; --bad-bg:#fdecea; --ok:#1e7d3f; --ok-bg:#e8f6ec;
  --code-bg:#eef1f5; --code-fg:#1a1d23;
}
@media (prefers-color-scheme: dark){
  :root{
    --bg:#0f1216; --fg:#e7ebf0; --muted:#9aa4b2; --card:#171c22; --line:#2a323c;
    --accent:#6ea0ff; --bad:#ff7a6e; --bad-bg:#2a1a18; --ok:#5fd08a; --ok-bg:#12281a;
    --code-bg:#0b0e12; --code-fg:#d8dee6;
  }
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);overflow-x:hidden;
  font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
.wrap{max-width:1080px;margin:0 auto;padding:28px 16px 80px}
h1{font-size:26px;margin:0 0 4px}
h2{font-size:20px;margin:34px 0 12px}
h3{font-size:17px;margin:0 0 6px}
h4{font-size:14px;margin:20px 0 8px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}
h5{font-size:13px;margin:14px 0 4px;color:var(--muted)}
.sub{color:var(--muted);margin:0 0 18px}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:18px 0}
.stat{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px}
.stat .n{font-size:26px;font-weight:650;line-height:1.1}
.stat .l{color:var(--muted);font-size:12.5px;margin-top:4px}
.stat.good .n{color:var(--ok)} .stat.bad .n{color:var(--bad)}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;
  padding:20px 22px;margin:18px 0}
.card-head{display:flex;justify-content:space-between;align-items:flex-start;gap:12px;flex-wrap:wrap}
.story{color:var(--muted);margin:6px 0 16px}
.badge{font-size:12px;padding:3px 9px;border-radius:999px;font-weight:600;white-space:nowrap}
.badge.ok{background:var(--ok-bg);color:var(--ok)}
.badge.bad{background:var(--bad-bg);color:var(--bad)}
.pipeline{display:flex;align-items:stretch;gap:10px;margin:14px 0;flex-wrap:wrap}
.pipeline .arrow{align-self:center;color:var(--muted);font-size:22px}
.hop{flex:1 1 260px;min-width:0;position:relative}
.hop-label{font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);
  margin:6px 0 0 2px}
.dialect{border:1px solid var(--line);border-radius:10px;padding:12px 14px;height:100%}
.dialect-name{font-weight:650}
.dialect p{color:var(--muted);font-size:13px;margin:4px 0 10px}
table.kv{width:100%;border-collapse:collapse;font-size:12px}
table.kv td{border-top:1px solid var(--line);padding:3px 4px;vertical-align:top}
table.kv td:first-child{white-space:nowrap;color:var(--muted)}
.tablewrap{overflow-x:auto;-webkit-overflow-scrolling:touch;margin:8px 0}
table.grid{border-collapse:collapse;font-size:13px;min-width:560px;width:100%}
table.grid td,table.grid th{overflow-wrap:anywhere}
table.grid th,table.grid td{border:1px solid var(--line);padding:6px 8px;text-align:left;
  vertical-align:top}
table.grid th{background:var(--code-bg);font-size:12px;color:var(--muted)}
table.grid tr.vuln td{background:var(--bad-bg)}
table.grid tr.clean td{color:var(--muted)}
code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
  background:var(--code-bg);color:var(--code-fg);padding:1px 5px;border-radius:4px;font-size:.9em}
pre{background:var(--code-bg);color:var(--code-fg);border:1px solid var(--line);border-radius:8px;
  padding:12px 14px;overflow:auto;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
  font-size:12.5px;line-height:1.45}
.shape-row{display:flex;justify-content:space-between;gap:10px;padding:7px 10px;border-radius:8px;
  margin:6px 0;flex-wrap:wrap}
.shape-row.vuln{background:var(--bad-bg)}
.shape-row.clean{background:var(--code-bg);color:var(--muted)}
.shape-name{font-weight:650}
.shape-verdict{font-size:13px}
.why{color:var(--muted);font-size:13px;margin:2px 0 8px}
.evidence{margin:8px 0}
.ev-label{font-size:12px;color:var(--muted);margin-bottom:3px}
.note{color:var(--muted);font-size:13px;margin:2px 0 10px}
.score-ok{color:var(--ok);font-size:13px;font-weight:600}
.score-bad{color:var(--bad);font-size:13px;font-weight:600}
.err{color:var(--bad)}
.muted{color:var(--muted)}
details.sample,details.instr{margin:10px 0;border:1px solid var(--line);border-radius:9px;
  padding:8px 12px}
details > summary{cursor:pointer;font-weight:600}
.pipeline-strip{display:flex;flex-wrap:wrap;gap:8px;margin:8px 0 4px}
.pill{font-size:12.5px;padding:4px 11px;border-radius:999px;text-decoration:none;
  font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
.pill.ok{background:var(--ok-bg);color:var(--ok)}
.pill.bad{background:var(--bad-bg);color:var(--bad)}
.appendix h4{margin-top:22px}
.footer{color:var(--muted);font-size:12.5px;margin-top:34px;border-top:1px solid var(--line);
  padding-top:14px}
"""


def render_html(report: MatrixReport) -> str:
    d = report.as_dict()
    s = d["summary"]["blackbox"]
    si = d["summary"]["instrumented"]
    when = datetime.fromtimestamp(report.finished, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    scenario_strip = "".join(
        f'<a href="#{esc(run.scenario.key)}" class="pill '
        f'{"bad" if (run.detected_blackbox or run.detected_instrumented) else "ok"}">'
        f"{esc(run.scenario.key)}</a>"
        for run in report.runs
    )
    cards = "".join(
        f'<div id="{esc(run.scenario.key)}">{_scenario_card(run)}</div>' for run in report.runs
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>HTTP Request Smuggling Lab report</title>
<style>{CSS}</style>
</head>
<body>
<div class="wrap">
  <h1>HTTP Request Smuggling Lab — detection report</h1>
  <p class="sub">Front end and back end parse the same bytes; the detector looks for
  a request boundary the two hops disagree on. Generated {esc(when)} ·
  {esc(len(report.runs))} scenarios · {esc(report.trials)} trials per shape.</p>

  <div class="stats">
    <div class="stat good"><div class="n">{s["detected"]}</div>
      <div class="l">black-box findings confirmed<br>({s["expected"]} expected)</div></div>
    <div class="stat {'good' if s["false_positives"] == 0 else 'bad'}">
      <div class="n">{s["false_positives"]}</div><div class="l">black-box false positives</div></div>
    <div class="stat {'good' if s["false_negatives"] == 0 else 'bad'}">
      <div class="n">{s["false_negatives"]}</div><div class="l">black-box false negatives</div></div>
    <div class="stat {'good' if si["false_positives"] == 0 else 'bad'}">
      <div class="n">{si["detected"]}</div>
      <div class="l">instrumented template desyncs<br>({si["expected"]} expected)</div></div>
    <div class="stat {'good' if si["false_positives"] + si['false_negatives'] == 0 else 'bad'}">
      <div class="n">{si["false_positives"] + si["false_negatives"]}</div>
      <div class="l">instrumented FP + FN</div></div>
  </div>

  <div class="pipeline-strip">{scenario_strip}</div>

  <h2>Scenarios</h2>
  {cards}

  {_coverage_tables()}

  <div class="footer">
    <p><strong>Method.</strong> A black-box finding requires a hidden request to execute
    on a different client connection than the attacker's, after the attacker's connection
    has closed, reproduced across trials, with a clean negative control. This is the
    response-queue-poisoning mechanism, so the same probe travels to a remote target.</p>
    <p><strong>Scope.</strong> The instrumented differential runs only against the local
    range, where both hops are in-process. It covers ambiguity families a remote target
    cannot confirm without timing noise (bare-LF, chunk-size whitespace, chunk extensions,
    header-name whitespace, ...). It is labelled separately and never reported as a remote
    finding.</p>
    <p>Local test range only. All listeners bind 127.0.0.1. Dialect presets are
    behavioural approximations, not copies of vendor code.</p>
  </div>
</div>
</body>
</html>
"""


def write_report(report: MatrixReport, path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write(render_html(report))
