"""Single-file HTML report writer (vanilla JS, no external resources)."""

from __future__ import annotations

import html
import json
from datetime import datetime

VERDICT_ORDER = ["VULNERABLE", "SUSPICIOUS", "REJECTED", "SAFE"]
BADGE = {
    "VULNERABLE": "#c0392b",
    "SUSPICIOUS": "#d68910",
    "REJECTED": "#5d6d7e",
    "SAFE": "#1e8449",
}


def _page_template() -> str:
    return r"""<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>HTTP Smuggling Scan Report</title>
<style>
  :root {
    --bg:#0f1419; --panel:#171d24; --panel2:#1e2630; --fg:#e6edf3;
    --muted:#8b98a5; --line:#2a3440; --accent:#4ea1ff;
    --vuln:#c0392b; --susp:#d68910; --rej:#5d6d7e; --safe:#1e8449;
  }
  @media (prefers-color-scheme: light) {
    :root { --bg:#f5f7fa; --panel:#ffffff; --panel2:#f0f3f7; --fg:#1c2733;
      --muted:#5c6b7a; --line:#dde3ea; --accent:#0b66c3; }
  }
  * { box-sizing:border-box; }
  body { margin:0; background:var(--bg); color:var(--fg);
    font:14px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,
    "Helvetica Neue",sans-serif; padding:24px; max-width:1180px; margin:auto; }
  h1 { font-size:22px; margin:0 0 4px; }
  h2 { font-size:16px; margin:24px 0 8px; }
  .muted { color:var(--muted); }
  .cards { display:flex; gap:12px; flex-wrap:wrap; margin:16px 0; }
  .card { background:var(--panel); border:1px solid var(--line);
    border-radius:10px; padding:14px 18px; min-width:130px; }
  .card .num { font-size:26px; font-weight:700; }
  .toolbar { display:flex; gap:10px; flex-wrap:wrap; align-items:center;
    margin:12px 0; }
  input[type=search], select { background:var(--panel2); color:var(--fg);
    border:1px solid var(--line); border-radius:8px; padding:8px 10px;
    font:inherit; }
  table { width:100%; border-collapse:collapse; background:var(--panel);
    border:1px solid var(--line); border-radius:10px; overflow:hidden; }
  th, td { text-align:left; padding:9px 12px; border-bottom:1px solid var(--line);
    vertical-align:top; }
  th { background:var(--panel2); font-size:12px; text-transform:uppercase;
    letter-spacing:.04em; color:var(--muted); cursor:pointer; user-select:none; }
  tr:last-child td { border-bottom:none; }
  tr.clickable { cursor:pointer; }
  tr.clickable:hover { background:var(--panel2); }
  .badge { display:inline-block; padding:2px 9px; border-radius:999px;
    color:#fff; font-size:12px; font-weight:600; white-space:nowrap; }
  .mono { font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; }
  .detail { background:var(--panel); border:1px solid var(--line);
    border-radius:10px; padding:18px; margin:10px 0; }
  .detail h3 { margin:0 0 6px; font-size:15px; }
  pre { background:#0b0f14; color:#d5dde5; padding:14px; border-radius:8px;
    overflow-x:auto; font-size:12.5px; margin:8px 0; white-space:pre; }
  .kv { display:grid; grid-template-columns:180px 1fr; gap:4px 12px;
    margin:8px 0; }
  .kv .k { color:var(--muted); }
  .tag { display:inline-block; background:var(--panel2); border:1px solid var(--line);
    border-radius:6px; padding:1px 7px; font-size:11px; margin:1px 3px 1px 0; }
  .hidden { display:none; }
  button { background:var(--accent); color:#fff; border:none; border-radius:8px;
    padding:7px 12px; font:inherit; cursor:pointer; }
  button.ghost { background:var(--panel2); color:var(--fg);
    border:1px solid var(--line); }
  .warn { background:rgba(214,137,16,.12); border:1px solid var(--susp);
    border-radius:8px; padding:10px 14px; margin:12px 0; }
  code { background:var(--panel2); padding:1px 5px; border-radius:4px; }
</style>
</head>
<body>
<h1>HTTP Request Smuggling — Scan Report</h1>
<div class="muted" id="meta"></div>
<div class="warn">
  This report describes active probes against an explicitly authorized target.
  Every evidence block contains the exact bytes sent; replay only against
  systems you are permitted to test.
</div>
<div class="cards" id="cards"></div>
<div class="toolbar">
  <label class="muted">Verdict
    <select id="fVerdict">
      <option value="">all</option><option>VULNERABLE</option>
      <option>SUSPICIOUS</option><option>REJECTED</option>
      <option>SAFE</option>
    </select>
  </label>
  <label class="muted">Family
    <select id="fFamily"><option value="">all</option></select>
  </label>
  <input type="search" id="fText" placeholder="filter id / name / tag…" size=28>
  <button class="ghost" id="exportBtn">Export JSON</button>
</div>
<table id="tbl">
  <thead><tr>
    <th data-k="vid">ID</th><th data-k="family">Family</th>
    <th data-k="name">Variant</th><th data-k="verdict">Verdict</th>
    <th data-k="timing_hits">Timing hits</th><th data-k="canary_misroute">Misroute</th>
    <th data-k="canary_state_hit">State hit</th>
  </tr></thead>
  <tbody></tbody>
</table>
<div id="detail"></div>
<script id="scan-data" type="application/json">__DATA__</script>
<script>
const SCAN = JSON.parse(document.getElementById('scan-data').textContent);
const BADGE = __BADGE__;
const esc = s => (s??'').toString().replace(/[&<>"]/g,
  c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
let rows = SCAN.results.slice();
let sortK = 'verdict', sortDir = 1;

document.getElementById('meta').textContent =
  SCAN.target + '  ·  ' + SCAN.started + '  ·  ' + rows.length + ' variants';

function card(v, n) {
  return `<div class="card"><div class="muted">${v}</div>
    <div class="num" style="color:${BADGE[v]||'inherit'}">${n}</div></div>`;
}
document.getElementById('cards').innerHTML =
  ['VULNERABLE','SUSPICIOUS','REJECTED','SAFE']
    .map(v => card(v, SCAN.counts[v] || 0)).join('');

const fams = [...new Set(rows.map(r => r.family))].sort();
document.getElementById('fFamily').innerHTML =
  '<option value="">all</option>' + fams.map(f=>`<option>${esc(f)}</option>`).join('');

const rank = {VULNERABLE:0,SUSPICIOUS:1,REJECTED:2,SAFE:3};
function applyFilters() {
  const v = fVerdict.value, f = fFamily.value, q = fText.value.toLowerCase();
  let view = rows.filter(r =>
    (!v || r.verdict===v) && (!f || r.family===f) &&
    (!q || (r.vid+' '+r.name+' '+r.tags.join(' ')).toLowerCase().includes(q)));
  view.sort((a,b) => {
    let x=a[sortK], y=b[sortK];
    if (sortK==='verdict'){x=rank[x];y=rank[y];}
    return (x>y?1:x<y?-1:0)*sortDir;
  });
  tbl.querySelector('tbody').innerHTML = view.map(r => `
    <tr class="clickable" data-id="${esc(r.vid)}">
      <td class="mono">${esc(r.vid)}</td>
      <td>${esc(r.family)}</td>
      <td>${esc(r.name)}</td>
      <td><span class="badge" style="background:${BADGE[r.verdict]}">${r.verdict}</span></td>
      <td>${r.timing_hits} <span class="muted">(${
        (r.timing_observed||[]).map(t=>t.toFixed(2)+'s').join(', ')})</span></td>
      <td>${r.canary_misroute?'✔':'—'}</td>
      <td>${r.canary_state_hit?'✔':'—'}</td>
    </tr>`).join('');
  tbl.querySelectorAll('tr.clickable').forEach(tr =>
    tr.addEventListener('click', () => showDetail(tr.dataset.id)));
}
document.querySelectorAll('th').forEach(th => th.addEventListener('click', () => {
  const k = th.dataset.k;
  if (sortK===k) sortDir*=-1; else { sortK=k; sortDir=1; }
  applyFilters();
}));
[fVerdict,fFamily,fText].forEach(el =>
  el.addEventListener('input', applyFilters));

function showDetail(vid) {
  const r = rows.find(x => x.vid===vid);
  if (!r) return;
  const ev = (r.evidence||[]).map(e => `
    <div class="muted">${esc(e.note||'evidence')}</div>
    ${e.request_bytes?`<div class="muted">request bytes:</div><pre>${esc(e.request_bytes)}</pre>`:''}
    ${e.response_bytes?`<div class="muted">response bytes:</div><pre>${esc(e.response_bytes)}</pre>`:''}
  `).join('') || '<p class="muted">no raw evidence captured</p>';
  detail.innerHTML = `
    <div class="detail">
      <h3><span class="badge" style="background:${BADGE[r.verdict]}">${r.verdict}</span>
        ${esc(r.vid)} — ${esc(r.name)}</h3>
      <p>${esc(r.ambiguity)}</p>
      <div>${r.tags.map(t=>`<span class="tag mono">${esc(t)}</span>`).join('')}</div>
      <div class="kv">
        <div class="k">timing threshold</div><div class="mono">${r.timing_threshold}s</div>
        <div class="k">timing observed</div><div class="mono">${
          (r.timing_observed||[]).map(t=>t+'s').join(', ')}</div>
        <div class="k">timing hits</div><div>${r.timing_hits}</div>
        <div class="k">canary misroute</div><div>${r.canary_misroute}</div>
        <div class="k">backend state hit</div><div>${r.canary_state_hit}</div>
        <div class="k">control clean</div><div>${r.control_clean}</div>
        <div class="k">control status</div><div>${r.control_status ?? '—'}</div>
        <div class="k">error</div><div>${esc(r.error ?? '—')}</div>
      </div>
      <h2>Evidence (reproducible bytes)</h2>${ev}
      <h2>Replay</h2><pre>${esc(r.replay||'')}</pre>
      <button class="ghost" onclick="document.getElementById('detail').innerHTML=''">
        Close</button>
    </div>`;
  detail.scrollIntoView({behavior:'smooth', block:'nearest'});
}
document.getElementById('exportBtn').addEventListener('click', () => {
  const blob = new Blob([JSON.stringify(SCAN,null,2)],
    {type:'application/json'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'smuggler-scan.json'; a.click();
});
applyFilters();
</script>
</body>
</html>
"""


def render(scan: dict, out_path: str) -> str:
    page = (_page_template()
            .replace("__DATA__", json.dumps(scan).replace("</", "<\\/"))
            .replace("__BADGE__", json.dumps(BADGE)))
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(page)
    return out_path
