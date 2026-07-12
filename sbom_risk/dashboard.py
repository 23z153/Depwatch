"""Local, dependency-free live dashboard for SBOM risk analyses."""
from __future__ import annotations

import json
import threading
import webbrowser
from collections import defaultdict
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from .analyzer import analyze
from .models import AnalysisResult


def remediation_playbook(result: AnalysisResult) -> list[dict[str, Any]]:
    """Turn findings into a concise, actionable component remediation queue."""
    findings: dict[str, list] = defaultdict(list)
    for finding in result.vulnerabilities + result.license_conflicts + result.unmaintained + result.version_conflicts:
        findings[finding.component].append(finding)
    playbook = []
    for component, component_findings in findings.items():
        steps = []
        for finding in sorted(component_findings, key=lambda f: (-f.score, f.finding_id)):
            if finding.fixed_version:
                steps.append(f"Upgrade to {finding.fixed_version} and regenerate the lockfile ({finding.finding_id}).")
            elif finding.finding_id.startswith("LICENSE"):
                steps.append(f"Review the license obligation and obtain approval or replace the component ({finding.finding_id}).")
            elif finding.finding_id.startswith("MAINTENANCE"):
                steps.append(f"Assess maintainer status and migrate or document an approved exception ({finding.finding_id}).")
            elif finding.finding_id in {"VERSION-CONFLICT", "DIAMOND-DEPENDENCY"}:
                steps.append(f"Align transitive versions and verify the resolved dependency tree ({finding.finding_id}).")
            else:
                steps.append(f"Investigate {finding.finding_id}; document a VEX exception only when justified.")
        playbook.append({
            "component": component,
            "risk_score": result.component_scores.get(component, 0),
            "findings": [f.finding_id for f in component_findings],
            "steps": list(dict.fromkeys(steps)),
        })
    return sorted(playbook, key=lambda item: (-item["risk_score"], item["component"]))


def correlate(results: list[AnalysisResult]) -> list[dict[str, Any]]:
    """Link the same affected component across systems for one remediation owner."""
    by_component: dict[str, list[tuple[AnalysisResult, Any]]] = defaultdict(list)
    for result in results:
        findings = result.vulnerabilities + result.license_conflicts + result.unmaintained + result.version_conflicts
        for finding in findings:
            by_component[finding.component].append((result, finding))
    correlations = []
    for component, occurrences in by_component.items():
        systems = sorted({result.project for result, _ in occurrences})
        if len(systems) < 2:
            continue
        correlations.append({
            "component": component,
            "systems": systems,
            "finding_ids": sorted({finding.finding_id for _, finding in occurrences}),
            "max_score": max(finding.score for _, finding in occurrences),
            "recommendation": "Coordinate one upgrade or approved exception across all affected systems.",
        })
    return sorted(correlations, key=lambda item: (-item["max_score"], item["component"]))


def cluster_risk_patterns(results: list[AnalysisResult]) -> list[dict[str, Any]]:
    """Group systems with the same finding-category signature.

    This is deterministic pattern clustering, not a claim of ML-based behavior
    inference: it makes repeated operational risk shapes visible.
    """
    groups: dict[tuple[str, ...], list[str]] = defaultdict(list)
    for result in results:
        categories = set()
        for finding in result.vulnerabilities + result.license_conflicts + result.unmaintained + result.version_conflicts:
            categories.add(finding.finding_id.split("-", 1)[0].lower())
        groups[tuple(sorted(categories))].append(result.project)
    return [
        {"pattern": list(pattern) or ["no findings"], "systems": sorted(systems), "count": len(systems)}
        for pattern, systems in sorted(groups.items(), key=lambda item: (-len(item[1]), item[0]))
    ]


class DashboardState:
    def __init__(self, projects: list[str], analysis_options: dict[str, Any], refresh_seconds: int):
        self.projects = projects
        self.analysis_options = analysis_options
        self.refresh_seconds = max(2, refresh_seconds)
        self._lock = threading.Lock()
        self._payload: dict[str, Any] = {"generated_at": None, "projects": [], "correlations": [], "clusters": [], "errors": []}

    def refresh(self) -> None:
        results, errors = [], []
        for project in self.projects:
            try:
                results.append(analyze(project, **self.analysis_options))
            except Exception as exc:
                errors.append({"project": project, "error": str(exc)})
        payload = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "projects": [result.to_dict() | {"playbook": remediation_playbook(result)} for result in results],
            "correlations": correlate(results),
            "clusters": cluster_risk_patterns(results),
            "errors": errors,
        }
        with self._lock:
            self._payload = payload

    def payload(self) -> dict[str, Any]:
        with self._lock:
            return self._payload

    def start(self) -> None:
        def loop():
            self.refresh()
            while True:
                threading.Event().wait(self.refresh_seconds)
                self.refresh()
        threading.Thread(target=loop, name="sbom-risk-dashboard-refresh", daemon=True).start()


def open_dashboard(url: str) -> bool:
    """Request the platform's default browser without failing the dashboard."""
    try:
        return webbrowser.open(url)
    except webbrowser.Error:
        return False


def serve(projects: list[str], analysis_options: dict[str, Any], port: int = 8765,
          refresh_seconds: int = 10, open_browser: bool = True) -> None:
    state = DashboardState(projects, analysis_options, refresh_seconds)
    state.start()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            if self.path in {"/", "/index.html"}:
                self._send("text/html; charset=utf-8", _HTML.encode())
            elif self.path == "/api/dashboard":
                self._send("application/json", json.dumps(state.payload()).encode())
            else:
                self.send_error(404)

        def log_message(self, format, *args):  # noqa: A003
            return

        def _send(self, content_type: str, body: bytes):
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server, selected_port = _bind_dashboard_server(Handler, port)
    url = f"http://127.0.0.1:{selected_port}"
    if selected_port != port:
        print(f"Dashboard port {port} is already in use; using {selected_port} instead.")
    print(f"SBOM Risk Dashboard: {url} (refreshes every {state.refresh_seconds}s)")
    if open_browser and not open_dashboard(url):
        print("Could not open a browser automatically; open the URL above manually.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nDashboard stopped.")
    finally:
        server.server_close()


def _bind_dashboard_server(handler, requested_port: int) -> tuple[ThreadingHTTPServer, int]:
    """Bind locally, choosing a nearby free port when the default is occupied."""
    try:
        return ThreadingHTTPServer(("127.0.0.1", requested_port), handler), requested_port
    except OSError as exc:
        if exc.errno != 98:  # EADDRINUSE
            raise
    for candidate in range(requested_port + 1, requested_port + 21):
        try:
            return ThreadingHTTPServer(("127.0.0.1", candidate), handler), candidate
        except OSError as exc:
            if exc.errno != 98:
                raise
    raise OSError(98, f"Dashboard ports {requested_port}-{requested_port + 20} are all in use; choose one with --port.")


_HTML = r'''<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>SBOM Risk Dashboard</title><style>
:root{--ink:#172033;--muted:#667085;--line:#e4e7ec;--canvas:#f7f8fc;--panel:#fff;--nav:#101828;--blue:#2563eb;--red:#d92d20;--amber:#dc6803;--green:#039855}*{box-sizing:border-box}body{margin:0;background:var(--canvas);color:var(--ink);font:14px/1.45 Inter,ui-sans-serif,system-ui,-apple-system,sans-serif}.top{background:linear-gradient(110deg,#101828,#1d2939);padding:26px max(5vw,24px);color:#fff}.topbar,.shell{max-width:1360px;margin:auto}.eyebrow{font-size:11px;letter-spacing:.12em;text-transform:uppercase;color:#98a2b3;font-weight:700}.top h1{font-size:28px;margin:3px 0}.top p{margin:0;color:#d0d5dd}.status{display:inline-flex;gap:7px;align-items:center;margin-top:13px;font-size:12px;color:#d0d5dd}.dot{width:7px;height:7px;background:#32d583;border-radius:50%;box-shadow:0 0 0 4px #32d58322}.shell{padding:24px}.metrics{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-top:-18px;position:relative}.metric,.panel,.system{background:var(--panel);border:1px solid var(--line);border-radius:12px;box-shadow:0 1px 2px #1018280a}.metric{padding:16px 18px}.metric span{display:block;color:var(--muted);font-size:12px;font-weight:600}.metric strong{display:block;font-size:26px;margin-top:4px}.metric.danger strong{color:var(--red)}.nav{display:flex;gap:8px;margin:24px 0 14px;overflow-x:auto}.nav button,.system button{font:inherit;border:0;cursor:pointer}.nav button{padding:9px 14px;border-radius:8px;background:transparent;color:var(--muted);font-weight:650}.nav button.active{background:#eaf0ff;color:#1849a9}.view{display:none}.view.active{display:block}.panel{padding:20px;margin-bottom:16px}.panelhead{display:flex;justify-content:space-between;gap:12px;align-items:start;margin-bottom:16px}.panel h2{font-size:17px;margin:0}.panelhead p{margin:3px 0 0;color:var(--muted)}.systems{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:12px}.system{padding:16px;text-align:left;transition:.15s}.system:hover,.system.active{border-color:#84adff;box-shadow:0 0 0 3px #eaf0ff}.system-name{font-weight:700;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.score-row{display:flex;align-items:baseline;gap:5px;margin:12px 0}.score{font-size:32px;font-weight:750}.score.high{color:var(--red)}.score.medium{color:var(--amber)}.score.low{color:var(--green)}.score-denom{color:var(--muted)}.system-meta{font-size:12px;color:var(--muted)}.graph-wrap{position:relative;overflow:auto;border:1px solid var(--line);border-radius:10px;background:radial-gradient(#e4e7ec 1px,transparent 1px) 0 0/18px 18px;min-height:430px}svg{display:block;min-width:780px;width:100%;height:430px}.node{cursor:pointer}.node circle{stroke:#fff;stroke-width:3px;filter:drop-shadow(0 2px 2px #10182833)}.node:hover circle{stroke:#101828;stroke-width:3px}.node text{font-size:11px;fill:#344054;pointer-events:none}.edge{stroke:#98a2b3;stroke-width:1.2}.root{fill:#344054}.direct{fill:#2563eb}.transitive{fill:#98a2b3}.legend{display:flex;gap:16px;color:var(--muted);font-size:12px;margin-top:12px}.legend i{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:5px}.detail{margin-top:14px;padding:14px 16px;border-radius:8px;background:#f9fafb;color:#475467}.two-col{display:grid;grid-template-columns:1fr 1fr;gap:16px}.finding,.play{border:1px solid var(--line);border-radius:9px;padding:14px;margin-top:10px}.finding-top,.play-top{display:flex;justify-content:space-between;gap:12px}.component{font-weight:700;overflow-wrap:anywhere}.pill{display:inline-block;padding:3px 8px;border-radius:99px;background:#f2f4f7;color:#475467;font-size:11px;font-weight:700}.pill.risk{background:#fef3f2;color:#b42318}.step{display:flex;gap:10px;margin-top:10px;color:#475467}.step b{display:grid;place-items:center;min-width:20px;height:20px;background:#eaf0ff;color:#1849a9;border-radius:50%;font-size:11px}.empty{padding:18px;border:1px dashed #d0d5dd;border-radius:8px;color:var(--muted)}.error{margin-top:12px;padding:10px 12px;background:#fef3f2;color:#b42318;border-radius:8px;font-size:12px}@media(max-width:800px){.shell{padding:16px}.top{padding:22px 16px}.metrics{grid-template-columns:1fr 1fr}.two-col{grid-template-columns:1fr}.metric strong{font-size:22px}}
</style></head><body><header class="top"><div class="topbar"><div class="eyebrow">Local security workspace</div><h1>SBOM Risk Dashboard</h1><p>Dependency intelligence, prioritized for action.</p><div class="status"><i class="dot"></i><span id="updated">Loading latest scan…</span></div></div></header><main class="shell"><div class="metrics" id="metrics"></div><nav class="nav"><button class="active" data-view="overview">Overview</button><button data-view="graphview">Dependency graph</button><button data-view="actions">Remediation queue</button></nav><section class="view active" id="overview"><div class="panel"><div class="panelhead"><div><h2>Systems at a glance</h2><p>Choose a system to explore its dependency posture.</p></div></div><div class="systems" id="systems"></div></div><div class="two-col"><div class="panel"><div class="panelhead"><div><h2>Shared risks</h2><p>One fix can improve several systems.</p></div></div><div id="correlations"></div></div><div class="panel"><div class="panelhead"><div><h2>Risk patterns</h2><p>Repeated finding categories across systems.</p></div></div><div id="clusters"></div></div></div></section><section class="view" id="graphview"><div class="panel"><div class="panelhead"><div><h2 id="graph-title">Dependency graph</h2><p>Click a component to reveal its remediation guidance.</p></div><span class="pill" id="graph-count"></span></div><div class="graph-wrap"><svg id="graph" aria-label="Dependency graph"></svg></div><div class="legend"><span><i style="background:#344054"></i>Root</span><span><i style="background:#2563eb"></i>Direct</span><span><i style="background:#98a2b3"></i>Transitive</span></div><div class="detail" id="selected">Select a node to inspect it.</div></div></section><section class="view" id="actions"><div class="panel"><div class="panelhead"><div><h2>Automated remediation playbook</h2><p>Work through the highest-risk components first.</p></div><span class="pill" id="playbook-count"></span></div><div id="playbook"></div></div></section><div id="errors"></div></main><script>
let data,active=0;const $=s=>document.querySelector(s),esc=s=>String(s).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));
function riskClass(n){return n>=50?'high':n>=25?'medium':'low'}function show(view){document.querySelectorAll('.view').forEach(x=>x.classList.toggle('active',x.id===view));document.querySelectorAll('.nav button').forEach(x=>x.classList.toggle('active',x.dataset.view===view));}document.querySelectorAll('.nav button').forEach(b=>b.onclick=()=>show(b.dataset.view));
async function load(){try{data=await (await fetch('/api/dashboard')).json();$('#updated').textContent='Last refreshed '+new Date(data.generated_at).toLocaleTimeString();render()}catch(e){$('#updated').textContent='Unable to refresh dashboard'}}
function render(){const ps=data.projects||[],vulns=ps.reduce((n,p)=>n+p.summary.vulnerabilities,0),components=ps.reduce((n,p)=>n+p.summary.components,0),score=ps.length?Math.max(...ps.map(p=>p.summary.risk_score)):0;$('#metrics').innerHTML=`<div class="metric"><span>Systems scanned</span><strong>${ps.length}</strong></div><div class="metric danger"><span>Known vulnerabilities</span><strong>${vulns}</strong></div><div class="metric"><span>Components inventoried</span><strong>${components}</strong></div><div class="metric"><span>Highest system risk</span><strong>${score}/100</strong></div>`;if(active>=ps.length)active=0;$('#systems').innerHTML=ps.map((p,i)=>`<button class="system ${i===active?'active':''}" onclick="selectSystem(${i})"><div class="system-name" title="${esc(p.project)}">${esc(p.project.split('/').filter(Boolean).pop()||p.project)}</div><div class="score-row"><span class="score ${riskClass(p.summary.risk_score)}">${p.summary.risk_score}</span><span class="score-denom">/100</span></div><div class="system-meta">${p.summary.components} components · ${p.summary.vulnerabilities} vulnerabilities</div></button>`).join('')||'<div class="empty">No successful analyses yet.</div>';const p=ps[active];if(!p)return;graph(p);playbook(p);$('#correlations').innerHTML=(data.correlations||[]).map(x=>`<div class="finding"><div class="finding-top"><span class="component">${esc(x.component)}</span><span class="pill risk">${x.systems.length} systems</span></div><div class="system-meta">${esc(x.finding_ids.join(' · '))}</div><div class="step"><b>→</b><span>${esc(x.recommendation)}</span></div></div>`).join('')||'<div class="empty">No affected components are shared across systems.</div>';$('#clusters').innerHTML=(data.clusters||[]).map(x=>`<div class="finding"><div class="finding-top"><span class="component">${esc(x.pattern.join(' + '))}</span><span class="pill">${x.count} system${x.count===1?'':'s'}</span></div><div class="system-meta">${x.systems.map(esc).join(', ')}</div></div>`).join('')||'<div class="empty">No risk patterns available.</div>';$('#errors').innerHTML=(data.errors||[]).map(e=>`<div class="error"><b>${esc(e.project)}</b>: ${esc(e.error)}</div>`).join('');}
function selectSystem(i){active=i;render();show('graphview')}function playbook(p){const list=p.playbook||[];$('#playbook-count').textContent=`${list.length} action item${list.length===1?'':'s'}`;$('#playbook').innerHTML=list.map(x=>`<article class="play"><div class="play-top"><span class="component">${esc(x.component)}</span><span class="pill risk">Risk ${x.risk_score}</span></div><div class="system-meta">${esc(x.findings.join(' · '))}</div>${x.steps.map((s,i)=>`<div class="step"><b>${i+1}</b><span>${esc(s)}</span></div>`).join('')}</article>`).join('')||'<div class="empty">No remediation actions for this system.</div>'}
function graph(p){const svg=$('#graph'),all=[{id:'ROOT',name:'Root',version:'',direct:false},...p.components],by=Object.fromEntries(all.map(n=>[n.id,n])),parents={};p.dependencies.forEach(e=>(parents[e.to]??=[]).push(e.from));const risky=new Set((p.vulnerabilities||[]).filter(f=>f.exploitability!=='suppressed').map(f=>f.component));const focused=all.length>70&&risky.size>0,keep=new Set(['ROOT']);if(focused){for(const id of risky){let stack=[id],seen=new Set;while(stack.length){const n=stack.pop();if(seen.has(n))continue;seen.add(n);keep.add(n);(parents[n]||[]).forEach(x=>stack.push(x));}}for(const n of all)if(n.direct)keep.add(n.id)}else all.forEach(n=>keep.add(n.id));const nodes=all.filter(n=>keep.has(n.id)),edges=p.dependencies.filter(e=>keep.has(e.from)&&keep.has(e.to));const children={};edges.forEach(e=>(children[e.from]??=[]).push(e.to));const depth={ROOT:0},queue=['ROOT'];while(queue.length){const from=queue.shift();for(const to of children[from]||[]){const next=depth[from]+1;if(depth[to]===undefined||next<depth[to]){depth[to]=next;queue.push(to)}}}for(const n of nodes)if(depth[n.id]===undefined)depth[n.id]=0;const levels={};nodes.forEach(n=>(levels[depth[n.id]]??=[]).push(n));const maxDepth=Math.max(...Object.values(depth)),maxRows=Math.max(...Object.values(levels).map(x=>x.length)),w=Math.max(900,180+(maxDepth+1)*220),h=Math.max(430,110+maxRows*72),clip=(s,n)=>s.length>n?s.slice(0,n-1)+'…':s,display=n=>{if(n.id==='ROOT')return 'ROOT';let name=n.name||n.id;if(n.ecosystem==='maven'&&name.includes(':'))name=name.split(':').pop();return clip(name,20)};Object.entries(levels).forEach(([d,list])=>list.forEach((n,i)=>{n.x=70+Number(d)*220;n.y=55+(i+1)*h/(list.length+1)}));svg.style.minWidth=w+'px';svg.style.height=h+'px';svg.setAttribute('viewBox',`0 0 ${w} ${h}`);svg.innerHTML='';edges.forEach(e=>{const a=by[e.from],b=by[e.to];if(a&&b)svg.innerHTML+=`<line class="edge" x1="${a.x}" y1="${a.y}" x2="${b.x}" y2="${b.y}"/>`});nodes.forEach(n=>{const kind=n.id==='ROOT'?'root':n.direct?'direct':'transitive',name=display(n),version=n.id==='ROOT'?'':clip(n.version||'',14),isRisk=risky.has(n.id);svg.innerHTML+=`<g class="node" onclick="showNode('${encodeURIComponent(n.id)}')"><circle class="${kind}" cx="${n.x}" cy="${n.y}" r="${isRisk?16:13}"/><text text-anchor="middle" style="font-weight:${isRisk?750:650}" x="${n.x}" y="${n.y+31}"><tspan x="${n.x}">${esc(name)}</tspan>${version?`<tspan x="${n.x}" dy="13" style="font-size:10px;fill:#667085;font-weight:500">${esc(version)}</tspan>`:''}</text></g>`});const project=p.project.split('/').filter(Boolean).pop()||p.project;$('#graph-title').textContent=`${focused?'Risk-focused dependency graph':'Dependency graph'} · ${project}`;$('#graph-count').textContent=focused?`${nodes.length} of ${all.length-1} components shown`:`${p.summary.components} components`}
function showNode(id){id=decodeURIComponent(id);const p=data.projects[active],item=(p.playbook||[]).find(x=>x.component===id);$('#selected').innerHTML=item?`<b>${esc(item.component)}</b>${item.steps.map((s,i)=>`<div class="step"><b>${i+1}</b><span>${esc(s)}</span></div>`).join('')}`:`<b>${esc(id)}</b><br><span class="system-meta">No active remediation action for this component.</span>`}load();setInterval(load,5000);
</script></body></html>'''

# Kept separate from the core dashboard template so usability enhancements
# remain small and do not alter the local HTTP/API surface.
_HTML = _HTML.replace("</body>", r'''<style>
.dashboard-tools{display:flex;gap:8px;align-items:center;position:relative;flex-wrap:wrap}.dashboard-search{width:245px;border:1px solid #d0d5dd;border-radius:8px;padding:9px 11px;background:#fff;color:#172033;font:inherit;outline:none}.dashboard-search:focus{border-color:#2563eb;box-shadow:0 0 0 3px #eaf0ff}.search-menu{position:absolute;right:0;top:42px;z-index:10;width:320px;max-height:300px;overflow:auto;background:#fff;border:1px solid #d0d5dd;border-radius:9px;box-shadow:0 12px 24px #10182824}.search-menu button{display:block;width:100%;padding:9px 11px;text-align:left;border:0;border-bottom:1px solid #f2f4f7;background:#fff;color:#172033;cursor:pointer;font:inherit}.search-menu button:hover{background:#f4f7ff}.search-menu small{display:block;color:#667085;margin-top:2px}.focus-note{margin:0 0 12px;padding:9px 12px;border-left:3px solid #2563eb;border-radius:0 7px 7px 0;background:#eef4ff;color:#1849a9;font-size:12px}.queue-filter{width:210px}.play.is-hidden{display:none}.system-meta{line-height:1.5}.panel{scroll-margin-top:18px}@media(max-width:800px){.dashboard-search{width:100%}.dashboard-tools{width:100%}.search-menu{left:0;right:auto;width:100%}}
</style><script>
(() => {
  const graphPanel = document.querySelector('#graph-title')?.closest('.panel');
  const graphHead = graphPanel?.querySelector('.panelhead');
  if (!graphPanel || !graphHead) return;

  const tools = document.createElement('div');
  tools.className = 'dashboard-tools';
  tools.innerHTML = '<input id="quick-component-search" class="dashboard-search" type="search" placeholder="Quick component search  ( / )" aria-label="Quick component search" autocomplete="off"><div id="quick-component-results" class="search-menu" hidden></div>';
  graphHead.appendChild(tools);
  const search = tools.querySelector('input');
  const menu = tools.querySelector('.search-menu');
  const note = document.createElement('p');
  note.className = 'focus-note';
  note.textContent = 'Large projects use a risk-focused graph: vulnerable components, their paths to ROOT, and direct dependencies are shown first. Use search to inspect any component.';
  graphPanel.querySelector('.graph-wrap').before(note);

  function currentProject(){ return (typeof data !== 'undefined' && data.projects) ? data.projects[active] : null; }
  function clearMenu(){ menu.hidden = true; menu.innerHTML = ''; }
  function findComponents(){
    const query = search.value.trim().toLowerCase();
    const project = currentProject();
    if (!query || !project) return clearMenu();
    const matches = project.components.filter(component => `${component.name} ${component.version} ${component.id}`.toLowerCase().includes(query)).slice(0, 12);
    if (!matches.length){ menu.innerHTML = '<button disabled>No matching components</button>'; menu.hidden = false; return; }
    menu.innerHTML = matches.map(component => `<button data-id="${encodeURIComponent(component.id)}"><strong>${esc(component.name)}</strong><small>${esc(component.version)} · ${esc(component.ecosystem)}</small></button>`).join('');
    menu.hidden = false;
    menu.querySelectorAll('button[data-id]').forEach(button => button.onclick = () => { show('graphview'); showNode(button.dataset.id); clearMenu(); });
  }
  search.addEventListener('input', findComponents);
  search.addEventListener('keydown', event => { if (event.key === 'Escape') { search.value = ''; clearMenu(); search.blur(); } });
  document.addEventListener('keydown', event => { if (event.key === '/' && document.activeElement?.tagName !== 'INPUT') { event.preventDefault(); search.focus(); } });
  document.addEventListener('click', event => { if (!tools.contains(event.target)) clearMenu(); });

  const queue = document.querySelector('#playbook');
  const queueHead = queue?.closest('.panel')?.querySelector('.panelhead');
  if (queue && queueHead) {
    const filter = document.createElement('input');
    filter.className = 'dashboard-search queue-filter';
    filter.type = 'search'; filter.placeholder = 'Filter remediation queue'; filter.setAttribute('aria-label', 'Filter remediation queue');
    queueHead.appendChild(filter);
    filter.addEventListener('input', () => { const query = filter.value.toLowerCase(); queue.querySelectorAll('.play').forEach(item => item.classList.toggle('is-hidden', !!query && !item.textContent.toLowerCase().includes(query))); });
  }
})();
</script></body>''')
