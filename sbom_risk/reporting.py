from __future__ import annotations

import csv
import html
import json
from pathlib import Path

import networkx as nx

from .models import AnalysisResult

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 2, "suppressed": 0}


def terminal_report(result: AnalysisResult, show_tree: bool = True) -> str:
    data = result.to_dict()["summary"]
    unique_advisories = {(f.component, f.finding_id) for f in result.vulnerabilities}
    vulnerable_components = {f.component for f in result.vulnerabilities}
    lines = [f"SBOM Risk Analyzer — {result.project}", "=" * 72,
             f"Components: {data['components']} | Edges: {data['dependencies']}",
             f"Advisories: {len(unique_advisories)} across {len(vulnerable_components)} vulnerable components | License findings: {data['license_conflicts']} | Unmaintained: {data['unmaintained']} | Version conflicts: {data.get('version_conflicts', 0)}"]
    if result.score_breakdown:
        lines.extend(["", "Score contributors (attributed points):"])
        labels = {"vulnerabilities": "Vulnerabilities", "reachability": "Reachable exposure", "maintenance": "Maintenance & package health", "license": "License policy", "dependency_conflicts": "Dependency conflicts"}
        lines.extend(f"  +{value:>4.1f}  {labels.get(key, key)}" for key, value in sorted(result.score_breakdown.items(), key=lambda item: (-item[1], item[0])))
    active_vulns = [f for f in result.vulnerabilities if f.exploitability != "suppressed"]
    suppressed_vulns = [f for f in result.vulnerabilities if f.exploitability == "suppressed"]
    groups = _vulnerability_groups(active_vulns, result)
    if show_tree:
        if groups:
            lines.extend(["", "Dependency paths to vulnerable components:"])
            for group in groups:
                lines.extend(_vulnerability_path_tree(group))
        else:
            lines.extend(["", "Dependency tree:"] + _tree(result))
    if result.vulnerabilities:
        lines.extend(["", "Vulnerable components (highest priority first):"])
        for group in groups:
            title = _short(group["component"])
            lines.extend([f"  {title}", f"  {'─' * min(68, max(12, len(title)))}"])
            lines.append(f"  {len(group['findings'])} advisories | Highest severity: {group['severity'].upper()} | Highest CVSS: {group['cvss']:.1f}" if group["cvss"] is not None else f"  {len(group['findings'])} advisories | Highest severity: {group['severity'].upper()}")
            for finding in group["findings"]:
                lines.append(f"  • {finding.finding_id}")
            lines.append(f"  Affected version: {group['version']}")
            lines.append(f"  Reachability: {group['reachability'].replace('_', ' ').title()}")
            lines.append(f"  Recommended fix: upgrade to {group['fixed_version']}" if group["fixed_version"] else "  Recommended fix: no patch available")
            if group["path"]:
                lines.append(f"  Path: {group['path']}")
        if suppressed_vulns:
            lines.extend(["", f"  {len(suppressed_vulns)} finding(s) suppressed via VEX:"])
            for f in suppressed_vulns:
                lines.append(f"    [SUPPRESSED] {f.finding_id}: {_short(f.component)} — {f.summary}")
    other = result.license_conflicts + result.unmaintained
    if other:
        lines.extend(["", "Policy & maintenance findings:"])
        lines.extend(f"  [{f.severity.upper()}] {_short(f.component)}: {f.summary}" for f in sorted(other, key=lambda x: (x.component, x.finding_id)))
    if result.version_conflicts:
        lines.extend(["", "Dependency version conflicts:"])
        for name, versions in _conflict_groups(result.version_conflicts).items():
            lines.append(f"  {name}")
            lines.append("  Versions detected: " + ", ".join(sorted(versions, key=_version_key)))
    manual = [group for group in groups if not group["fixed_version"]]
    if manual:
        lines.extend(["", "⚠ Packages requiring manual remediation:"])
        for group in manual:
            lines.append(f"  {group['component']} — {group['severity'].upper()}, no patch available")
    if result.component_scores:
        lines.extend(["", "Prioritized remediation (score/100):"])
        group_by_component = {group["component"]: group for group in groups}
        def priority(item):
            key, score = item; group = group_by_component.get(key)
            return (not (group and not group["fixed_version"]), -(SEVERITY_RANK.get(group["severity"], 0) if group else 0), -(group["cvss"] or 0.0) if group else 0.0, -score, key)
        for key, score in sorted(result.component_scores.items(), key=priority)[:8]:
            comp_vulns = [f for f in result.vulnerabilities if f.component == key and f.exploitability != "suppressed"]
            top_cvss = f"  top CVSS {max((f.cvss for f in comp_vulns if f.cvss is not None), default=0.0):.1f}" if comp_vulns else ""
            fix_state = "  ⚠ no patch" if key in group_by_component and not group_by_component[key]["fixed_version"] else ""
            lines.append(f"  {score:>5.1f}  {_short(key)}{top_cvss}{fix_state}")
    if result.parse_warnings: lines.extend(["", "Warnings:"] + [f"  {w}" for w in result.parse_warnings])
    lines.extend(["", "=" * 72, f"Overall Threat Score: {data['risk_score']}/100 — {_threat_level(data['risk_score'])}"])
    return "\n".join(lines)


def export(result: AnalysisResult, format: str, output: str | Path) -> None:
    output = Path(output); data = result.to_dict()
    if format == "json": output.write_text(json.dumps(data, indent=2), encoding="utf-8")
    elif format == "csv": _csv(result, output)
    elif format == "html": _html(result, output)
    elif format == "pdf": _pdf(terminal_report(result), output)
    else: raise ValueError(f"Unknown export format: {format}")


def _tree(result: AnalysisResult) -> list[str]:
    graph = nx.DiGraph(); graph.add_edges_from(result.edges)
    lines = []
    def visit(node, prefix="", seen=frozenset()):
        children = list(graph.successors(node)) if node in graph else []
        for i, child in enumerate(children):
            lines.append(f"  {prefix}{'└─' if i == len(children)-1 else '├─'} {_short(child)}")
            if child not in seen: visit(child, prefix + ("   " if i == len(children)-1 else "│  "), seen | {child})
    visit("ROOT")
    return lines or ["  (No resolved dependency edges; manifests may be direct-only.)"]


def _short(value: str) -> str: return value[8:] if value.startswith("generic:") else value


def _vulnerability_path_tree(group: dict) -> list[str]:
    nodes = group["path_nodes"] or [group["component"]]
    lines = []
    for index, node in enumerate(nodes):
        indent = "  " + "   " * index
        branch = "└─ " if index else ""
        lines.append(f"{indent}{branch}{_short(node)}")
    detail_indent = "  " + "   " * len(nodes)
    lines.append(f"{detail_indent}├─ {len(group['findings'])} advisories; highest {group['severity'].upper()}")
    lines.append(f"{detail_indent}├─ Reachability: {group['reachability'].replace('_', ' ').title()}")
    lines.append(f"{detail_indent}└─ Fix: upgrade to {group['fixed_version']}" if group["fixed_version"] else f"{detail_indent}└─ Fix: manual remediation required")
    return lines


def _conflict_groups(findings) -> dict[str, set[str]]:
    grouped: dict[str, set[str]] = {}
    for finding in findings:
        identifier = finding.component.split(":", 1)[-1]
        name, version = identifier.rsplit("@", 1) if "@" in identifier else (identifier, "unknown")
        grouped.setdefault(name, set()).add(version)
        # Conflict summaries contain the paired resolved version.
        import re
        match = re.search(r"Other version is ([^.\s]+(?:\.[^.\s]+)*)", finding.summary)
        if match: grouped[name].add(match.group(1).rstrip("."))
    return grouped


def _version_key(value: str):
    import re
    return tuple(int(x) if x.isdigit() else x.lower() for x in re.findall(r"\d+|[A-Za-z]+", value))


def _threat_level(score: float) -> str:
    return "CRITICAL" if score >= 80 else "HIGH" if score >= 60 else "ELEVATED" if score >= 40 else "MODERATE" if score >= 20 else "LOW"


def _vulnerability_groups(findings, result: AnalysisResult) -> list[dict]:
    """Group duplicate and distinct advisories into one remediation unit/package."""
    component_versions = {c.key: c.version for c in result.components}
    grouped: dict[str, dict] = {}
    for finding in findings:
        group = grouped.setdefault(finding.component, {"component": finding.component, "findings": {}})
        previous = group["findings"].get(finding.finding_id)
        if previous is None or finding.score > previous.score:
            group["findings"][finding.finding_id] = finding
    rendered = []
    for component, group in grouped.items():
        unique = list(group["findings"].values())
        top = max(unique, key=lambda f: (SEVERITY_RANK.get(f.severity, 0), f.cvss or 0.0, f.score))
        fixed = _highest_version([f.fixed_version for f in unique if f.fixed_version])
        path = " -> ".join(_short(x) for x in (top.paths[0] if top.paths else []))
        rendered.append({"component": component, "findings": sorted(unique, key=lambda f: f.finding_id), "severity": top.severity, "cvss": max((f.cvss for f in unique if f.cvss is not None), default=None), "version": component_versions.get(component, component.rsplit("@", 1)[-1]), "fixed_version": fixed, "path": path, "path_nodes": top.paths[0] if top.paths else [], "reachability": top.exploitability or "unknown", "score": max(f.score for f in unique)})
    return sorted(rendered, key=lambda group: (group["fixed_version"] is not None, -SEVERITY_RANK.get(group["severity"], 0), -(group["cvss"] or 0.0), -group["score"], group["component"]))


def _highest_version(versions: list[str]) -> str | None:
    if not versions: return None
    import re
    def key(value: str): return tuple(int(x) if x.isdigit() else x.lower() for x in re.findall(r"\d+|[A-Za-z]+", value))
    try: return max(versions, key=key)
    except TypeError: return versions[0]


def _csv(result: AnalysisResult, output: Path) -> None:
    all_findings = result.vulnerabilities + result.license_conflicts + result.unmaintained + result.version_conflicts
    findings = {f.component: [] for f in all_findings}
    for f in all_findings: findings.setdefault(f.component, []).append(f.finding_id)
    with output.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["component", "ecosystem", "name", "version", "direct", "license", "risk_score", "findings"]); writer.writeheader()
        for c in result.components: writer.writerow({"component": c.key, "ecosystem": c.ecosystem, "name": c.name, "version": c.version, "direct": c.direct, "license": c.license or "", "risk_score": result.component_scores.get(c.key, 0), "findings": ";".join(dict.fromkeys(findings.get(c.key, [])))})


def _html(result: AnalysisResult, output: Path) -> None:
    report = html.escape(terminal_report(result))
    output.write_text(f"<!doctype html><html><head><meta charset='utf-8'><title>SBOM Risk Report</title><style>body{{font:14px system-ui;margin:2rem;background:#fafafa}}pre{{white-space:pre-wrap;background:#fff;padding:1.5rem;border:1px solid #ddd}}</style></head><body><h1>SBOM Risk Report</h1><pre>{report}</pre></body></html>", encoding="utf-8")


def _pdf(text: str, output: Path) -> None:
    # Small dependency-free PDF writer; reports are intentionally text-only.
    lines = text.splitlines(); pages = [lines[i:i + 48] for i in range(0, len(lines), 48)] or [[]]
    objects = ["<< /Type /Catalog /Pages 2 0 R >>", ""]
    page_ids = []
    for page in pages:
        stream = "BT /F1 9 Tf 45 760 Td 11 TL " + " ".join(f"({_pdf_escape(line[:110])}) Tj T*" for line in page) + " ET"
        content_id = len(objects) + 2; page_id = len(objects) + 1; page_ids.append(page_id)
        objects.extend([f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 {content_id + 1} 0 R >> >> /Contents {content_id} 0 R >>", f"<< /Length {len(stream.encode())} >>\nstream\n{stream}\nendstream", "<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>"])
    objects[1] = f"<< /Type /Pages /Kids [{' '.join(f'{x} 0 R' for x in page_ids)}] /Count {len(page_ids)} >>"
    content = "%PDF-1.4\n"; offsets = [0]
    for i, obj in enumerate(objects, 1): offsets.append(len(content.encode())); content += f"{i} 0 obj\n{obj}\nendobj\n"
    start = len(content.encode()); content += f"xref\n0 {len(objects)+1}\n0000000000 65535 f \n" + "".join(f"{o:010d} 00000 n \n" for o in offsets[1:]) + f"trailer << /Size {len(objects)+1} /Root 1 0 R >>\nstartxref\n{start}\n%%EOF\n"
    output.write_bytes(content.encode("latin-1", "replace"))


def _pdf_escape(value: str) -> str: return value.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def global_report(results: list[AnalysisResult]) -> str:
    unique_comps = {}
    component_usages = {}
    vuln_findings = {}
    license_findings = {}
    maint_findings = {}
    version_findings = {}
    
    for r in results:
        project_name = Path(r.project).name
        for c in r.components:
            unique_comps[c.key] = c
            component_usages.setdefault(c.key, []).append(project_name)
        for f in r.vulnerabilities:
            vuln_findings.setdefault(f.component, []).append(f)
        for f in r.license_conflicts:
            license_findings.setdefault(f.component, []).append(f)
        for f in r.unmaintained:
            maint_findings.setdefault(f.component, []).append(f)
        for f in r.version_conflicts:
            version_findings.setdefault(f.component, []).append(f)
            
    lines = [
        "",
        "========================================================================",
        "Global Aggregated SBOM Risk Summary",
        "========================================================================",
        f"Analyzed {len(results)} applications: {', '.join(Path(r.project).name for r in results)}",
        f"Total unique resolved components: {len(unique_comps)}",
        f"Total unique vulnerabilities: {sum(len({f.finding_id for f in fs}) for fs in vuln_findings.values())}",
        f"Total unique license conflicts: {sum(len({f.finding_id for f in fs}) for fs in license_findings.values())}",
        f"Total unique maintenance alerts: {sum(len({f.finding_id for f in fs}) for fs in maint_findings.values())}",
        f"Total unique version conflicts: {sum(len({f.finding_id for f in fs}) for fs in version_findings.values())}",
        "",
        "Global Deduplicated Remediation Checklist:"
    ]
    
    all_affected_keys = set(vuln_findings.keys()) | set(license_findings.keys()) | set(maint_findings.keys()) | set(version_findings.keys())
    if not all_affected_keys:
        lines.append("  No remediation actions required!")
        return "\n".join(lines)
        
    for key in sorted(all_affected_keys):
        c = unique_comps[key]
        usages = ", ".join(component_usages[key])
        lines.append(f"  - {_short(key)} (used in: {usages}):")
        
        seen_v = set()
        for v in vuln_findings.get(key, []):
            if v.finding_id in seen_v: continue
            seen_v.add(v.finding_id)
            fix_str = f" (Upgrade to {v.fixed_version})" if v.fixed_version else " (No patch available)"
            lines.append(f"      [{v.severity.upper()}] {v.finding_id}: {v.summary}{fix_str}")
            
        seen_l = set()
        for l in license_findings.get(key, []):
            if l.summary in seen_l: continue
            seen_l.add(l.summary)
            lines.append(f"      [LICENSE] {l.finding_id}: {l.summary}")
            
        seen_m = set()
        for m in maint_findings.get(key, []):
            if m.summary in seen_m: continue
            seen_m.add(m.summary)
            lines.append(f"      [MAINT] {m.finding_id}: {m.summary}")

        seen_vc = set()
        for vc in version_findings.get(key, []):
            if vc.summary in seen_vc: continue
            seen_vc.add(vc.summary)
            lines.append(f"      [VERSION] {vc.finding_id}: {vc.summary}")
            
    return "\n".join(lines)
