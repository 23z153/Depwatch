from __future__ import annotations

import json
import sqlite3
from datetime import date, datetime, timezone
from importlib.resources import files
from itertools import islice
from pathlib import Path
from typing import Any

import networkx as nx

from .discovery import discover_inputs, check_missing_lockfile
from .models import AnalysisResult, Component, Finding
from .osv import DEFAULT_DB, info as osv_cache_info, records_for_components
from .parsers import parse_file
from .registry_cache import DEFAULT_REGISTRY_DB, load as load_registry_cache, store as store_registry_cache

SEVERITY = {"critical": 10.0, "high": 7.5, "medium": 4.5, "low": 1.5, "unknown": 5.0}
COPYLEFT = {"GPL-2.0", "GPL-2.0-only", "GPL-3.0", "GPL-3.0-only", "AGPL-3.0", "AGPL-3.0-only", "LGPL-2.1", "LGPL-3.0"}

# Source-text reachability is a confidence signal, not a call-graph proof.
EXPLOITABILITY_WEIGHT = {"reachable": 1.15, "unknown": 1.0, "vulnerable_function_not_used": 0.85, "unreachable": 0.75, "suppressed": 0.0}


def analyze(project: str | Path, criticality: int = 3, vulnerability_db: str | None = None,
            metadata_file: str | None = None, allowed_licenses: set[str] | None = None,
            project_type: str = "proprietary-distributed", vex_file: str | None = None,
            online: bool = False, registry_metadata_online: bool = False,
            osv_db: str | None = None, registry_db: str | None = None) -> AnalysisResult:
    project = Path(project).resolve(); components: dict[str, Component] = {}; edges: list[tuple[str, str]] = []; warnings = []
    inputs = discover_inputs(project)
    if not inputs:
        warnings.append("No supported manifests or JSON SBOM files were discovered.")
    for input_file in inputs:
        parsed, file_edges, file_warnings = parse_file(input_file)
        warnings.extend(file_warnings)
        check_missing_lockfile(input_file, warnings)
        for c in parsed:
            old = components.get(c.key)
            components[c.key] = Component(**(c.__dict__ | {"direct": c.direct or (old.direct if old else False), "license": c.license or (old.license if old else None)}))
        edges.extend(file_edges)
    valid_edges = [(a, b) for a, b in edges if (a == "ROOT" or a in components) and b in components and a != b]
    graph = nx.DiGraph(); graph.add_node("ROOT"); graph.add_nodes_from(components); graph.add_edges_from(valid_edges)
    for key, comp in list(components.items()):
        if comp.direct and not graph.has_edge("ROOT", key): graph.add_edge("ROOT", key)

    # 1. Scan codebase for imports to check exploitability
    codebase_refs = _scan_codebase_references(project)

    # 2. VEX override dictionary
    vex_data = {}
    if vex_file:
        try:
            raw_vex = _load_json(vex_file)
            if isinstance(raw_vex, list):
                for item in raw_vex:
                    vid = item.get("vulnerability_id") or item.get("id")
                    if vid: vex_data[vid] = item
            elif isinstance(raw_vex, dict):
                if "vex" in raw_vex and isinstance(raw_vex["vex"], list):
                    for item in raw_vex["vex"]:
                        vid = item.get("vulnerability_id") or item.get("id")
                        if vid: vex_data[vid] = item
                else:
                    for vid, item in raw_vex.items():
                        if isinstance(item, dict): vex_data[vid] = item
                        else: vex_data[vid] = {"status": str(item)}
        except Exception as e:
            warnings.append(f"Could not load VEX file {vex_file}: {e}")

    # 3. Detect version conflicts and diamond dependencies
    conflicts = _detect_version_conflicts(components, graph)

    # 4. Resolve vulnerabilities
    db_records = _load_json(vulnerability_db) if vulnerability_db else _bundled_vulns()
    local_osv = Path(osv_db).expanduser() if osv_db else DEFAULT_DB
    if local_osv.is_file():
        _warn_if_osv_cache_stale(local_osv, warnings)
        db_records.extend(_local_osv_records(local_osv, list(components.values())))
    if online:
        api_records, osv_warning = _query_osv_api_batch(list(components.values()))
        if osv_warning:
            warnings.append(osv_warning)
        seen = {(r["id"], r["package"].lower(), r["ecosystem"].lower()) for r in db_records}
        for r in api_records:
            key = (r["id"], r["package"].lower(), r["ecosystem"].lower())
            if key not in seen:
                db_records.append(r)
                seen.add(key)
    vulns = _vulnerabilities(components, graph, db_records, codebase_refs, vex_data)

    # 5. Resolve maintenance
    metadata = _load_json(metadata_file) if metadata_file else {}
    local_registry = Path(registry_db).expanduser() if registry_db else DEFAULT_REGISTRY_DB
    cached_registry = load_registry_cache(local_registry, list(components))
    for key, cache_row in cached_registry.items():
        local_row = metadata.get(key, {})
        if not isinstance(local_row, dict): local_row = {"last_release": local_row}
        metadata[key] = cache_row | local_row
    if registry_metadata_online:
        registry_metadata, registry_warning = _query_registry_metadata(list(components.values()))
        if registry_warning:
            warnings.append(registry_warning)
        # User-provided metadata is authoritative when it disagrees with a
        # registry response, while registry data fills missing fields.
        for key, registry_row in registry_metadata.items():
            local_row = metadata.get(key, {})
            if not isinstance(local_row, dict):
                local_row = {"last_release": local_row}
            metadata[key] = registry_row | local_row
        try:
            store_registry_cache(local_registry, registry_metadata)
        except (OSError, sqlite3.Error) as exc:
            warnings.append(f"Could not update local registry metadata cache ({local_registry}): {exc}")
    unmaintained = _maintenance(components, metadata)

    # 6. Resolve licenses
    licenses = _licenses(components, allowed_licenses, project_type)

    # 7. Compute scores
    scores, raw_breakdown = _scores(components, graph, vulns, unmaintained, licenses, conflicts)
    overall, breakdown = _overall_score(scores, raw_breakdown, criticality)
    
    return AnalysisResult(str(project), sorted(components.values(), key=lambda c: c.key), sorted(graph.edges()), vulns, licenses, unmaintained, scores, overall, criticality, conflicts, warnings, breakdown)


def _bundled_vulns() -> list[dict[str, Any]]:
    return json.loads(files("sbom_risk.data").joinpath("vulnerabilities.json").read_text())


def _load_json(path: str) -> Any:
    with open(path, encoding="utf-8") as f: return json.load(f)


def _warn_if_osv_cache_stale(database: Path, warnings: list[str], max_age_days: int = 7) -> None:
    metadata = osv_cache_info(database) or {}
    synced_at = metadata.get("synced_at")
    if not synced_at:
        warnings.append(f"Local OSV cache has no sync timestamp: {database}. Run `sbom-risk sync-osv` to refresh it.")
        return
    try:
        age = datetime.now(timezone.utc) - datetime.fromisoformat(synced_at.replace("Z", "+00:00"))
        if age.days >= max_age_days:
            warnings.append(f"Local OSV cache is {age.days} days old (last synced {synced_at}); run `sbom-risk sync-osv` to refresh vulnerability data.")
    except ValueError:
        warnings.append(f"Local OSV cache has an invalid sync timestamp ({synced_at}); run `sbom-risk sync-osv` to refresh it.")


def _scan_codebase_references(project_path: Path) -> set[str]:
    import re
    refs = set()
    if project_path.is_file():
        # If the input is a single file, its codebase context is empty or we check its parent directory
        project_path = project_path.parent
    ignored = {".git", "node_modules", "vendor", ".venv", "venv", "dist", "build"}
    extensions = {".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".java", ".cpp", ".h", ".cs", ".rb", ".php"}
    for path in project_path.rglob("*"):
        if any(part in ignored for part in path.parts) or not path.is_file():
            continue
        if path.suffix not in extensions:
            continue
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")[:500000]
            for m in re.finditer(r"[a-zA-Z0-9_-]+", content):
                refs.add(m.group(0).lower())
            for m in re.finditer(r"['\"]([^'\"]+)['\"]", content):
                val = m.group(1).lower()
                refs.add(val)
                if "/" in val:
                    refs.add(val.split("/")[-1])
        except Exception:
            pass
    return refs


def _is_component_referenced(c: Component, codebase_refs: set[str], graph: nx.DiGraph) -> bool:
    if not codebase_refs:
        return True
    name_variants = {c.name.lower(), c.name.lower().replace("-", "_"), c.name.lower().replace("_", "-")}
    if name_variants.intersection(codebase_refs):
        return True
    try:
        ancestors = nx.ancestors(graph, c.key)
        for anc_key in ancestors:
            if anc_key == "ROOT": continue
            try:
                anc_name = anc_key.split(":")[1].split("@")[0].lower()
                anc_variants = {anc_name, anc_name.replace("-", "_"), anc_name.replace("_", "-")}
                if anc_variants.intersection(codebase_refs):
                    return True
            except Exception:
                pass
    except Exception:
        pass
    return False


def _detect_version_conflicts(comps: dict[str, Component], graph: nx.DiGraph) -> list[Finding]:
    from collections import defaultdict
    by_name = defaultdict(list)
    for c in comps.values():
        by_name[(c.ecosystem, c.name)].append(c)
    findings = []
    for (ecosystem, name), versions in by_name.items():
        if len(versions) <= 1:
            continue
        for i in range(len(versions)):
            for j in range(i + 1, len(versions)):
                v1 = versions[i]
                v2 = versions[j]
                paths1 = _paths(graph, v1.key)
                paths2 = _paths(graph, v2.key)
                try:
                    anc1 = nx.ancestors(graph, v1.key) - {"ROOT"}
                    anc2 = nx.ancestors(graph, v2.key) - {"ROOT"}
                    common = anc1.intersection(anc2)
                except Exception:
                    common = set()
                is_diamond = len(common) > 0
                fid = "DIAMOND-DEPENDENCY" if is_diamond else "VERSION-CONFLICT"
                severity = "high" if is_diamond else "medium"
                score = 7.0 if is_diamond else 5.0
                common_str = f" via common ancestors: {', '.join(x.split('@')[0].split(':')[-1] for x in common)}" if common else ""
                summary = f"Conflict detected for {name}: version {v1.version} and {v2.version} both resolved{common_str}."
                findings.append(Finding(v1.key, fid, severity, summary + f" Other version is {v2.version}.", paths=paths1, score=score))
                findings.append(Finding(v2.key, fid, severity, summary + f" Other version is {v1.version}.", paths=paths2, score=score))
    return findings


def _vulnerabilities(comps: dict[str, Component], graph: nx.DiGraph, records: list[dict[str, Any]], codebase_refs: set[str], vex_data: dict[str, Any]) -> list[Finding]:
    found = []
    for c in comps.values():
        for row in records:
            if row.get("package", "").lower() != c.name.lower() or row.get("ecosystem", "generic").lower() != c.ecosystem.lower(): continue
            if _matches(c.version, row.get("affected", ""), c.ecosystem):
                paths = _paths(graph, c.key)
                vuln_id = row.get("id", "UNKNOWN")

                # --- Exploitability ---
                is_referenced = _is_component_referenced(c, codebase_refs, graph)
                vuln_func = row.get("vulnerable_function")
                if not codebase_refs:
                    exploitability = "unknown"
                elif not is_referenced:
                    exploitability = "unreachable"
                elif vuln_func and vuln_func.lower() not in codebase_refs:
                    exploitability = "vulnerable_function_not_used"
                else:
                    exploitability = "reachable"

                # --- CVSS score (authoritative source of truth) ---
                cvss_val = row.get("cvss")
                severity = row.get("severity", "unknown").lower()
                if cvss_val is not None:
                    try:
                        cvss_float = float(cvss_val)
                        # Derive severity from CVSS if not already meaningful
                        if cvss_float >= 9.0: severity = "critical"
                        elif cvss_float >= 7.0: severity = "high"
                        elif cvss_float >= 4.0: severity = "medium"
                        else: severity = "low"
                    except (ValueError, TypeError):
                        cvss_float = SEVERITY.get(severity, 2.0)
                else:
                    cvss_float = SEVERITY.get(severity, 2.0)

                # Store canonical CVSS for display and scoring
                canonical_cvss = round(cvss_float, 1)

                # Compounded path risk: +10% per extra path, capped at +30%
                path_multiplier = min(1.3, 1.0 + 0.1 * max(0, len(paths) - 1))
                # Effective score = CVSS × path_multiplier × exploitability_weight (0–10 scale)
                # exploitability is not yet finalized (VEX comes later), use current value
                exploit_weight = EXPLOITABILITY_WEIGHT.get(exploitability, 0.7)
                effective_score = round(min(10.0, cvss_float * path_multiplier * exploit_weight), 2)

                # --- VEX suppression ---
                vex_status = None
                vex_justification = ""
                if vuln_id in vex_data:
                    vex_status = vex_data[vuln_id].get("status")
                    vex_justification = vex_data[vuln_id].get("justification") or vex_data[vuln_id].get("comment") or ""

                summary = row.get("summary", "Known vulnerability")
                affected_range = row.get("affected", "")

                if vex_status in {"not_affected", "suppressed", "approved-exception"}:
                    exploitability = "suppressed"
                    severity = "suppressed"
                    effective_score = 0.0
                    summary = f"[VEX-SUPPRESSED] {summary} (Justification: {vex_justification})"
                elif exploitability != "unknown":
                    summary = f"[{exploitability.upper()}] {summary}"

                found.append(Finding(
                    component=c.key,
                    finding_id=vuln_id,
                    severity=severity,
                    summary=summary,
                    fixed_version=row.get("fixed_version"),
                    references=row.get("references", []),
                    paths=paths,
                    score=effective_score,
                    cvss=canonical_cvss,
                    affected_range=affected_range,
                    exploitability=exploitability,
                ))
    return found


def _local_osv_records(database: Path, components: list[Component]) -> list[dict[str, Any]]:
    """Normalize matching local OSV records to the scanner's existing DB shape."""
    normalized: list[dict[str, Any]] = []
    records = records_for_components(database, ((c.ecosystem, c.name) for c in components))
    for component in components:
        if component.version in {"unknown", "unresolved", "", "*"}:
            continue
        for record in records.get((component.ecosystem, component.name), []):
            if not _osv_affects(record, component):
                continue
            severity, cvss = _osv_severity(record)
            fixed = _osv_fixed(record, component)
            normalized.append({
                "id": record.get("id", "OSV-UNKNOWN"), "ecosystem": component.ecosystem,
                "package": component.name, "affected": f"=={component.version}",
                "severity": severity, "cvss": cvss,
                "summary": record.get("summary") or record.get("details", "OSV vulnerability").split("\n", 1)[0],
                "fixed_version": fixed,
                "references": [r["url"] for r in record.get("references", []) if r.get("url")],
            })
    return normalized


def _osv_affects(record: dict[str, Any], component: Component) -> bool:
    for affected in record.get("affected", []):
        pkg = affected.get("package", {})
        if pkg.get("name", "").lower() != component.name.lower():
            continue
        if component.version in affected.get("versions", []):
            return True
        for range_ in affected.get("ranges", []):
            if range_.get("type") in {"SEMVER", "ECOSYSTEM"} and _osv_events_match(component.version, range_.get("events", []), component.ecosystem):
                return True
    return False


def _osv_events_match(version: str, events: list[dict[str, str]], ecosystem: str | None = None) -> bool:
    active = False
    for event in events:
        if "introduced" in event and (event["introduced"] == "0" or _version_cmp(version, event["introduced"], ecosystem) >= 0):
            active = True
        if "fixed" in event and _version_cmp(version, event["fixed"], ecosystem) >= 0:
            active = False
        if "last_affected" in event and _version_cmp(version, event["last_affected"], ecosystem) > 0:
            active = False
    return active


def _osv_fixed(record: dict[str, Any], component: Component) -> str | None:
    for affected in record.get("affected", []):
        if affected.get("package", {}).get("name", "").lower() != component.name.lower():
            continue
        for range_ in affected.get("ranges", []):
            for event in range_.get("events", []):
                if event.get("fixed"):
                    return event["fixed"]
    return None


def _osv_severity(record: dict[str, Any]) -> tuple[str, float | None]:
    import re
    for entry in record.get("severity", []):
        raw = entry.get("score", "")
        # OSV commonly stores vector strings; their numeric base score is not
        # necessarily present, so use database-specific numeric CVSS below.
        if isinstance(raw, (int, float)):
            return _severity_from_cvss(float(raw)), float(raw)
    db_specific = record.get("database_specific", {})
    cvss = db_specific.get("cvss", {}) if isinstance(db_specific, dict) else {}
    raw = cvss.get("score") if isinstance(cvss, dict) else cvss
    try:
        return _severity_from_cvss(float(raw)), float(raw)
    except (TypeError, ValueError):
        label = (db_specific.get("severity", "unknown") if isinstance(db_specific, dict) else "unknown").lower()
        return {"moderate": "medium"}.get(label, label if label in SEVERITY else "unknown"), None


def _severity_from_cvss(score: float) -> str:
    return "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low"


def _matches(version: str, expression: str, ecosystem: str | None = None) -> bool:
    if version in {"unknown", "unresolved", "", "*"}: return False
    for term in expression.split(","):
        term = term.strip()
        import re
        match = re.match(r"(<=|>=|==|=|<|>)?\s*(.+)", term)
        if not match: continue
        op, boundary = match.groups(); cmp = _version_cmp(version, boundary, ecosystem)
        if (op in (None, "=", "==") and cmp != 0) or (op == "<" and cmp >= 0) or (op == "<=" and cmp > 0) or (op == ">" and cmp <= 0) or (op == ">=" and cmp < 0): return False
    return bool(expression)


def _version_cmp(a: str, b: str, ecosystem: str | None = None) -> int:
    """Compare PyPI with PEP 440; use SemVer ordering elsewhere when possible."""
    if (ecosystem or "").lower() == "pypi":
        try:
            from packaging.version import Version
            return (Version(a) > Version(b)) - (Version(a) < Version(b))
        except Exception:
            pass
    import re
    def parse(value: str):
        value = value.strip().lstrip("v")
        release = value.split("+", 1)[0]  # SemVer build metadata has no precedence.
        base, separator, prerelease = release.partition("-")
        numbers = tuple(int(x) for x in re.findall(r"\d+", base))
        pre = [] if not separator else [int(x) if x.isdigit() else x.lower() for x in prerelease.split(".")]
        return numbers, pre
    aa, apre = parse(a); bb, bpre = parse(b)
    width = max(len(aa), len(bb)); aa += (0,) * (width - len(aa)); bb += (0,) * (width - len(bb))
    if aa != bb: return -1 if aa < bb else 1
    if not apre or not bpre:
        return 0 if not apre and not bpre else 1 if not apre else -1
    for left, right in zip(apre, bpre):
        if left == right: continue
        if isinstance(left, int) != isinstance(right, int): return -1 if isinstance(left, int) else 1
        return -1 if left < right else 1
    return (len(apre) > len(bpre)) - (len(apre) < len(bpre))


def _paths(graph: nx.DiGraph, node: str) -> list[list[str]]:
    if "ROOT" not in graph or node not in graph: return [[node]]
    try: return list(islice(nx.all_simple_paths(graph, "ROOT", node), 3))
    except (nx.NetworkXNoPath, nx.NodeNotFound): return [[node]]


def _maintenance(comps: dict[str, Component], metadata: dict[str, Any]) -> list[Finding]:
    findings = []; today = date.today()
    cutoff_abandoned = today.replace(year=today.year - 2)
    cutoff_stale = today.replace(year=today.year - 1)
    for c in comps.values():
        row = metadata.get(c.key) or metadata.get(f"{c.ecosystem}:{c.name}") or {}
        if not isinstance(row, dict):
            row = {"last_release": row}
        updated = row.get("last_release")
        if updated:
            try:
                released = datetime.fromisoformat(str(updated).replace("Z", "+00:00")).date()
                if released < cutoff_abandoned:
                    findings.append(Finding(c.key, "MAINTENANCE-ABANDONED", "medium", f"Abandoned project: no release since {released.isoformat()} (older than 2 years).", score=4.5))
                elif released < cutoff_stale:
                    findings.append(Finding(c.key, "MAINTENANCE-STALE", "low", f"Stale project: no release since {released.isoformat()} (older than 1 year).", score=2.0))
            except ValueError:
                pass
        m_count = row.get("maintainers_count")
        if m_count is not None:
            try:
                if int(m_count) == 1:
                    findings.append(Finding(c.key, "MAINTENANCE-BUS-FACTOR", "medium", "Single maintainer project (bus factor = 1).", score=3.5))
            except (ValueError, TypeError):
                pass
        if "has_security_policy" in row:
            pol = row["has_security_policy"]
            if pol is False or str(pol).lower() == "false":
                findings.append(Finding(c.key, "MAINTENANCE-NO-SECURITY-POLICY", "low", "No security policy or CVE response process documented.", score=1.5))
        if "deprecated" in row:
            dep = row["deprecated"]
            if dep is True or str(dep).lower() == "true":
                reason = row.get("deprecation_reason")
                suffix = f" Reason: {reason}" if reason else ""
                findings.append(Finding(c.key, "MAINTENANCE-DEPRECATED", "high", f"Component has been deprecated or yanked by the registry.{suffix}", score=7.0))
    return findings


def _single_license_risk(lic: str, project_type: str, allowed: set[str] | None) -> tuple[str, float, str]:
    lic_upper = lic.upper().strip()
    if allowed is not None:
        allowed_upper = {a.upper() for a in allowed}
        if lic_upper in allowed_upper:
            return "low", 0.0, f"License {lic} is allowed by policy."
        else:
            return "high", 6.0, f"License {lic} is not in the allowed list."
    COPYLEFT_VIRAL = {
        "GPL-1.0", "GPL-1.0-ONLY", "GPL-1.0-OR-LATER",
        "GPL-2.0", "GPL-2.0-ONLY", "GPL-2.0-OR-LATER",
        "GPL-3.0", "GPL-3.0-ONLY", "GPL-3.0-OR-LATER",
        "AGPL-3.0", "AGPL-3.0-ONLY", "AGPL-3.0-OR-LATER",
        "GPL", "AGPL"
    }
    COPYLEFT_WEAK = {
        "LGPL-2.0", "LGPL-2.0-ONLY", "LGPL-2.0-OR-LATER",
        "LGPL-2.1", "LGPL-2.1-ONLY", "LGPL-2.1-OR-LATER",
        "LGPL-3.0", "LGPL-3.0-ONLY", "LGPL-3.0-OR-LATER",
        "LGPL", "MPL-1.1", "MPL-2.0", "EPL-1.0", "EPL-2.0", "CDDL-1.0", "CDDL-1.1"
    }
    PERMISSIVE = {"MIT", "APACHE-2.0", "APACHE", "BSD-2-CLAUSE", "BSD-3-CLAUSE", "BSD", "ISC", "UNLICENSE", "CC0-1.0"}
    is_weak = lic_upper in COPYLEFT_WEAK or any(x in lic_upper for x in ["LGPL", "MPL-", "EPL-"])
    # Check LGPL first: the substring "GPL-2.0" in "LGPL-2.0" must never
    # promote weak copyleft to a strong/viral copyleft release-gate finding.
    is_viral = not is_weak and (lic_upper in COPYLEFT_VIRAL or any(x in lic_upper for x in ["GPL-2.0", "GPL-3.0", "AGPL"]))
    is_permissive = lic_upper in PERMISSIVE or any(x in lic_upper for x in ["MIT", "APACHE", "BSD", "ISC"])
    if is_viral:
        if project_type == "proprietary-distributed":
            return "critical", 8.0, f"Copyleft {lic} license in proprietary distributed codebase triggers distribution requirements."
        elif project_type == "proprietary-internal":
            return "low", 1.5, f"Copyleft {lic} license in internal tool. Low compliance risk since it is not distributed."
        else:
            return "low", 1.0, f"Copyleft {lic} license in open-source project. Generally compatible."
    if is_weak:
        if project_type == "proprietary-distributed":
            return "medium", 4.5, f"Weak copyleft {lic} license requires source sharing for modifications, though linking is allowed."
        elif project_type == "proprietary-internal":
            return "low", 1.0, f"Weak copyleft {lic} license in internal codebase. Low risk."
        else:
            return "low", 0.5, f"Weak copyleft {lic} license in open-source codebase."
    if is_permissive:
        return "low", 0.0, f"Permissive license {lic} is compatible and low risk."
    return "low", 1.0, f"Unrecognized license {lic}. Evaluate manually."


def _evaluate_license_expression(lic: str | None, project_type: str, allowed: set[str] | None) -> tuple[str, float, str]:
    if not lic or lic.upper() in {"NOASSERTION", "NONE", "UNKNOWN"}:
        score = 3.0 if project_type != "proprietary-internal" else 2.0
        return "medium" if project_type != "proprietary-internal" else "low", score, "No license specified (unknown legal status)."
    lic_clean = lic.replace("Dual:", "").replace("/", " OR ").replace(" or ", " OR ").replace(" and ", " AND ")
    if " OR " in lic_clean:
        parts = [p.strip() for p in lic_clean.split(" OR ") if p.strip()]
        results = [_single_license_risk(p, project_type, allowed) for p in parts]
        min_res = min(results, key=lambda x: x[1])
        return min_res[0], min_res[1], f"Dual licensed ({lic}). Chosen choice: {min_res[2]}"
    if " AND " in lic_clean:
        parts = [p.strip() for p in lic_clean.split(" AND ") if p.strip()]
        results = [_single_license_risk(p, project_type, allowed) for p in parts]
        max_res = max(results, key=lambda x: x[1])
        return max_res[0], max_res[1], f"Multi-licensed ({lic}). Combined risk: {max_res[2]}"
    return _single_license_risk(lic_clean, project_type, allowed)


def _licenses(comps: dict[str, Component], allowed: set[str] | None, project_type: str) -> list[Finding]:
    findings = []
    for c in comps.values():
        lic = c.license
        # Lockfiles often omit license metadata. That is an enrichment gap, not
        # proof of a license conflict. A strict allow-list makes it actionable.
        if lic is None and allowed is None:
            continue
        severity, score, justification = _evaluate_license_expression(lic, project_type, allowed)
        if score > 0.0:
            fid = "LICENSE-POLICY" if allowed is not None and (not lic or lic not in allowed) else ("LICENSE-UNKNOWN" if not lic or lic.upper() in {"NOASSERTION", "NONE", "UNKNOWN"} else "LICENSE-COPYLEFT")
            findings.append(Finding(c.key, fid, severity, justification, score=score))
    return findings


def _scores(comps: dict[str, Component], graph: nx.DiGraph, vulns, maintenance, licenses, conflicts) -> tuple[dict[str, float], dict[str, float]]:
    """Score each *package* once, then retain explainable score categories.

    Advisory count is intentionally not a multiplier: the highest active
    advisory is the package's vulnerability signal. Multiple advisories remain
    visible in the report, but cannot make one package dominate its peers.
    """
    per = {key: 0.0 for key in comps}
    breakdown = {"vulnerabilities": 0.0, "reachability": 0.0, "maintenance": 0.0, "license": 0.0, "dependency_conflicts": 0.0}
    by_component: dict[str, dict[str, Finding]] = {}
    for finding in vulns:
        if finding.component not in comps or finding.exploitability == "suppressed":
            continue
        # Duplicate OSV/GHSA records with the same ID resolve to one advisory.
        current = by_component.setdefault(finding.component, {}).get(finding.finding_id)
        if current is None or finding.score > current.score:
            by_component[finding.component][finding.finding_id] = finding

    for key, unique in by_component.items():
        top = max(unique.values(), key=lambda f: f.score)
        # f.score already includes reachability; expose the uplift separately.
        base_cvss = min(10.0, top.cvss if top.cvss is not None else SEVERITY.get(top.severity, 5.0))
        base = base_cvss * 8.0
        effective = min(80.0, top.score * 8.0)
        per[key] += effective
        breakdown["vulnerabilities"] += min(base, effective)
        breakdown["reachability"] += max(0.0, effective - base)

    health_values = {
        "MAINTENANCE-DEPRECATED": 5.0, "MAINTENANCE-ABANDONED": 10.0,
        "MAINTENANCE-NO-SECURITY-POLICY": 5.0, "MAINTENANCE-BUS-FACTOR": 3.0,
        "MAINTENANCE-STALE": 2.0,
    }
    for finding in maintenance:
        if finding.component in per:
            amount = health_values.get(finding.finding_id, finding.score)
            per[finding.component] += amount; breakdown["maintenance"] += amount
    for finding in licenses:
        if finding.component in per:
            amount = min(10.0, finding.score * 1.5)
            per[finding.component] += amount; breakdown["license"] += amount
    for finding in conflicts:
        if finding.component in per:
            amount = min(6.0, finding.score)
            per[finding.component] += amount; breakdown["dependency_conflicts"] += amount

    # Direct dependencies are more actionable and more exposed. Deeply nested
    # packages are still counted, but receive a modest discount.
    for key in per:
        try: depth = nx.shortest_path_length(graph, "ROOT", key)
        except nx.NetworkXNoPath: depth = 1
        depth_factor = 1.2 if depth <= 1 else 1.0 if depth <= 3 else 0.9
        per[key] = round(min(100.0, per[key] * depth_factor), 1)
    return per, breakdown


def _overall_score(component_scores: dict[str, float], raw_breakdown: dict[str, float], criticality: int) -> tuple[float, dict[str, float]]:
    """Aggregate risky packages without dilution by safe dependencies.

    The leading packages receive descending weights, then an exponential curve
    saturates the result. This makes several critical packages materially raise
    project risk without allowing an arbitrary advisory count to exceed 100.
    """
    risky = sorted((score for score in component_scores.values() if score > 0), reverse=True)
    weights = (0.60, 0.40, 0.25)
    weighted_total = sum(score * (weights[i] if i < len(weights) else 0.10) for i, score in enumerate(risky))
    raw_score = 100.0 * (1.0 - __import__("math").exp(-weighted_total / 75.0))
    criticality_factor = {1: 0.8, 2: 0.9, 3: 1.0, 4: 1.15, 5: 1.3}[criticality]
    overall = round(min(100.0, raw_score * criticality_factor), 1)
    total = sum(raw_breakdown.values())
    if total <= 0 or overall == 0:
        return overall, {}
    # Attribution is proportional and rounded; it explains the final score,
    # while the score itself remains a saturating package-level calculation.
    breakdown = {key: round(overall * value / total, 1) for key, value in raw_breakdown.items() if value > 0}
    return overall, breakdown


def _query_osv_api_batch(components: list[Component]) -> tuple[list[dict[str, Any]], str | None]:
    import urllib.request
    import urllib.error
    import json

    eco_map = {
        "pypi": "PyPI",
        "npm": "npm",
        "golang": "Go",
        "cargo": "Crates.io",
        "maven": "Maven"
    }

    queries = []
    for c in components:
        osv_eco = eco_map.get(c.ecosystem.lower(), c.ecosystem)
        queries.append({
            "package": {"name": c.name, "ecosystem": osv_eco},
            "version": c.version
        })

    if not queries:
        return [], None

    payload = {"queries": queries}
    req = urllib.request.Request(
        "https://api.osv.dev/v1/querybatch",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST"
    )

    records = []
    # Map GHSA text severity labels → representative CVSS midpoints
    GHSA_SEV_MAP = {"critical": 9.5, "high": 7.5, "moderate": 5.5, "medium": 5.5, "low": 2.5}

    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            res_data = json.loads(response.read().decode("utf-8"))
            results = res_data.get("results", [])
            for c, result in zip(components, results):
                vulns = result.get("vulns", [])
                for v in vulns:
                    # Prefer CVE alias as the canonical finding ID
                    cve_id = None
                    for alias in v.get("aliases", []):
                        if alias.startswith("CVE-"):
                            cve_id = alias
                            break
                    vuln_id = cve_id or v.get("id", "UNKNOWN")

                    # --- Parse affected ranges for this package ---
                    fixed = None
                    introduced = None   # None means "from the very start (0)"
                    has_range = False
                    for aff in v.get("affected", []):
                        if aff.get("package", {}).get("name", "").lower() != c.name.lower():
                            continue
                        for rng in aff.get("ranges", []):
                            rng_type = rng.get("type", "")
                            if rng_type not in {"SEMVER", "ECOSYSTEM"}:
                                continue
                            has_range = True
                            for evt in rng.get("events", []):
                                # "0" means "since the beginning"; treat as no lower bound
                                if "introduced" in evt and evt["introduced"] != "0":
                                    introduced = evt["introduced"]
                                if "fixed" in evt:
                                    fixed = evt["fixed"]
                        break  # use the first matching package entry

                    if has_range:
                        if introduced and fixed:
                            affected_range_str = f">={introduced},<{fixed}"
                        elif introduced:
                            affected_range_str = f">={introduced} (unfixed)"
                        elif fixed:
                            affected_range_str = f"<{fixed}"
                        else:
                            # introduced="0", no fixed → all versions up to current
                            affected_range_str = f"all versions (unfixed as of {c.version})"
                    else:
                        # OSV querybatch sometimes omits affected detail; fall back gracefully
                        affected_range_str = f"see advisory (installed: {c.version})"

                    # --- Extract CVSS score ---
                    # Priority order:
                    #   1. severity[].score as a raw float (rare but clean)
                    #   2. database_specific.cvss.score  (GitHub Advisory style — most reliable)
                    #   3. database_specific.severity text label (GHSA: CRITICAL/HIGH/MODERATE/LOW)
                    cvss_score = None

                    # 1. Try top-level severity[] array (OSV spec)
                    for sev_entry in v.get("severity", []):
                        s_type = sev_entry.get("type", "")
                        s_score = sev_entry.get("score", "")
                        if s_type in {"CVSS_V3", "CVSS_V4", "CVSS_V2"} and s_score:
                            try:
                                cvss_score = float(s_score)
                                break
                            except (ValueError, TypeError):
                                # score is a vector string like "CVSS:3.1/AV:N/..." — not a float
                                pass

                    # 2. database_specific.cvss.score (GitHub Advisory / GHSA)
                    db_spec = v.get("database_specific", {})
                    if cvss_score is None and isinstance(db_spec, dict):
                        cvss_obj = db_spec.get("cvss", {})
                        if isinstance(cvss_obj, dict):
                            raw = cvss_obj.get("score") or cvss_obj.get("baseScore")
                            try:
                                if raw is not None:
                                    cvss_score = float(raw)
                            except (ValueError, TypeError):
                                pass
                        elif isinstance(cvss_obj, (int, float)):
                            try:
                                cvss_score = float(cvss_obj)
                            except (ValueError, TypeError):
                                pass

                    # 3. database_specific.severity text label (GHSA: "HIGH", "MODERATE", …)
                    text_severity = None
                    if isinstance(db_spec, dict):
                        text_severity = (db_spec.get("severity") or "").lower()

                    if cvss_score is None and text_severity:
                        cvss_score = GHSA_SEV_MAP.get(text_severity)

                    # --- Derive severity label from CVSS or text ---
                    if cvss_score is not None:
                        s = float(cvss_score)
                        if s >= 9.0:   severity = "critical"
                        elif s >= 7.0: severity = "high"
                        elif s >= 4.0: severity = "medium"
                        else:          severity = "low"
                    elif text_severity in {"critical", "high", "moderate", "medium", "low"}:
                        severity = "high" if text_severity == "high" else \
                                   "medium" if text_severity in {"moderate", "medium"} else \
                                   "critical" if text_severity == "critical" else "low"
                    else:
                        severity = "unknown"

                    records.append({
                        "id": vuln_id,
                        "ecosystem": c.ecosystem,
                        "package": c.name,
                        "affected": affected_range_str,
                        "severity": severity,
                        "cvss": cvss_score,
                        "summary": v.get("summary") or v.get("details", "Vulnerability found via OSV API"),
                        "fixed_version": fixed,
                        "references": [ref.get("url") for ref in v.get("references", []) if ref.get("url")]
                    })
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, ValueError, OSError) as exc:
        return [], f"OSV online lookup failed; offline vulnerability data was used instead: {exc}"
    return records, None


def _query_registry_metadata(components: list[Component]) -> tuple[dict[str, dict[str, Any]], str | None]:
    """Fetch registry-native deprecation signals for exact npm/PyPI versions.

    npm exposes a ``deprecated`` field for a published version. PyPI has no
    equivalent package-wide field, but exposes whether a specific release is
    yanked, which is surfaced as a deprecation signal here.
    """
    import urllib.error
    import urllib.parse
    import urllib.request

    from concurrent.futures import ThreadPoolExecutor, as_completed

    # Lockfiles can reference the same resolved component through many paths.
    # Probe each exact component once, then run independent registry requests
    # concurrently; serial 5-second timeouts made large scans painfully slow.
    unique = {component.key: component for component in components}

    def fetch(component: Component) -> tuple[str, dict[str, Any] | None, bool]:
        if component.version in {"unknown", "unresolved", "", "*"}:
            return component.key, None, False
        try:
            if component.ecosystem == "npm":
                name = urllib.parse.quote(component.name, safe="")
                version = urllib.parse.quote(component.version, safe="")
                url = f"https://registry.npmjs.org/{name}/{version}"
                with urllib.request.urlopen(url, timeout=5) as response:
                    record = json.loads(response.read().decode("utf-8"))
                if record.get("deprecated"):
                    return component.key, {
                        "deprecated": True,
                        "deprecation_reason": str(record["deprecated"]),
                    }, False
                return component.key, {"deprecated": False}, False
            elif component.ecosystem == "pypi":
                name = urllib.parse.quote(component.name, safe="")
                version = urllib.parse.quote(component.version, safe="")
                url = f"https://pypi.org/pypi/{name}/{version}/json"
                with urllib.request.urlopen(url, timeout=5) as response:
                    record = json.loads(response.read().decode("utf-8"))
                info = record.get("info", {})
                if info.get("yanked"):
                    return component.key, {
                        "deprecated": True,
                        "deprecation_reason": str(info.get("yanked_reason") or "Release is yanked on PyPI."),
                    }, False
                return component.key, {"deprecated": False}, False
            return component.key, None, False
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, ValueError, OSError, json.JSONDecodeError):
            return component.key, None, True

    metadata: dict[str, dict[str, Any]] = {}
    failures = 0
    supported = [c for c in unique.values() if c.ecosystem in {"npm", "pypi"}]
    with ThreadPoolExecutor(max_workers=min(12, max(1, len(supported)))) as pool:
        futures = [pool.submit(fetch, component) for component in supported]
        for future in as_completed(futures):
            key, row, failed = future.result()
            if row:
                metadata[key] = row
            failures += int(failed)
    warning = f"Registry metadata lookup failed for {failures} component(s)." if failures else None
    return metadata, warning
