from __future__ import annotations

import json
import re
try:  # Python 3.11+
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib
import xml.etree.ElementTree as ET
from pathlib import Path

from .models import Component

ParseResult = tuple[list[Component], list[tuple[str, str]], list[str]]


def parse_file(path: Path) -> ParseResult:
    name = path.name.lower()
    try:
        if name in {"package-lock.json", "npm-shrinkwrap.json"}:
            return _npm_lock(path)
        if name == "package.json": return _package_json(path)
        if name == "requirements.txt": return _requirements(path)
        if name == "poetry.lock": return _poetry(path)
        if name == "pyproject.toml": return _pyproject(path)
        if name == "pipfile.lock": return _pipfile(path)
        if name == "pom.xml": return _pom(path)
        if name == "go.mod": return _go_mod(path)
        if name == "cargo.lock": return _cargo_lock(path)
        if name.endswith((".cdx.json", ".cyclonedx.json")): return _cyclonedx(path)
        if name.endswith(".spdx.json"): return _spdx(path)
    except (OSError, ValueError, KeyError, ET.ParseError) as exc:
        return [], [], [f"Could not parse {path}: {exc}"]
    return [], [], [f"Unsupported input: {path}"]


def _component(name: str, version: str, ecosystem: str, direct=False, license=None, source=None) -> Component:
    return Component(name=name, version=str(version or "unknown"), ecosystem=ecosystem,
                     direct=direct, license=license, source=source)


def _requirements(path: Path) -> ParseResult:
    items = []
    for line in path.read_text().splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith(("-", ".")): continue
        match = re.match(r"([A-Za-z0-9_.-]+)(?:\[.*?\])?\s*(?:==|===)\s*([^;\s]+)", line)
        if match: items.append(_component(match.group(1).lower(), match.group(2), "pypi", True, source=str(path)))
        else:
            name = re.match(r"([A-Za-z0-9_.-]+)", line)
            if name: items.append(_component(name.group(1).lower(), "unresolved", "pypi", True, source=str(path)))
    return items, [], []


def _package_json(path: Path) -> ParseResult:
    data = json.loads(path.read_text()); items = []
    for kind in ("dependencies", "devDependencies", "optionalDependencies"):
        for name, version in data.get(kind, {}).items():
            items.append(_component(name, str(version).lstrip("^~>=< "), "npm", True, source=str(path)))
    return items, [], []


def _npm_lock(path: Path) -> ParseResult:
    data = json.loads(path.read_text()); comps: dict[str, Component] = {}; edges = []
    packages = data.get("packages")
    if isinstance(packages, dict):
        locations: dict[str, str] = {}
        for location, pkg in packages.items():
            if not location: continue
            name = pkg.get("name") or location.rsplit("node_modules/", 1)[-1]
            # Installation location alone does not mean "direct": npm hoists
            # transitive packages to the root node_modules directory.
            c = _component(name, pkg.get("version", "unknown"), "npm", False, pkg.get("license"), str(path))
            comps[c.key] = c; locations[location] = c.key
        root = packages.get("", {})
        for name in root.get("dependencies", {}):
            child = _npm_resolve_location("", name, locations)
            if child:
                edges.append(("ROOT", child))
                current = comps[child]
                comps[child] = Component(**(current.__dict__ | {"direct": True}))
        for location, pkg in packages.items():
            if not location: continue
            parent = locations.get(location)
            for child_name in pkg.get("dependencies", {}):
                child = _npm_resolve_location(location, child_name, locations)
                if parent and child: edges.append((parent, child))
    else:  # npm lockfile v1
        def walk(deps, parent=None):
            for n, value in deps.items():
                c = _component(n, value.get("version", "unknown"), "npm", parent is None, value.get("license"), str(path)); comps[c.key] = c
                edges.append(((parent or "ROOT"), c.key)); walk(value.get("dependencies", {}), c.key)
        walk(data.get("dependencies", {}))
    return list(comps.values()), list(dict.fromkeys(edges)), []


def _npm_resolve_location(parent_location: str, dependency: str, locations: dict[str, str]) -> str | None:
    """Resolve an npm dependency using Node's nearest-node_modules lookup."""
    current = parent_location
    while True:
        candidate = f"{current}/node_modules/{dependency}" if current else f"node_modules/{dependency}"
        if candidate in locations:
            return locations[candidate]
        if not current:
            return None
        marker = "/node_modules/"
        current = current.rsplit(marker, 1)[0] if marker in current else ""


def _poetry(path: Path) -> ParseResult:
    data = tomllib.loads(path.read_text()); packages = data.get("package", []); comps = {}
    by_name = {}
    for p in packages:
        c = _component(p["name"], p.get("version", "unknown"), "pypi", source=str(path)); comps[c.key] = c; by_name[c.name.lower()] = c.key
    edges = []
    for p in packages:
        parent = by_name.get(p["name"].lower())
        for child in p.get("dependencies", {}):
            if parent and child.lower() in by_name: edges.append((parent, by_name[child.lower()]))
    children = {b for _, b in edges}
    comps = {k: Component(**(c.__dict__ | {"direct": k not in children})) for k, c in comps.items()}
    return list(comps.values()), edges, []


def _pyproject(path: Path) -> ParseResult:
    data = tomllib.loads(path.read_text()); deps = data.get("project", {}).get("dependencies", [])
    if not deps: deps = list(data.get("tool", {}).get("poetry", {}).get("dependencies", {}).items())
    lines = [x if isinstance(x, str) else f"{x[0]}=={x[1]}" for x in deps if not (isinstance(x, tuple) and x[0] == "python")]
    fake = path.with_name("requirements.txt")
    items = []
    for line in lines:
        m = re.match(r"([\w.-]+).*?(?:==|>=|~=|\^)?\s*([\w.+-]+)?", line)
        if m: items.append(_component(m.group(1).lower(), m.group(2) or "unresolved", "pypi", True, source=str(fake)))
    return items, [], []


def _pipfile(path: Path) -> ParseResult:
    data = json.loads(path.read_text()); items = []
    for group in ("default", "develop"):
        for name, meta in data.get(group, {}).items():
            ver = meta.get("version", "unresolved") if isinstance(meta, dict) else str(meta)
            items.append(_component(name.lower(), ver.lstrip("="), "pypi", True, source=str(path)))
    return items, [], []


def _pom(path: Path) -> ParseResult:
    root = ET.parse(path).getroot(); ns = {"m": root.tag.split("}")[0].strip("{")} if "}" in root.tag else {}
    def txt(node, key):
        found = node.find(f"m:{key}", ns) if ns else node.find(key)
        return found.text.strip() if found is not None and found.text else "unknown"
    deps = root.findall(".//m:dependencies/m:dependency", ns) if ns else root.findall(".//dependencies/dependency")
    items = []
    for d in deps:
        scope = txt(d, "scope")
        if scope == "test": continue
        name = f"{txt(d, 'groupId')}:{txt(d, 'artifactId')}"; items.append(_component(name, txt(d, "version"), "maven", True, source=str(path)))
    return items, [], []


def _go_mod(path: Path) -> ParseResult:
    items = []
    for line in path.read_text().splitlines():
        m = re.match(r"\s*([^\s]+)\s+(v[^\s]+)", line)
        if m and not line.strip().startswith(("module", "go ")): items.append(_component(m.group(1), m.group(2), "golang", True, source=str(path)))
    return items, [], []


def _cargo_lock(path: Path) -> ParseResult:
    data = tomllib.loads(path.read_text()); items = [_component(p["name"], p.get("version", "unknown"), "cargo", source=str(path)) for p in data.get("package", [])]
    return items, [], []


def _cyclonedx(path: Path) -> ParseResult:
    data = json.loads(path.read_text()); comps = {}; refmap = {}
    for x in data.get("components", []):
        purl = x.get("purl", ""); ecosystem = _purl_type(purl) or x.get("type", "generic")
        lic = next((l.get("license", {}).get("id") or l.get("expression") for l in x.get("licenses", []) if isinstance(l, dict)), None)
        c = _component(x.get("name", "unknown"), x.get("version", "unknown"), ecosystem, license=lic, source=str(path)); comps[c.key] = c; refmap[x.get("bom-ref", purl or c.key)] = c.key
    edges = [(refmap.get(d.get("ref"), d.get("ref")), refmap.get(x, x)) for d in data.get("dependencies", []) for x in d.get("dependsOn", [])]
    children = {b for _, b in edges}; comps = {k: Component(**(v.__dict__ | {"direct": k not in children})) for k,v in comps.items()}
    return list(comps.values()), edges, []


def _spdx(path: Path) -> ParseResult:
    data = json.loads(path.read_text()); comps = {}; refs = {}
    for p in data.get("packages", []):
        c = _component(p.get("name", "unknown"), p.get("versionInfo", "unknown"), "generic", license=p.get("licenseConcluded"), source=str(path)); comps[c.key] = c; refs[p.get("SPDXID", c.key)] = c.key
    document_ref = data.get("SPDXID", "SPDXRef-DOCUMENT")
    edges = []
    for relationship in data.get("relationships", []):
        kind = relationship.get("relationshipType")
        if kind not in {"DEPENDS_ON", "DEPENDENCY_OF"}:
            continue
        source = relationship.get("spdxElementId")
        target = relationship.get("relatedSpdxElement")
        if kind == "DEPENDENCY_OF":
            source, target = target, source
        edges.append(("ROOT" if source == document_ref else refs.get(source, source), refs.get(target, target)))
    return list(comps.values()), edges, []


def _purl_type(purl: str) -> str | None:
    return purl[4:].split("/", 1)[0] if purl.startswith("pkg:") and "/" in purl else None
