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
        if name == "yarn.lock": return _yarn_lock(path)
        if name == "requirements.txt": return _requirements(path)
        if name == "poetry.lock": return _poetry(path)
        if name == "pyproject.toml": return _pyproject(path)
        if name == "pipfile.lock": return _pipfile(path)
        if name == "pom.xml": return _pom(path)
        if name == "go.mod": return _go_mod(path)
        if name == "cargo.lock": return _cargo_lock(path)
        if name == "gemfile.lock": return _gemfile_lock(path)
        if name == "composer.lock": return _composer_lock(path)
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
        for dep_type in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
            for name in root.get(dep_type, {}):
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
    """Parse go.mod (direct deps) and go.sum (transitive) for the full picture.

    go.mod lists only the *minimum required* module versions and marks some as
    ``// indirect``.  go.sum (in the same directory) is a flat checksum file
    that mentions every module transitively resolved by ``go mod download``.
    We use go.sum to surface transitive modules that are missing from go.mod,
    then mark only go.mod entries as direct.  No edge graph is available
    without running ``go mod graph``; edges are left empty so the analyzer
    falls back to the flat component list.
    """
    direct_modules: dict[str, str] = {}   # module path -> version
    indirect_modules: dict[str, str] = {}
    for line in path.read_text().splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(("module ", "go ", "toolchain ", "//", "require (", ")", "replace ", "exclude ")):
            continue
        # Handles both block-style (inside require ( )) and inline require lines.
        m = re.match(r"(?:require\s+)?([^\s]+)\s+(v[^\s]+)(.*)", stripped)
        if not m:
            continue
        mod_path, version, rest = m.group(1), m.group(2), m.group(3)
        is_indirect = "// indirect" in rest
        if is_indirect:
            indirect_modules[mod_path] = version
        else:
            direct_modules[mod_path] = version

    items: list[Component] = []
    seen: set[str] = set()
    for mod_path, version in direct_modules.items():
        c = _component(mod_path, version, "golang", True, source=str(path))
        items.append(c)
        seen.add(mod_path)
    for mod_path, version in indirect_modules.items():
        c = _component(mod_path, version, "golang", False, source=str(path))
        items.append(c)
        seen.add(mod_path)

    # Augment with go.sum for any transitives not declared in go.mod at all.
    go_sum = path.with_name("go.sum")
    if go_sum.is_file():
        for line in go_sum.read_text().splitlines():
            parts = line.split()
            if len(parts) < 2:
                continue
            mod_path = parts[0]
            raw_ver = parts[1].split("/")[0]   # strip /go.mod suffix
            if mod_path not in seen:
                c = _component(mod_path, raw_ver, "golang", False, source=str(go_sum))
                items.append(c)
                seen.add(mod_path)
    return items, [], []


def _cargo_lock(path: Path) -> ParseResult:
    """Parse Cargo.lock, recovering full transitive dependency edges.

    Cargo.lock stores a flat list of [[package]] sections. Each package may
    have a ``dependencies`` list of strings in the form ``name`` or
    ``name version`` (and optionally a registry/source suffix that we ignore).
    We index all packages by both ``name@version`` and bare ``name`` (the
    latter is only used when the name is unambiguous), then walk the dep
    strings to emit edges.
    """
    data = tomllib.loads(path.read_text())
    packages = data.get("package", [])
    comps: dict[str, Component] = {}
    # Index: "name@version" -> component key
    by_name_ver: dict[str, str] = {}
    # Index: bare name -> list of keys (used to resolve unversioned refs)
    by_name: dict[str, list[str]] = {}
    for p in packages:
        c = _component(p["name"], p.get("version", "unknown"), "cargo", source=str(path))
        comps[c.key] = c
        nv = f"{p['name']}@{p.get('version', 'unknown')}"
        by_name_ver[nv] = c.key
        by_name.setdefault(p["name"], []).append(c.key)
    edges: list[tuple[str, str]] = []
    for p in packages:
        parent_nv = f"{p['name']}@{p.get('version', 'unknown')}"
        parent = by_name_ver.get(parent_nv)
        if not parent:
            continue
        for dep_str in p.get("dependencies", []):
            # dep_str is "name", "name version", or "name version (source)"
            parts = dep_str.split()
            dep_name = parts[0]
            dep_ver = parts[1] if len(parts) >= 2 else None
            if dep_ver:
                child = by_name_ver.get(f"{dep_name}@{dep_ver}")
            else:
                candidates = by_name.get(dep_name, [])
                child = candidates[0] if len(candidates) == 1 else None
            if child and parent != child:
                edges.append((parent, child))
    # Mark components that are never a child of another component as direct.
    children = {b for _, b in edges}
    comps = {k: Component(**(c.__dict__ | {"direct": k not in children})) for k, c in comps.items()}
    return list(comps.values()), list(dict.fromkeys(edges)), []


def _yarn_lock(path: Path) -> ParseResult:
    """Parse yarn.lock v1 with full transitive edge resolution.

    Each stanza maps one or more ``name@range`` aliases to a single resolved
    package.  The ``dependencies:`` sub-block lists what that package itself
    requires, expressed as ``name  "range"`` lines.  We build a
    ``range_to_key`` index so we can resolve those dependency ranges to their
    installed component keys and emit parent→child edges.
    """
    text = path.read_text(encoding="utf-8", errors="replace")
    if "__metadata:" in text and "version:" in text and "resolution:" in text:
        return [], [], [f"{path}: yarn berry (v2+) lockfile detected; only yarn classic (v1) is supported. Generate a CycloneDX SBOM for full analysis."]

    comps: dict[str, Component] = {}
    range_to_key: dict[str, str] = {}   # "name@range" -> component key
    by_name: dict[str, list[str]] = {}  # bare name  -> [component keys]
    entry_deps: dict[str, dict[str, str]] = {}  # key -> {dep_name: dep_range}

    current_aliases: list[str] = []
    current_version: str | None = None
    current_deps: dict[str, str] = {}
    in_deps = False

    def _flush() -> None:
        nonlocal current_aliases, current_version, current_deps, in_deps
        if not current_aliases or current_version is None:
            current_aliases, current_version, current_deps, in_deps = [], None, {}, False
            return
        # Name comes from the first alias (strip surrounding quotes).
        raw_name = current_aliases[0].strip('"')
        # Handle scoped packages: "@scope/pkg@range" -> "@scope/pkg"
        if raw_name.startswith("@"):
            pkg_name = "@" + raw_name[1:].rsplit("@", 1)[0]
        else:
            pkg_name = raw_name.rsplit("@", 1)[0]
        c = _component(pkg_name, current_version, "npm", source=str(path))
        comps[c.key] = c
        by_name.setdefault(pkg_name, []).append(c.key)
        for alias in current_aliases:
            range_to_key[alias.strip('"')] = c.key
        entry_deps[c.key] = dict(current_deps)
        current_aliases, current_version, current_deps, in_deps = [], None, {}, False

    for raw_line in text.splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(raw_line) - len(raw_line.lstrip(" "))
        if indent == 0:
            _flush()
            header = stripped.rstrip(":")
            current_aliases = [a.strip() for a in header.split(",")]
            in_deps = False
        elif stripped.startswith("version "):
            current_version = stripped.split('"')[1] if '"' in stripped else stripped.split()[-1].strip('"')
        elif stripped == "dependencies:":
            in_deps = True
        elif in_deps and indent >= 4:
            # dep line:  depname "range"  OR  "depname" "range"
            parts = stripped.split(None, 1)
            dep_name = parts[0].strip('"')
            dep_range = parts[1].strip().strip('"') if len(parts) > 1 else ""
            current_deps[dep_name] = dep_range
        elif in_deps and indent < 4:
            in_deps = False
    _flush()

    edges: list[tuple[str, str]] = []
    for parent_key, deps in entry_deps.items():
        for dep_name, dep_range in deps.items():
            alias = f"{dep_name}@{dep_range}"
            child = range_to_key.get(alias)
            if child is None:
                # Scoped alias search
                candidates = by_name.get(dep_name, [])
                child = candidates[0] if len(candidates) == 1 else None
            if child and parent_key != child:
                edges.append((parent_key, child))

    children = {b for _, b in edges}
    comps = {k: Component(**(c.__dict__ | {"direct": k not in children})) for k, c in comps.items()}
    return list(comps.values()), list(dict.fromkeys(edges)), []


def _gemfile_lock(path: Path) -> ParseResult:
    """Parse Gemfile.lock (Bundler) with full transitive edges.

    The ``GEM … specs:`` block lists every installed gem at 4-space indent.
    Each gem's own dependencies appear at 6-space indent beneath it.  We do a
    two-pass parse: first collect all gems into ``by_name``, then wire edges,
    so forward-references (alphabetical ordering) resolve correctly.
    """
    text = path.read_text(encoding="utf-8", errors="replace")
    comps: dict[str, Component] = {}
    by_name: dict[str, str] = {}           # gem name (lower) -> component key
    gem_raw_deps: dict[str, list[str]] = {}  # key -> [dep_name_lower, ...]

    in_specs = False
    gem_block = False
    current_key: str | None = None

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        indent = len(line) - len(line.lstrip(" "))

        if stripped in ("GEM", "PATH", "GIT"):
            gem_block = (stripped == "GEM")
            in_specs = False
            current_key = None
        elif stripped in ("DEPENDENCIES", "BUNDLED WITH", "RUBY VERSION", "PLATFORMS"):
            gem_block = False
            in_specs = False
            current_key = None
        elif stripped == "specs:" and gem_block:
            in_specs = True
        elif in_specs and indent == 4:
            # Top-level gem:  "    name (version)"
            m = re.match(r"([A-Za-z0-9_.\-]+)\s+\(([^)]+)\)", stripped)
            if m:
                gname, raw_ver = m.group(1), m.group(2)
                # Version may include operators: "= 1.0", "~> 2" — strip them.
                version = re.sub(r"^[=~><! ]+", "", raw_ver).strip()
                c = _component(gname, version, "gem", source=str(path))
                comps[c.key] = c
                by_name[gname.lower()] = c.key
                gem_raw_deps[c.key] = []
                current_key = c.key
        elif in_specs and indent == 6 and current_key:
            # Dependency of current gem:  "      depname (req)"
            m = re.match(r"([A-Za-z0-9_.\-]+)", stripped)
            if m:
                gem_raw_deps[current_key].append(m.group(1).lower())

    edges: list[tuple[str, str]] = []
    for parent_key, dep_names in gem_raw_deps.items():
        for dep_name in dep_names:
            child = by_name.get(dep_name)
            if child and parent_key != child:
                edges.append((parent_key, child))

    children = {b for _, b in edges}
    comps = {k: Component(**(c.__dict__ | {"direct": k not in children})) for k, c in comps.items()}
    return list(comps.values()), list(dict.fromkeys(edges)), []


def _composer_lock(path: Path) -> ParseResult:
    """Parse composer.lock (PHP) with full transitive edges.

    Each package entry has a ``require`` dict that maps dependency names to
    version constraints.  Platform requirements (``php``, ``ext-*``,
    ``lib-*``) are skipped; only Packagist packages are modelled.
    """
    data = json.loads(path.read_text())
    comps: dict[str, Component] = {}
    by_name: dict[str, str] = {}           # package name (lower) -> key
    pkg_deps: dict[str, list[str]] = {}    # key -> [dep_name_lower, ...]

    for section in ("packages", "packages-dev"):
        for p in data.get(section, []):
            pname = p.get("name", "unknown")
            version = p.get("version", "unknown").lstrip("v")
            c = _component(pname, version, "composer", source=str(path))
            comps[c.key] = c
            by_name[pname.lower()] = c.key
            # Collect only package deps (skip platform reqs).
            pkg_deps[c.key] = [
                dep.lower() for dep in p.get("require", {})
                if not dep.lower().startswith(("php", "ext-", "lib-", "hhvm"))
            ]

    edges: list[tuple[str, str]] = []
    for parent_key, dep_names in pkg_deps.items():
        for dep_name in dep_names:
            child = by_name.get(dep_name)
            if child and parent_key != child:
                edges.append((parent_key, child))

    children = {b for _, b in edges}
    comps = {k: Component(**(c.__dict__ | {"direct": k not in children})) for k, c in comps.items()}
    return list(comps.values()), list(dict.fromkeys(edges)), []


def _cyclonedx(path: Path) -> ParseResult:
    # CycloneDX component types (library, framework, container, …) are NOT
    # ecosystems. Only the purl carries reliable ecosystem information.
    _CDX_TYPE_NOT_ECOSYSTEM = {"library", "framework", "container", "device", "firmware", "file", "operating-system", "application"}
    data = json.loads(path.read_text()); comps = {}; refmap = {}
    for x in data.get("components", []):
        purl = x.get("purl", "")
        raw_type = x.get("type", "generic")
        ecosystem = _purl_type(purl) or ("generic" if raw_type in _CDX_TYPE_NOT_ECOSYSTEM else raw_type)
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
