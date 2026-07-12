from __future__ import annotations

from pathlib import Path

SUPPORTED = {
    "package-lock.json", "npm-shrinkwrap.json", "package.json", "requirements.txt",
    "poetry.lock", "pyproject.toml", "Pipfile.lock", "pom.xml", "go.mod", "Cargo.lock",
}

# A resolved lockfile is authoritative for the package manager it belongs to.
# Keep unrelated manifests (for example a Python requirements file beside a
# package-lock) so repositories containing more than one ecosystem still work.
LOCKFILE_MANIFESTS = {
    "package-lock.json": {"package.json"},
    "npm-shrinkwrap.json": {"package.json"},
    "poetry.lock": {"pyproject.toml"},
    "Pipfile.lock": set(),
    "Cargo.lock": set(),
}


def discover_inputs(project: Path) -> list[Path]:
    """Return manifests/SBOMs below a project, skipping common generated directories."""
    if project.is_file():
        return [project]
    found: list[Path] = []
    ignored = {".git", "node_modules", "vendor", ".venv", "venv", "dist", "build"}
    for path in project.rglob("*"):
        if any(part in ignored for part in path.parts) or not path.is_file():
            continue
        low = path.name.lower()
        if path.name in SUPPORTED or low.endswith((".cdx.json", ".cyclonedx.json", ".spdx.json")):
            found.append(path)
    names_by_parent: dict[Path, set[str]] = {}
    for path in found:
        names_by_parent.setdefault(path.parent, set()).add(path.name)
    selected = []
    for path in found:
        suppressed = set().union(*(LOCKFILE_MANIFESTS.get(name, set()) for name in names_by_parent[path.parent]))
        if path.name not in suppressed:
            selected.append(path)
    return sorted(selected, key=lambda p: (str(p.parent), p.name))
