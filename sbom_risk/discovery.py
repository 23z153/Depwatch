from __future__ import annotations

from pathlib import Path

SUPPORTED = {
    "package-lock.json", "npm-shrinkwrap.json", "package.json",
    "yarn.lock",
    "requirements.txt",
    "poetry.lock", "pyproject.toml", "Pipfile.lock",
    "pom.xml", "go.mod", "Cargo.lock",
    "Gemfile.lock", "Gemfile",
    "composer.lock", "composer.json",
}

# A resolved lockfile is authoritative for the package manager it belongs to.
# Keep unrelated manifests (for example a Python requirements file beside a
# package-lock) so repositories containing more than one ecosystem still work.
LOCKFILE_MANIFESTS = {
    "package-lock.json": {"package.json"},
    "npm-shrinkwrap.json": {"package.json"},
    # yarn.lock is authoritative over package.json for npm projects.
    "yarn.lock": {"package.json"},
    "poetry.lock": {"pyproject.toml"},
    "Pipfile.lock": set(),
    "Cargo.lock": set(),
    # Gemfile.lock is authoritative over the bare Gemfile.
    "Gemfile.lock": {"Gemfile"},
    # composer.lock is authoritative over composer.json.
    "composer.lock": {"composer.json"},
}


def discover_inputs(project: Path) -> list[Path]:
    """Return manifests/SBOMs below a project, skipping common generated directories."""
    if project.is_file():
        for lockfile_name, suppressed_set in LOCKFILE_MANIFESTS.items():
            if project.name in suppressed_set:
                lockfile_path = project.parent / lockfile_name
                if lockfile_path.is_file():
                    return [lockfile_path]
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


def check_missing_lockfile(path: Path, warnings: list[str]) -> None:
    """Check if a bare manifest file is parsed without a corresponding lockfile,
    and add warning instructions for building lockfiles on trusted environments.
    """
    name = path.name.lower()
    if name == "package.json":
        lockfile_path1 = path.parent / "package-lock.json"
        lockfile_path2 = path.parent / "yarn.lock"
        if not lockfile_path1.is_file() and not lockfile_path2.is_file():
            warnings.append(
                "No package-lock.json or yarn.lock was found next to package.json. "
                "Transitive dependencies cannot be analyzed. "
                "Instruction: Run 'npm install --package-lock-only' or 'yarn install' in a trusted environment to generate the lockfile."
            )
    elif name == "pyproject.toml":
        lockfile_path = path.parent / "poetry.lock"
        if not lockfile_path.is_file():
            warnings.append(
                "No poetry.lock was found next to pyproject.toml. "
                "Transitive dependencies cannot be analyzed. "
                "Instruction: Run 'poetry lock --no-update' in a trusted environment to generate the lockfile."
            )
    elif name == "gemfile":
        lockfile_path = path.parent / "Gemfile.lock"
        if not lockfile_path.is_file():
            warnings.append(
                "No Gemfile.lock was found next to Gemfile. "
                "Transitive dependencies cannot be analyzed. "
                "Instruction: Run 'bundle lock' in a trusted environment to generate the lockfile."
            )
    elif name == "composer.json":
        lockfile_path = path.parent / "composer.lock"
        if not lockfile_path.is_file():
            warnings.append(
                "No composer.lock was found next to composer.json. "
                "Transitive dependencies cannot be analyzed. "
                "Instruction: Run 'composer update --lock' in a trusted environment to generate the lockfile."
            )
    elif name == "go.mod":
        lockfile_path = path.parent / "go.sum"
        if not lockfile_path.is_file():
            warnings.append(
                "No go.sum was found next to go.mod. "
                "Transitive dependencies cannot be analyzed. "
                "Instruction: Run 'go mod tidy' in a trusted environment to generate the lockfile."
            )

