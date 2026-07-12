"""Generate minimal, portable SBOMs from the manifests this tool understands."""
from __future__ import annotations

import json
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from .discovery import discover_inputs, check_missing_lockfile
from .models import Component
from .parsers import parse_file

SBOMFormat = Literal["cyclonedx", "spdx"]


def ensure_sbom(project: str | Path, format: SBOMFormat, output: str | Path | None = None) -> tuple[Path, bool]:
    """Return an existing SBOM, or generate one from supported project inputs."""
    project = Path(project).resolve()
    inputs = discover_inputs(project)
    existing = next((item for item in inputs if _is_sbom(item)), None)
    if existing:
        return existing, False
    destination = Path(output).resolve() if output else _default_output(project, format)
    return generate_sbom(project, format, destination), True


def generate_sbom(project: str | Path, format: SBOMFormat, output: str | Path) -> Path:
    """Generate a CycloneDX or SPDX JSON document without invoking build tools."""
    project = Path(project).resolve()
    output = Path(output).resolve()
    components, edges, warnings = _collect(project)
    if not components:
        detail = f" Warnings: {'; '.join(warnings)}" if warnings else ""
        raise ValueError(f"No supported, parseable manifests were found to generate an SBOM.{detail}")
    
    import sys
    for warning in warnings:
        print(f"warning: {warning}", file=sys.stderr)
        
    if format == "cyclonedx":
        document = _cyclonedx(project, components, edges)
    elif format == "spdx":
        document = _spdx(project, components, edges)
    else:
        raise ValueError(f"Unsupported SBOM format: {format}")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    return output


def _collect(project: Path) -> tuple[dict[str, Component], list[tuple[str, str]], list[str]]:
    components: dict[str, Component] = {}
    edges: list[tuple[str, str]] = []
    warnings: list[str] = []
    for input_file in discover_inputs(project):
        if _is_sbom(input_file):
            continue
        parsed, file_edges, file_warnings = parse_file(input_file)
        warnings.extend(file_warnings)
        check_missing_lockfile(input_file, warnings)
        for component in parsed:
            previous = components.get(component.key)
            components[component.key] = Component(**(component.__dict__ | {
                "direct": component.direct or (previous.direct if previous else False),
                "license": component.license or (previous.license if previous else None),
            }))
        edges.extend(file_edges)
    valid_edges = [(a, b) for a, b in edges if (a == "ROOT" or a in components) and b in components and a != b]
    for key, component in components.items():
        if component.direct and ("ROOT", key) not in valid_edges:
            valid_edges.append(("ROOT", key))
    return components, list(dict.fromkeys(valid_edges)), warnings


def _cyclonedx(project: Path, components: dict[str, Component], edges: list[tuple[str, str]]) -> dict:
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.5", "serialNumber": f"urn:uuid:sbom-risk-{project.name}", "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": [{"vendor": "sbom-risk", "name": "SBOM Risk Analyzer"}],
            "component": {
                "bom-ref": "ROOT",
                "type": "application",
                "name": project.name,
            }
        },
        "components": [_cdx_component(component) for component in sorted(components.values(), key=lambda c: c.key)],
        "dependencies": [{"ref": source, "dependsOn": sorted(target for parent, target in edges if parent == source)}
                         for source in sorted({parent for parent, _ in edges})],
    }


def _cdx_component(component: Component) -> dict:
    item = {"type": "library", "bom-ref": component.key, "name": component.name, "version": component.version,
            "purl": f"pkg:{component.ecosystem}/{urllib.parse.quote(component.name, safe='')}@{urllib.parse.quote(component.version, safe='')}"}
    if component.license:
        item["licenses"] = [{"expression": component.license}]
    return item


def _spdx(project: Path, components: dict[str, Component], edges: list[tuple[str, str]]) -> dict:
    refs = {key: f"SPDXRef-Package-{index}" for index, key in enumerate(sorted(components), 1)}
    packages = []
    for key in sorted(components):
        component = components[key]
        packages.append({"SPDXID": refs[key], "name": component.name, "versionInfo": component.version,
                         "licenseConcluded": component.license or "NOASSERTION", "downloadLocation": "NOASSERTION"})
    relationships = []
    for parent, child in edges:
        relationships.append({"spdxElementId": "SPDXRef-DOCUMENT" if parent == "ROOT" else refs[parent],
                              "relationshipType": "DEPENDS_ON", "relatedSpdxElement": refs[child]})
    return {"spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT",
            "name": f"{project.name}-sbom", "documentNamespace": f"https://sbom-risk.local/{project.name}",
            "creationInfo": {"created": datetime.now(timezone.utc).isoformat(), "creators": ["Tool: sbom-risk"]},
            "packages": packages, "relationships": relationships}


def _is_sbom(path: Path) -> bool:
    return path.name.lower().endswith((".cdx.json", ".cyclonedx.json", ".spdx.json"))


def _default_output(project: Path, format: SBOMFormat) -> Path:
    directory = project.parent if project.is_file() else project
    return directory / ("sbom.cdx.json" if format == "cyclonedx" else "sbom.spdx.json")
