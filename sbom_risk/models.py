from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class Component:
    name: str
    version: str = "unknown"
    ecosystem: str = "generic"
    license: str | None = None
    purl: str | None = None
    direct: bool = False
    source: str | None = None

    @property
    def key(self) -> str:
        return f"{self.ecosystem}:{self.name}@{self.version}"


@dataclass
class Finding:
    component: str
    finding_id: str
    severity: str
    summary: str
    fixed_version: str | None = None
    references: list[str] = field(default_factory=list)
    paths: list[list[str]] = field(default_factory=list)
    score: float = 0.0
    # Vulnerability-specific enrichment fields (optional; None for non-CVE findings)
    cvss: float | None = None
    affected_range: str | None = None
    exploitability: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AnalysisResult:
    project: str
    components: list[Component]
    edges: list[tuple[str, str]]
    vulnerabilities: list[Finding]
    license_conflicts: list[Finding]
    unmaintained: list[Finding]
    component_scores: dict[str, float]
    overall_score: float
    criticality: int
    version_conflicts: list[Finding] = field(default_factory=list)
    parse_warnings: list[str] = field(default_factory=list)
    score_breakdown: dict[str, float] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "project": self.project,
            "summary": {
                "components": len(self.components), "dependencies": len(self.edges),
                "vulnerabilities": len(self.vulnerabilities),
                "license_conflicts": len(self.license_conflicts),
                "unmaintained": len(self.unmaintained),
                "version_conflicts": len(self.version_conflicts),
                "risk_score": self.overall_score,
                "criticality": self.criticality,
            },
            "components": [asdict(c) | {"id": c.key} for c in self.components],
            "dependencies": [{"from": a, "to": b} for a, b in self.edges],
            "vulnerabilities": [f.to_dict() for f in self.vulnerabilities],
            "license_conflicts": [f.to_dict() for f in self.license_conflicts],
            "unmaintained": [f.to_dict() for f in self.unmaintained],
            "version_conflicts": [f.to_dict() for f in self.version_conflicts],
            "component_scores": self.component_scores,
            "score_breakdown": self.score_breakdown,
            "parse_warnings": self.parse_warnings,
        }
