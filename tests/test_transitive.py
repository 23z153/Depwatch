"""Tests for transitive dependency detection correctness.

Covers:
- Single indirect dependency (App → A → vuln_lib)
- Deep multi-hop chain (App → A → B → C → vuln_lib)
- Diamond: two paths to same vulnerable lib (compounded risk)
- True diamond conflict: two versions of same lib via shared ancestor
- Safe direct + vulnerable transitive ranking (score isolation)
- CycloneDX SBOM without purl → ecosystem falls back to "generic" not "library"
- CycloneDX SBOM with purl → ecosystem extracted correctly
- Transitive dep score exceeds its non-vulnerable parent
"""
import json
import pytest
from sbom_risk.analyzer import analyze


# ─────────────────────────── helpers ────────────────────────────────────────

def _npm_lock(packages: dict) -> str:
    return json.dumps({"lockfileVersion": 3, "packages": packages})


def _cdx(components: list, dependencies: list) -> str:
    return json.dumps({
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "components": components,
        "dependencies": dependencies,
    })


# ─────────────────────────── tests ──────────────────────────────────────────

def test_single_hop_transitive_vuln_detected(tmp_path):
    """A vulnerability in a 1-hop transitive dep must be reported."""
    (tmp_path / "package-lock.json").write_text(_npm_lock({
        "": {"dependencies": {"pkg-a": "1.0.0"}},
        "node_modules/pkg-a": {
            "name": "pkg-a", "version": "1.0.0",
            "dependencies": {"lodash": "4.17.20"},
        },
        "node_modules/lodash": {"name": "lodash", "version": "4.17.20", "license": "MIT"},
    }))
    result = analyze(tmp_path)

    lodash = next((c for c in result.components if c.name == "lodash"), None)
    assert lodash is not None, "lodash must be discovered as a component"
    assert lodash.direct is False, "lodash should be non-direct (transitive)"

    lodash_vulns = [v for v in result.vulnerabilities if "lodash" in v.component]
    assert lodash_vulns, "lodash@4.17.20 should have ≥1 vulnerability"

    top = max(lodash_vulns, key=lambda v: v.score)
    assert len(top.paths[0]) >= 3, "path must include ROOT → pkg-a → lodash"
    assert top.paths[0][0] == "ROOT"
    assert "pkg-a" in top.paths[0][1]
    assert "lodash" in top.paths[0][-1]


def test_deep_chain_vuln_detected_with_full_path(tmp_path):
    """A vulnerability 4 hops deep must be found with the complete path."""
    (tmp_path / "package-lock.json").write_text(_npm_lock({
        "": {"dependencies": {"layer-1": "1.0.0"}},
        "node_modules/layer-1": {"name": "layer-1", "version": "1.0.0", "dependencies": {"layer-2": "1.0.0"}},
        "node_modules/layer-2": {"name": "layer-2", "version": "1.0.0", "dependencies": {"layer-3": "1.0.0"}},
        "node_modules/layer-3": {"name": "layer-3", "version": "1.0.0", "dependencies": {"axios": "0.21.1"}},
        "node_modules/axios": {"name": "axios", "version": "0.21.1", "license": "MIT"},
    }))
    result = analyze(tmp_path)

    axios_vulns = [v for v in result.vulnerabilities if "axios" in v.component]
    assert axios_vulns, "axios@0.21.1 must have vulnerabilities even 4 hops deep"

    top = max(axios_vulns, key=lambda v: v.score)
    path = top.paths[0]
    assert path[0] == "ROOT"
    assert "layer-1" in path[1]
    assert "axios" in path[-1]
    assert len(path) == 5, f"Expected 5-node path, got {path}"

    # Intermediate layers should have 0 vuln score (they are not themselves vulnerable)
    layer_scores = {k: v for k, v in result.component_scores.items() if "layer" in k}
    for k, s in layer_scores.items():
        assert s == 0.0, f"{k} should have score 0 (not itself vulnerable), got {s}"


def test_diamond_paths_increase_risk_score(tmp_path):
    """When two paths lead to the same vulnerable lib, the risk score must be
    higher (path multiplier) than with a single path."""
    single_path = _npm_lock({
        "": {"dependencies": {"pkg-a": "1.0.0"}},
        "node_modules/pkg-a": {"name": "pkg-a", "version": "1.0.0", "dependencies": {"lodash": "4.17.20"}},
        "node_modules/lodash": {"name": "lodash", "version": "4.17.20", "license": "MIT"},
    })
    two_paths = _npm_lock({
        "": {"dependencies": {"pkg-a": "1.0.0", "pkg-b": "1.0.0"}},
        "node_modules/pkg-a": {"name": "pkg-a", "version": "1.0.0", "dependencies": {"lodash": "4.17.20"}},
        "node_modules/pkg-b": {"name": "pkg-b", "version": "1.0.0", "dependencies": {"lodash": "4.17.20"}},
        "node_modules/lodash": {"name": "lodash", "version": "4.17.20", "license": "MIT"},
    })

    tmp_single = tmp_path / "single"
    tmp_single.mkdir()
    (tmp_single / "package-lock.json").write_text(single_path)

    tmp_two = tmp_path / "two"
    tmp_two.mkdir()
    (tmp_two / "package-lock.json").write_text(two_paths)

    r_single = analyze(tmp_single)
    r_two = analyze(tmp_two)

    def top_lodash_score(r):
        vulns = [v for v in r.vulnerabilities if "lodash" in v.component]
        return max((v.score for v in vulns), default=0)

    score_single = top_lodash_score(r_single)
    score_two = top_lodash_score(r_two)

    assert score_two > score_single, (
        f"Two-path score ({score_two}) should exceed single-path score ({score_single})"
    )

    # Confirm two paths are actually reported
    top2 = max(
        [v for v in r_two.vulnerabilities if "lodash" in v.component],
        key=lambda v: v.score,
    )
    assert len(top2.paths) >= 2, "Must report ≥2 paths for the diamond"


def test_version_conflict_detected_in_diamond(tmp_path):
    """Two different versions of the same library from separate parents must
    produce a version-conflict finding."""
    (tmp_path / "sbom.cdx.json").write_text(_cdx(
        components=[
            {"bom-ref": "pkg-a", "name": "pkg-a", "version": "1.0.0",
             "type": "library", "purl": "pkg:npm/pkg-a@1.0.0"},
            {"bom-ref": "pkg-b", "name": "pkg-b", "version": "1.0.0",
             "type": "library", "purl": "pkg:npm/pkg-b@1.0.0"},
            {"bom-ref": "lodash-415", "name": "lodash", "version": "4.17.15",
             "type": "library", "purl": "pkg:npm/lodash@4.17.15"},
            {"bom-ref": "lodash-420", "name": "lodash", "version": "4.17.20",
             "type": "library", "purl": "pkg:npm/lodash@4.17.20"},
        ],
        dependencies=[
            {"ref": "ROOT", "dependsOn": ["pkg-a", "pkg-b"]},
            {"ref": "pkg-a", "dependsOn": ["lodash-415"]},
            {"ref": "pkg-b", "dependsOn": ["lodash-420"]},
        ],
    ))
    result = analyze(tmp_path)

    conflicts = result.version_conflicts
    assert conflicts, "Must detect a version conflict for lodash"
    conflict_ids = {c.finding_id for c in conflicts}
    assert "VERSION-CONFLICT" in conflict_ids or "DIAMOND-DEPENDENCY" in conflict_ids


def test_safe_direct_sibling_does_not_inflate_transitive_vuln_score(tmp_path):
    """A clean direct dependency must score 0. Only the vulnerable transitive
    dep should carry a non-zero score."""
    (tmp_path / "package-lock.json").write_text(_npm_lock({
        "": {"dependencies": {"express": "4.21.0", "pkg-a": "1.0.0"}},
        "node_modules/express": {"name": "express", "version": "4.21.0", "license": "MIT"},
        "node_modules/pkg-a": {
            "name": "pkg-a", "version": "1.0.0",
            "dependencies": {"lodash": "4.17.20"},
        },
        "node_modules/lodash": {"name": "lodash", "version": "4.17.20", "license": "MIT"},
    }))
    result = analyze(tmp_path)

    express_score = result.component_scores.get("npm:express@4.21.0", 0)
    pkg_a_score = result.component_scores.get("npm:pkg-a@1.0.0", 0)
    lodash_score = result.component_scores.get("npm:lodash@4.17.20", 0)

    assert express_score == 0.0, f"Safe express should score 0, got {express_score}"
    assert pkg_a_score == 0.0, f"pkg-a (not vulnerable itself) should score 0, got {pkg_a_score}"
    assert lodash_score > 0, f"Vulnerable lodash should have a non-zero score, got {lodash_score}"
    assert lodash_score > express_score
    assert lodash_score > pkg_a_score


def test_cyclonedx_without_purl_uses_generic_ecosystem(tmp_path):
    """CycloneDX components without a purl should use 'generic', not the
    CycloneDX component type ('library', 'framework', etc.)."""
    (tmp_path / "sbom.cdx.json").write_text(_cdx(
        components=[
            # No purl — type is 'library' which is a CDX type, NOT an ecosystem
            {"bom-ref": "comp-a", "name": "some-lib", "version": "1.0.0", "type": "library"},
        ],
        dependencies=[
            {"ref": "ROOT", "dependsOn": ["comp-a"]},
        ],
    ))
    result = analyze(tmp_path)

    comps = {c.name: c for c in result.components}
    assert "some-lib" in comps
    assert comps["some-lib"].ecosystem == "generic", (
        f"Expected 'generic' ecosystem, got '{comps['some-lib'].ecosystem}'"
    )


def test_cyclonedx_with_purl_resolves_correct_ecosystem(tmp_path):
    """CycloneDX components with a purl must have the ecosystem taken from it."""
    (tmp_path / "sbom.cdx.json").write_text(_cdx(
        components=[
            {
                "bom-ref": "lodash-ref",
                "name": "lodash",
                "version": "4.17.20",
                "type": "library",
                "purl": "pkg:npm/lodash@4.17.20",
            },
        ],
        dependencies=[
            {"ref": "ROOT", "dependsOn": ["lodash-ref"]},
        ],
    ))
    result = analyze(tmp_path)

    comps = {c.name: c for c in result.components}
    assert "lodash" in comps
    assert comps["lodash"].ecosystem == "npm", (
        f"Expected 'npm' from purl, got '{comps['lodash'].ecosystem}'"
    )
    # With correct npm ecosystem, OSV should find vulnerabilities
    assert result.vulnerabilities, "lodash@4.17.20 via CycloneDX+purl must produce vuln findings"


def test_transitive_vuln_not_attributed_to_parent(tmp_path):
    """The vulnerability finding must be on the vulnerable component itself,
    not on its parent or any ancestor."""
    (tmp_path / "package-lock.json").write_text(_npm_lock({
        "": {"dependencies": {"middleware": "1.0.0"}},
        "node_modules/middleware": {
            "name": "middleware", "version": "1.0.0",
            "dependencies": {"axios": "0.21.1"},
        },
        "node_modules/axios": {"name": "axios", "version": "0.21.1", "license": "MIT"},
    }))
    result = analyze(tmp_path)

    # All vuln findings must be on axios, not middleware
    for v in result.vulnerabilities:
        assert "axios" in v.component, (
            f"Vuln {v.finding_id} is incorrectly attributed to {v.component} "
            f"instead of axios"
        )

    middleware_score = result.component_scores.get("npm:middleware@1.0.0", 0)
    axios_score = result.component_scores.get("npm:axios@0.21.1", 0)
    assert axios_score > middleware_score, (
        "axios (vulnerable) must score higher than middleware (not vulnerable)"
    )
