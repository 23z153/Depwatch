import json
from datetime import date

from sbom_risk.analyzer import analyze
import sbom_risk.analyzer as analyzer_module
from sbom_risk.cli import main
from sbom_risk.discovery import discover_inputs
from sbom_risk.dashboard import cluster_risk_patterns, correlate, open_dashboard, remediation_playbook
from sbom_risk.sbom import ensure_sbom


def test_npm_vulnerability_path(tmp_path):
    (tmp_path / "package-lock.json").write_text(json.dumps({
        "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {"lodash": "4.17.20"}},
            "node_modules/lodash": {"name": "lodash", "version": "4.17.20", "license": "MIT"},
        },
    }))
    result = analyze(tmp_path)
    assert len(result.vulnerabilities) == 1
    assert result.vulnerabilities[0].finding_id == "CVE-2021-23337"
    assert result.vulnerabilities[0].paths[0][0] == "ROOT"


def test_generate_cyclonedx_sbom_then_analyze(tmp_path):
    (tmp_path / "requirements.txt").write_text("setuptools==65.0.0\n")
    sbom, generated = ensure_sbom(tmp_path, "cyclonedx")
    assert generated and sbom.name == "sbom.cdx.json"
    document = json.loads(sbom.read_text())
    assert document["bomFormat"] == "CycloneDX"
    result = analyze(sbom)
    assert result.vulnerabilities[0].finding_id == "CVE-2022-40897"


def test_generate_spdx_sbom_retains_root_dependency(tmp_path):
    (tmp_path / "requirements.txt").write_text("setuptools==65.0.0\n")
    sbom, generated = ensure_sbom(tmp_path, "spdx")
    assert generated and sbom.name == "sbom.spdx.json"
    result = analyze(sbom)
    assert ("ROOT", "generic:setuptools@65.0.0") in result.edges


def test_discovery_prefers_lockfiles(tmp_path):
    (tmp_path / "package.json").write_text('{"dependencies":{"axios":"^0.21.1"}}')
    (tmp_path / "package-lock.json").write_text('{"lockfileVersion": 3, "packages": {}}')
    assert [path.name for path in discover_inputs(tmp_path)] == ["package-lock.json"]


def test_npm_lock_resolves_nested_versions_by_location(tmp_path):
    (tmp_path / "package-lock.json").write_text(json.dumps({
        "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {"pkg-a": "1.0.0", "pkg-b": "1.0.0"}},
            "node_modules/pkg-a": {"version": "1.0.0", "dependencies": {"lodash": "4.17.20"}},
            "node_modules/pkg-a/node_modules/lodash": {"version": "4.17.20"},
            "node_modules/pkg-b": {"version": "1.0.0", "dependencies": {"lodash": "4.17.15"}},
            "node_modules/pkg-b/node_modules/lodash": {"version": "4.17.15"},
        },
    }))
    result = analyze(tmp_path)
    assert {c.key for c in result.components if c.name == "lodash"} == {"npm:lodash@4.17.20", "npm:lodash@4.17.15"}
    assert ("npm:pkg-a@1.0.0", "npm:lodash@4.17.20") in result.edges
    assert ("npm:pkg-b@1.0.0", "npm:lodash@4.17.15") in result.edges


def test_ci_threshold_returns_failure(tmp_path):
    (tmp_path / "package-lock.json").write_text(json.dumps({
        "lockfileVersion": 3, "packages": {"": {"dependencies": {"axios": "0.21.1"}}, "node_modules/axios": {"version": "0.21.1"}},
    }))
    assert main([str(tmp_path), "--fail-on-severity", "high", "--no-tree"]) == 1


def test_dashboard_playbook_correlation_and_clusters(tmp_path):
    for name in ("one", "two"):
        project = tmp_path / name
        project.mkdir()
        (project / "package-lock.json").write_text(json.dumps({
            "lockfileVersion": 3, "packages": {"": {"dependencies": {"axios": "0.21.1"}}, "node_modules/axios": {"version": "0.21.1"}},
        }))
    results = [analyze(tmp_path / name) for name in ("one", "two")]
    assert remediation_playbook(results[0])[0]["steps"]
    assert correlate(results)[0]["component"] == "npm:axios@0.21.1"
    assert cluster_risk_patterns(results)[0]["count"] == 2


def test_dashboard_browser_opening(monkeypatch):
    import webbrowser
    monkeypatch.setattr(webbrowser, "open", lambda url: url == "http://127.0.0.1:8765")
    assert open_dashboard("http://127.0.0.1:8765")

    def unavailable(url):
        raise webbrowser.Error("no browser")
    monkeypatch.setattr(webbrowser, "open", unavailable)
    assert not open_dashboard("http://127.0.0.1:8765")


def test_maintenance_and_license_policy(tmp_path):
    (tmp_path / "requirements.txt").write_text("demo==1.0.0\n")
    metadata = tmp_path / "metadata.json"
    metadata.write_text(json.dumps({"pypi:demo": {"last_release": "2020-01-01"}}))
    result = analyze(tmp_path, metadata_file=str(metadata), allowed_licenses={"MIT"})
    # Since we split "unmaintained" into stale and abandoned, let's verify finding exists
    assert len(result.unmaintained) == 1
    assert result.unmaintained[0].finding_id == "MAINTENANCE-ABANDONED"
    assert len(result.license_conflicts) == 1


def test_live_registry_deprecation_metadata(tmp_path, monkeypatch):
    (tmp_path / "package-lock.json").write_text(json.dumps({
        "lockfileVersion": 3, "packages": {"": {"dependencies": {"old-package": "1.0.0"}}, "node_modules/old-package": {"version": "1.0.0"}},
    }))
    monkeypatch.setattr(analyzer_module, "_query_registry_metadata", lambda components: (
        {"npm:old-package@1.0.0": {"deprecated": True, "deprecation_reason": "Use new-package instead."}}, None
    ))
    result = analyze(tmp_path, registry_metadata_online=True)
    finding = next(f for f in result.unmaintained if f.finding_id == "MAINTENANCE-DEPRECATED")
    assert "Use new-package instead." in finding.summary


def test_compounded_path_risk(tmp_path):
    # Lodash reachable via multiple paths
    (tmp_path / "package-lock.json").write_text(json.dumps({
        "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {"pkg-a": "1.0.0", "pkg-b": "1.0.0"}},
            "node_modules/pkg-a": {"name": "pkg-a", "version": "1.0.0", "dependencies": {"lodash": "4.17.20"}},
            "node_modules/pkg-b": {"name": "pkg-b", "version": "1.0.0", "dependencies": {"lodash": "4.17.20"}},
            "node_modules/lodash": {"name": "lodash", "version": "4.17.20", "license": "MIT"},
        },
    }))
    result = analyze(tmp_path)
    assert len(result.vulnerabilities) == 1
    vuln = result.vulnerabilities[0]
    assert len(vuln.paths) > 1
    # Check that the raw CVSS is correct
    assert vuln.cvss == 7.5
    # The graph now retains the two real parent paths (without a false direct
    # ROOT edge from npm hoisting): 7.5 * 1.1 = 8.25.
    assert vuln.score == 8.25


def test_version_conflict_and_diamond(tmp_path):
    # Diamond dependency using CycloneDX format: ROOT -> pkg-parent -> pkg-a/pkg-b -> lodash (diff versions)
    (tmp_path / "sbom.cdx.json").write_text(json.dumps({
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "components": [
            {
                "bom-ref": "pkg-parent",
                "type": "library",
                "name": "pkg-parent",
                "version": "1.0.0"
            },
            {
                "bom-ref": "pkg-a",
                "type": "library",
                "name": "pkg-a",
                "version": "1.0.0"
            },
            {
                "bom-ref": "pkg-b",
                "type": "library",
                "name": "pkg-b",
                "version": "1.0.0"
            },
            {
                "bom-ref": "lodash-1",
                "type": "library",
                "name": "lodash",
                "version": "4.17.20"
            },
            {
                "bom-ref": "lodash-2",
                "type": "library",
                "name": "lodash",
                "version": "4.17.15"
            }
        ],
        "dependencies": [
            {
                "ref": "ROOT",
                "dependsOn": ["pkg-parent"]
            },
            {
                "ref": "pkg-parent",
                "dependsOn": ["pkg-a", "pkg-b"]
            },
            {
                "ref": "pkg-a",
                "dependsOn": ["lodash-1"]
            },
            {
                "ref": "pkg-b",
                "dependsOn": ["lodash-2"]
            }
        ]
    }))
    result = analyze(tmp_path)
    # Check for version conflict/diamond findings
    assert len(result.version_conflicts) > 0
    fids = {f.finding_id for f in result.version_conflicts}
    assert "DIAMOND-DEPENDENCY" in fids


def test_exploitability_reachability(tmp_path):
    # Axios has CVE-2022-24999 (affected <0.21.2)
    (tmp_path / "package-lock.json").write_text(json.dumps({
        "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {"axios": "0.21.1"}},
            "node_modules/axios": {"name": "axios", "version": "0.21.1", "license": "MIT"},
        },
    }))
    
    # Scenario A: Code imports Axios
    (tmp_path / "app.js").write_text("const axios = require('axios');")
    result_active = analyze(tmp_path)
    assert len(result_active.vulnerabilities) == 1
    vuln_active = result_active.vulnerabilities[0]
    assert "[REACHABLE]" in vuln_active.summary
    
    # Scenario B: Code does NOT import Axios
    (tmp_path / "app.js").write_text("console.log('hello world');")
    result_inactive = analyze(tmp_path)
    assert len(result_inactive.vulnerabilities) == 1
    vuln_inactive = result_inactive.vulnerabilities[0]
    assert "[UNREACHABLE]" in vuln_inactive.summary
    assert vuln_inactive.score < vuln_active.score


def test_vex_overrides(tmp_path):
    # Setup Axios vulnerability
    (tmp_path / "package-lock.json").write_text(json.dumps({
        "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {"axios": "0.21.1"}},
            "node_modules/axios": {"name": "axios", "version": "0.21.1", "license": "MIT"},
        },
    }))
    # Setup VEX file
    vex_file = tmp_path / "vex.json"
    vex_file.write_text(json.dumps({
        "CVE-2022-24999": {
            "status": "not_affected",
            "justification": "vulnerable_code_not_present",
            "comment": "Axios is only used for server-side trusted requests."
        }
    }))
    result = analyze(tmp_path, vex_file=str(vex_file))
    assert len(result.vulnerabilities) == 1
    vuln = result.vulnerabilities[0]
    assert vuln.severity == "suppressed"
    assert vuln.score == 0.0
    assert "VEX-SUPPRESSED" in vuln.summary


def test_license_complexity_project_types(tmp_path):
    # GPL component
    (tmp_path / "package-lock.json").write_text(json.dumps({
        "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {"gpl-pkg": "1.0.0"}},
            "node_modules/gpl-pkg": {"name": "gpl-pkg", "version": "1.0.0", "license": "GPL-3.0-only"},
        },
    }))
    
    # proprietary-distributed -> GPL should be critical/high risk
    res_dist = analyze(tmp_path, project_type="proprietary-distributed")
    assert len(res_dist.license_conflicts) == 1
    assert res_dist.license_conflicts[0].severity == "critical"
    
    # proprietary-internal -> GPL risk is low (since no distribution)
    res_int = analyze(tmp_path, project_type="proprietary-internal")
    assert len(res_int.license_conflicts) == 1
    assert res_int.license_conflicts[0].severity == "low"

    # open-source -> GPL is fine/low risk
    res_os = analyze(tmp_path, project_type="open-source")
    assert len(res_os.license_conflicts) == 1
    assert res_os.license_conflicts[0].severity == "low"

    # Dual license check: OR
    (tmp_path / "package-lock.json").write_text(json.dumps({
        "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {"dual-pkg": "1.0.0"}},
            "node_modules/dual-pkg": {"name": "dual-pkg", "version": "1.0.0", "license": "GPL-3.0 OR MIT"},
        },
    }))
    res_dual_or = analyze(tmp_path, project_type="proprietary-distributed")
    # Choosing MIT resolved to low/zero risk finding (so no LICENSE-POLICY conflict should be recorded, or its score is 0.0, so no finding)
    assert len(res_dual_or.license_conflicts) == 0

    # Dual license check: AND
    (tmp_path / "package-lock.json").write_text(json.dumps({
        "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {"dual-pkg": "1.0.0"}},
            "node_modules/dual-pkg": {"name": "dual-pkg", "version": "1.0.0", "license": "GPL-3.0 AND MIT"},
        },
    }))
    res_dual_and = analyze(tmp_path, project_type="proprietary-distributed")
    assert len(res_dual_and.license_conflicts) == 1
    assert res_dual_and.license_conflicts[0].severity == "critical"


def test_maintenance_extended(tmp_path):
    (tmp_path / "requirements.txt").write_text("testpkg==1.0.0\n")
    metadata = tmp_path / "metadata.json"
    
    # 18-month release date (stale), single maintainer, no security policy, deprecated
    today = date.today()
    stale_date = today.replace(year=today.year - 1, month=today.month - 6 if today.month > 6 else 12)
    metadata.write_text(json.dumps({
        "pypi:testpkg": {
            "last_release": stale_date.isoformat(),
            "maintainers_count": 1,
            "has_security_policy": False,
            "deprecated": True
        }
    }))
    
    result = analyze(tmp_path, metadata_file=str(metadata))
    # Should flag stale, bus factor, security policy, and deprecation!
    fids = {f.finding_id for f in result.unmaintained}
    assert "MAINTENANCE-STALE" in fids
    assert "MAINTENANCE-BUS-FACTOR" in fids
    assert "MAINTENANCE-NO-SECURITY-POLICY" in fids
    assert "MAINTENANCE-DEPRECATED" in fids


def test_global_report_multi_project():
    from sbom_risk.models import Component, Finding, AnalysisResult
    from sbom_risk.reporting import global_report
    
    c1 = Component(name="axios", version="0.21.1", ecosystem="npm", license="MIT", direct=True)
    c2 = Component(name="lodash", version="4.17.20", ecosystem="npm", license="MIT", direct=True)
    
    f1 = Finding(c1.key, "CVE-2022-24999", "high", "Axios vulnerable to regex DoS", "0.21.2", score=7.5)
    f2 = Finding(c2.key, "CVE-2021-23337", "high", "Lodash template injection", "4.17.21", score=7.5)
    
    res1 = AnalysisResult(
        project="/home/abis/project-a",
        components=[c1],
        edges=[("ROOT", c1.key)],
        vulnerabilities=[f1],
        license_conflicts=[],
        unmaintained=[],
        component_scores={c1.key: 70.0},
        overall_score=70.0,
        criticality=3,
        version_conflicts=[]
    )
    
    res2 = AnalysisResult(
        project="/home/abis/project-b",
        components=[c1, c2],
        edges=[("ROOT", c1.key), ("ROOT", c2.key)],
        vulnerabilities=[f1, f2],
        license_conflicts=[],
        unmaintained=[],
        component_scores={c1.key: 70.0, c2.key: 75.0},
        overall_score=72.5,
        criticality=3,
        version_conflicts=[]
    )
    
    report = global_report([res1, res2])
    # Verify both projects are mentioned
    assert "project-a" in report
    assert "project-b" in report
    # Verify axios is listed with both usages
    assert "axios" in report
    assert "project-a, project-b" in report
    # Verify lodash is listed
    assert "lodash" in report


def test_online_osv_api_mocked(tmp_path, monkeypatch):
    # Setup lockfile
    (tmp_path / "package-lock.json").write_text(json.dumps({
        "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {"axios": "0.21.1", "qs": "6.5.2"}},
            "node_modules/axios": {"name": "axios", "version": "0.21.1", "license": "MIT"},
            "node_modules/qs": {"name": "qs", "version": "6.5.2", "license": "BSD-3-Clause"},
        },
    }))

    class MockResponse:
        def read(self):
            return json.dumps({
                "results": [
                    {
                        "vulns": [
                            {
                                "id": "GHSA-cph5-m8f7-6c5x",
                                "summary": "Axios vulnerable to regular expression DoS",
                                "aliases": ["CVE-2022-24999"],
                                "affected": [
                                    {
                                        "package": {"name": "axios", "ecosystem": "npm"},
                                        "ranges": [
                                            {
                                                "type": "SEMVER",
                                                "events": [{"introduced": "0"}, {"fixed": "0.21.2"}]
                                            }
                                        ]
                                    }
                                ],
                                "database_specific": {
                                    "cvss": {"score": 7.5}
                                }
                            }
                        ]
                    },
                    {
                        "vulns": [
                            {
                                "id": "GHSA-qdgf-abcd-1234",
                                "summary": "qs prototype pollution",
                                "aliases": [],
                                # No numeric CVSS — only database_specific.severity text label
                                "affected": [
                                    {
                                        "package": {"name": "qs", "ecosystem": "npm"},
                                        "ranges": [
                                            {
                                                "type": "SEMVER",
                                                "events": [{"introduced": "0"}, {"fixed": "6.5.3"}]
                                            }
                                        ]
                                    }
                                ],
                                "database_specific": {
                                    "severity": "HIGH"
                                }
                            }
                        ]
                    }
                ]
            }).encode("utf-8")
        def __enter__(self):
            return self
        def __exit__(self, exc_type, exc_val, exc_tb):
            pass

    def mock_urlopen(req, timeout=None):
        return MockResponse()

    import urllib.request
    monkeypatch.setattr(urllib.request, "urlopen", mock_urlopen)

    # Call analyze with online=True
    result = analyze(tmp_path, online=True)

    # --- axios finding ---
    axios_vulns = [v for v in result.vulnerabilities if v.finding_id == "CVE-2022-24999"]
    assert len(axios_vulns) == 1
    vuln = axios_vulns[0]
    assert vuln.fixed_version == "0.21.2"
    assert vuln.cvss == 7.5                          # numeric CVSS extracted
    assert vuln.severity == "high"
    assert vuln.affected_range == "<0.21.2"          # introduced=0 → no lower bound shown
    # Unknown reachability now receives the full baseline weight.
    assert vuln.score == 7.5

    # --- qs finding: text-only severity should map to CVSS midpoint via GHSA_SEV_MAP ---
    qs_vulns = [v for v in result.vulnerabilities if v.finding_id == "GHSA-qdgf-abcd-1234"]
    assert len(qs_vulns) == 1
    qs_vuln = qs_vulns[0]
    assert qs_vuln.severity == "high"
    assert qs_vuln.cvss == 7.5                        # GHSA_SEV_MAP["high"] = 7.5
    assert qs_vuln.fixed_version == "6.5.3"
    assert qs_vuln.affected_range == "<6.5.3"


def test_npm_dev_dependencies_and_lockfile_redirection(tmp_path):
    # Setup dummy project with package.json and package-lock.json
    (tmp_path / "package.json").write_text(json.dumps({
        "name": "test-project",
        "version": "1.0.0",
        "devDependencies": {
            "jest": "^27.0.0"
        }
    }))
    (tmp_path / "package-lock.json").write_text(json.dumps({
        "name": "test-project",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "packages": {
            "": {
                "name": "test-project",
                "version": "1.0.0",
                "devDependencies": {
                    "jest": "^27.0.0"
                }
            },
            "node_modules/jest": {
                "version": "27.0.0",
                "dependencies": {
                    "dep-of-jest": "^2.0.0"
                }
            },
            "node_modules/dep-of-jest": {
                "version": "2.0.0"
            }
        }
    }))

    # 1. Test lockfile redirection: discover_inputs on package.json should return package-lock.json
    inputs = discover_inputs(tmp_path / "package.json")
    assert len(inputs) == 1
    assert inputs[0].name == "package-lock.json"

    # 2. Test devDependencies are marked direct and have ROOT edges
    result = analyze(tmp_path)
    jest_comp = next((c for c in result.components if c.name == "jest"), None)
    assert jest_comp is not None
    assert jest_comp.direct is True
    assert ("ROOT", "npm:jest@27.0.0") in result.edges
    assert ("npm:jest@27.0.0", "npm:dep-of-jest@2.0.0") in result.edges

    # 3. Test ensure_sbom writes metadata.component and transitive dependency nodes
    sbom_path, generated = ensure_sbom(tmp_path / "package.json", "cyclonedx")
    assert generated
    sbom_data = json.loads(sbom_path.read_text())
    assert sbom_data["metadata"]["component"]["bom-ref"] == "ROOT"
    
    # Verify the dependencies section includes transitives
    dep_nodes = sbom_data["dependencies"]
    root_node = next((d for d in dep_nodes if d["ref"] == "ROOT"), None)
    assert root_node is not None
    assert "npm:jest@27.0.0" in root_node["dependsOn"]

    jest_node = next((d for d in dep_nodes if d["ref"] == "npm:jest@27.0.0"), None)
    assert jest_node is not None
    assert "npm:dep-of-jest@2.0.0" in jest_node["dependsOn"]


def test_missing_lockfile_warning(tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({
        "name": "test-project",
        "version": "1.0.0",
        "dependencies": {
            "express": "4.17.1"
        }
    }))
    result = analyze(tmp_path)
    assert any(
        "No package-lock.json or yarn.lock was found next to package.json" in w
        for w in result.parse_warnings
    )
    assert any(
        "Instruction: Run 'npm install --package-lock-only' or 'yarn install' in a trusted environment" in w
        for w in result.parse_warnings
    )


