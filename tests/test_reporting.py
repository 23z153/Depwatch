from sbom_risk.models import AnalysisResult, Component, Finding
from sbom_risk.reporting import terminal_report


def test_terminal_report_groups_component_advisories():
    component = Component("@angular/common", "21.2.1", "npm", direct=True)
    findings = [
        Finding(component.key, "GHSA-39pv", "high", "first", "22.0.0", score=7.5, cvss=7.5),
        Finding(component.key, "GHSA-48r7", "medium", "second", "22.0.1", score=4.5, cvss=4.5),
        Finding(component.key, "GHSA-39pv", "high", "duplicate", "22.0.0", score=7.5, cvss=7.5),
    ]
    result = AnalysisResult("project", [component], [("ROOT", component.key)], findings, [], [], {component.key: 75.0}, 60.0, 3)
    report = terminal_report(result, show_tree=False)
    assert "2 advisories" in report
    assert report.count("• GHSA-39pv") == 1
    assert "Recommended    upgrade to 22.0.1" in report
