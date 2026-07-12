from sbom_risk.dashboard import _HTML


def test_dashboard_includes_search_and_remediation_filter_controls():
    assert "Quick component search" in _HTML
    assert "Filter remediation queue" in _HTML
    assert "Risk-highlighted" in _HTML
