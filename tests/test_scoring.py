from sbom_risk.analyzer import _overall_score


def test_safe_dependencies_do_not_dilute_project_risk():
    score, _ = _overall_score({"critical": 90.0, **{f"safe-{i}": 0.0 for i in range(500)}}, {"vulnerabilities": 90.0}, 3)
    assert score > 50


def test_multiple_critical_packages_materially_increase_risk():
    one, _ = _overall_score({"a": 90.0}, {"vulnerabilities": 90.0}, 3)
    three, _ = _overall_score({"a": 90.0, "b": 90.0, "c": 90.0}, {"vulnerabilities": 270.0}, 3)
    assert three > one
    assert three > 75
