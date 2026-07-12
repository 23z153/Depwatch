from sbom_risk.analyzer import analyze


def test_missing_manifest_license_is_not_a_default_policy_violation(tmp_path):
    (tmp_path / "requirements.txt").write_text("demo==1.0.0\n")
    assert analyze(tmp_path).license_conflicts == []
    assert len(analyze(tmp_path, allowed_licenses={"MIT"}).license_conflicts) == 1
