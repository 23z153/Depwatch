from datetime import datetime, timedelta, timezone

from sbom_risk.analyzer import _single_license_risk, _version_cmp, _warn_if_osv_cache_stale


def test_lgpl_is_weak_copyleft_not_viral():
    severity, score, _ = _single_license_risk("LGPL-2.0", "proprietary-distributed", None)
    assert severity == "medium"
    assert score == 4.5


def test_version_comparison_handles_semver_prerelease_and_pep440():
    assert _version_cmp("1.0.0-rc.1", "1.0.0", "npm") < 0
    assert _version_cmp("1.0.0+build.2", "1.0.0+build.1", "npm") == 0
    assert _version_cmp("1.0.0.post1", "1.0.0", "pypi") > 0


def test_stale_osv_cache_warns(tmp_path, monkeypatch):
    import sbom_risk.analyzer as analyzer
    stale = (datetime.now(timezone.utc) - timedelta(days=8)).isoformat()
    monkeypatch.setattr(analyzer, "osv_cache_info", lambda _: {"synced_at": stale})
    warnings = []
    _warn_if_osv_cache_stale(tmp_path / "osv.sqlite3", warnings)
    assert "8 days old" in warnings[0]
