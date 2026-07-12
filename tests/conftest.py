import pytest


@pytest.fixture(autouse=True)
def isolate_default_osv_cache(monkeypatch, tmp_path):
    """Tests using bundled fixtures must not depend on a developer's OSV cache."""
    import sbom_risk.analyzer as analyzer
    monkeypatch.setattr(analyzer, "DEFAULT_DB", tmp_path / "no-local-osv.sqlite3")
