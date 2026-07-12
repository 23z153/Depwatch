import json

from sbom_risk.analyzer import analyze
from sbom_risk.registry_cache import info, load, store


def test_registry_metadata_cache_round_trip(tmp_path):
    database = tmp_path / "registry.sqlite3"
    store(database, {"npm:example@1.0.0": {"deprecated": False}})
    assert load(database, ["npm:example@1.0.0"]) == {"npm:example@1.0.0": {"deprecated": False}}
    assert info(database)["cached_components"] == "1"


def test_scan_uses_cached_registry_deprecation_without_live_lookup(tmp_path):
    (tmp_path / "package-lock.json").write_text(json.dumps({"lockfileVersion": 3, "packages": {"": {"dependencies": {"old": "1.0.0"}}, "node_modules/old": {"name": "old", "version": "1.0.0"}}}))
    database = tmp_path / "registry.sqlite3"
    store(database, {"npm:old@1.0.0": {"deprecated": True, "deprecation_reason": "Use replacement."}})
    result = analyze(tmp_path, registry_db=str(database))
    assert any(f.finding_id == "MAINTENANCE-DEPRECATED" for f in result.unmaintained)
