import networkx as nx

import sbom_risk.analyzer as analyzer


def test_paths_stops_after_three_generator_results(monkeypatch):
    graph = nx.DiGraph([( "ROOT", "target")])
    consumed = []

    def paths(*_args, **_kwargs):
        for index in range(100):
            consumed.append(index)
            yield ["ROOT", f"branch-{index}", "target"]

    monkeypatch.setattr(analyzer.nx, "all_simple_paths", paths)
    result = analyzer._paths(graph, "target")
    assert len(result) == 3
    assert consumed == [0, 1, 2]
