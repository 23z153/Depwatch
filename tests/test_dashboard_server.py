import sbom_risk.dashboard as dashboard


def test_dashboard_uses_next_port_when_preferred_port_is_busy(monkeypatch):
    calls = []
    sentinel = object()

    def fake_server(address, handler):
        calls.append(address[1])
        if len(calls) == 1:
            raise OSError(98, "Address already in use")
        return sentinel

    monkeypatch.setattr(dashboard, "ThreadingHTTPServer", fake_server)
    server, selected = dashboard._bind_dashboard_server(object, 8765)
    assert (server, selected) == (sentinel, 8766)
