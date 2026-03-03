import socket

from sentinelti.resolution import resolve_hostname_to_ip


def test_resolver_returns_ip_for_valid_hostname(monkeypatch):
    def fake_gethostbyname(host: str) -> str:
        assert host == "example.com"
        return "93.184.216.34"

    monkeypatch.setattr(socket, "gethostbyname", fake_gethostbyname)

    ip = resolve_hostname_to_ip("example.com")
    assert ip == "93.184.216.34"


def test_resolver_returns_none_on_failure(monkeypatch):
    def fake_gethostbyname(host: str) -> str:
        raise OSError("DNS failure")

    monkeypatch.setattr(socket, "gethostbyname", fake_gethostbyname)

    ip = resolve_hostname_to_ip("does-not-resolve.invalid")
    assert ip is None
