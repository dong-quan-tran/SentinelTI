import dns.resolver
import pytest

from sentinelti.resolution import resolve_hostname_to_ip


def test_resolver_returns_ip_for_valid_hostname(monkeypatch):
    class Answer:
        address = "93.184.216.34"

    class FakeResolver:
        timeout = None

        def resolve(self, host, record_type, *, lifetime, search):
            assert host == "example.com"
            assert record_type == "A"
            assert lifetime == 0.5
            assert search is False
            return [Answer()]

    monkeypatch.setattr(dns.resolver, "Resolver", FakeResolver)

    assert resolve_hostname_to_ip("example.com") == "93.184.216.34"


def test_resolver_returns_ip_literal_without_dns(monkeypatch):
    def unexpected_resolver():
        raise AssertionError("IP literals should not be sent to DNS.")

    monkeypatch.setattr(dns.resolver, "Resolver", unexpected_resolver)

    assert resolve_hostname_to_ip("192.0.2.1") == "192.0.2.1"


def test_resolver_returns_none_on_dns_failure(monkeypatch):
    class FakeResolver:
        timeout = None

        def resolve(self, host, record_type, *, lifetime, search):
            raise dns.resolver.NXDOMAIN

    monkeypatch.setattr(dns.resolver, "Resolver", FakeResolver)

    assert resolve_hostname_to_ip("does-not-resolve.invalid") is None


def test_resolver_returns_none_when_resolver_cannot_be_initialized(monkeypatch):
    def fail_to_initialize():
        raise OSError("resolver configuration unavailable")

    monkeypatch.setattr(dns.resolver, "Resolver", fail_to_initialize)

    assert resolve_hostname_to_ip("example.com") is None


def test_resolver_rejects_non_positive_timeout():
    with pytest.raises(ValueError, match="timeout must be greater than zero"):
        resolve_hostname_to_ip("example.com", timeout=0)
