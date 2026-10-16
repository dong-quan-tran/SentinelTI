from __future__ import annotations

import ipaddress
from typing import Optional

import dns.exception
import dns.resolver


def resolve_hostname_to_ip(host: str, timeout: float = 0.5) -> Optional[str]:
    """
    Return one IPv4 address within a bounded DNS lifetime, or None on failure.
    """
    host = (host or "").strip()
    if not host:
        return None

    try:
        return str(ipaddress.IPv4Address(host))
    except ipaddress.AddressValueError:
        pass

    if timeout <= 0:
        raise ValueError("DNS timeout must be greater than zero.")

    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        answers = resolver.resolve(host, "A", lifetime=timeout, search=False)
        for answer in answers:
            return str(ipaddress.IPv4Address(answer.address))
    except (dns.exception.DNSException, OSError, ValueError):
        return None
    return None
