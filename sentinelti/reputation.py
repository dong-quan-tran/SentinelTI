from __future__ import annotations

from typing import Optional, Iterable, Set

# You can either import this from scoring or define it here and import it there.
KNOWN_SUSPICIOUS_IPS: Set[str] = {
    "203.0.113.66",
    "198.51.100.200",
}


class IPReputationResult:
    def __init__(self, reputation: str = "unknown", source: Optional[str] = None) -> None:
        self.reputation = reputation  # e.g. 'unknown', 'suspicious', 'trusted'
        self.source = source          # e.g. 'local-list', 'external-feed-name'


def lookup_ip_reputation(
    ip: str,
    suspicious_ips: Optional[Iterable[str]] = None,
) -> IPReputationResult:
    """
    Placeholder for IP reputation lookup.

    Currently uses a small local suspicious-IP list when provided, otherwise
    returns 'unknown' for all IPs.
    """
    if not ip:
        return IPReputationResult(reputation="unknown", source=None)

    ips = set(suspicious_ips) if suspicious_ips is not None else KNOWN_SUSPICIOUS_IPS

    if ips and ip in ips:
        return IPReputationResult(reputation="suspicious", source="local-list")

    return IPReputationResult(reputation="unknown", source="local-list" if ips else None)

