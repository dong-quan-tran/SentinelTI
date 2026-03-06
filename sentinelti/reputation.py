from __future__ import annotations

from typing import Optional


class IPReputationResult:
    def __init__(self, reputation: str = "unknown", source: Optional[str] = None) -> None:
        self.reputation = reputation  # e.g. 'unknown', 'suspicious', 'trusted'
        self.source = source          # e.g. 'local-list', 'external-feed-name'


def lookup_ip_reputation(ip: str) -> IPReputationResult:
    """
    Placeholder for IP reputation lookup.

    Currently returns 'unknown' for all IPs. In future, this can be wired to
    external feeds or services without changing the scoring logic.
    """
    return IPReputationResult(reputation="unknown", source=None)
