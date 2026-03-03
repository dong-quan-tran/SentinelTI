from __future__ import annotations

from typing import Optional
import socket


def resolve_hostname_to_ip(host: str, timeout: float = 0.5) -> Optional[str]:
    """
    Best-effort resolver: returns a single IPv4 address for a hostname,
    or None if resolution fails.

    This is intentionally simple and conservative; upstream callers
    must handle None safely.
    """
    host = (host or "").strip()
    if not host:
        return None

    try:
        # Simple IPv4 resolution; you can extend this later if needed.
        return socket.gethostbyname(host)
    except OSError:
        # DNS failure, invalid name, etc.
        return None
