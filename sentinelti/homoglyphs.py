from __future__ import annotations

from typing import Iterable


BRAND_LIKE_HOMOGLYPH_PATTERNS: tuple[tuple[str, str], ...] = (
    ("microsoft", "rnicrosoft"),
    ("marriott", "rnarriott"),
    # add more as needed
)


def has_m_rn_homoglyph_token(tokens: Iterable[str]) -> bool:
    lowered = [t.lower() for t in tokens]
    for _, spoof in BRAND_LIKE_HOMOGLYPH_PATTERNS:
        for token in lowered:
            if spoof in token:
                return True
    return False

