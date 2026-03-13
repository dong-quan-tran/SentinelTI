from sentinelti.homoglyphs import has_m_rn_homoglyph_token


def test_has_m_rn_homoglyph_token_detects_known_spoof() -> None:
    assert has_m_rn_homoglyph_token(["login", "to", "rnicrosoft"])


def test_has_m_rn_homoglyph_token_ignores_legit_brand() -> None:
    assert not has_m_rn_homoglyph_token(["microsoft", "microsoft.com"])


def test_has_m_rn_homoglyph_token_handles_empty_input() -> None:
    assert not has_m_rn_homoglyph_token([])
