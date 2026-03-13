from sentinelti.homoglyphs import has_m_rn_homoglyph_token
from sentinelti.heuristics import analyze_url

def test_has_m_rn_homoglyph_token_detects_known_spoof() -> None:
    assert has_m_rn_homoglyph_token(["login", "to", "rnicrosoft"])


def test_has_m_rn_homoglyph_token_ignores_legit_brand() -> None:
    assert not has_m_rn_homoglyph_token(["microsoft", "microsoft.com"])


def test_has_m_rn_homoglyph_token_handles_empty_input() -> None:
    assert not has_m_rn_homoglyph_token([])

def test_analyze_url_flags_rnicrosoft_homoglyph() -> None:
    url = "https://rnicrosoft.com/login"

    result = analyze_url(url)

    # Feature should be set
    assert result.features.get("has_m_rn_homoglyph") is True

    # Score should be > 0 and include a homoglyph-related reason
    assert result.score > 0.0
    assert any(
        "homoglyph" in r.lower() or "lookalike 'rn' vs 'm'" in r.lower()
        for r in result.reasons
    )

def test_analyze_url_does_not_flag_microsoft_dot_com() -> None:
    url = "https://microsoft.com/login"

    result = analyze_url(url)

    assert result.features.get("has_m_rn_homoglyph") is False
