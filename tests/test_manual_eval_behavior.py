import pytest

from sentinelti.scoring import enrich_score


@pytest.mark.parametrize(
    "url",
    [
        "http://paypal.com.verify-update.info",
        "http://appleid.apple.com.security-check.net",
        "http://login-office365.com",
        "http://verify-account-netflix.com/login",
        "http://example.com@evil.com/login",
        "http://192.168.0.1/login",
        "http://example.xyz/login",
    ],
)
def test_obvious_phish_are_not_benign(url: str) -> None:
    """
    Obvious phishing-style URLs should never be classified as plain benign.
    They should be at least 'suspicious' or 'malicious'.
    """
    result = enrich_score(url)
    assert result["final_label"] in {"suspicious", "malicious"}


@pytest.mark.parametrize(
    "url",
    [
        "https://accounts.google.com/ServiceLogin",
        "https://login.microsoftonline.com",
        "https://www.netflix.com/login",
        "https://www.paypal.com/signin",
        "https://www.amazon.com/ap/signin",
    ],
)
def test_known_legit_brand_logins_stay_benign(url: str) -> None:
    """
    Known legitimate brand login URLs should normally stay benign/low-risk.
    This guards against over-aggressive brand impersonation heuristics.
    """
    result = enrich_score(url)
    assert result["final_label"] == "benign"
    assert result["risk"] == "low"
