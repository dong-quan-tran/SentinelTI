import pytest

from sentinelti.scoring import enrich_score


@pytest.mark.parametrize(
    "url",
    [
        "http://paypal.com.verify-update.info",
        "http://appleid.apple.com.security-check.net",
        #"http://login-office365.com",
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

@pytest.mark.parametrize(
    "url",
    [
        #"http://examp1e.com/login",
        "http://paypa1-secure.com/verify",
        "http://micr0soft-account.com/signin",
        "http://xn--pple-43d.com/login",
        "http://paypa1-secure.com/login",
        "http://micr0soft-account.com/recover",
    ],
)
def test_typosquatted_and_idn_domains_are_suspicious(url: str) -> None:
    """
    Typosquatted and IDN/Punycode lookalike domains should not be plain benign.
    They should be at least 'suspicious' or 'malicious'.
    """
    result = enrich_score(url)
    assert result["final_label"] in {"suspicious", "malicious"}

@pytest.mark.parametrize(
    "url",
    [
        "http://malware-drop.example.com/payload.exe",
        "http://example.com/drive-by-install/update.exe",
    ],
)
def test_executable_malware_downloads_are_not_benign(url: str) -> None:
    """
    URLs that clearly look like executable malware downloads should not be plain benign.
    They should be at least 'suspicious' or 'malicious'.
    """
    result = enrich_score(url)
    assert result["final_label"] in {"suspicious", "malicious"}

@pytest.mark.parametrize(
    "url",
    [
        "http://verify.example.com/login?token=abc123&redirect=http://evil.com",
        "http://example.com/login?next=http://evil.phish.xyz",
        "http://example.com/open-redirect?url=http%3A%2F%2Fevil.com",
        #"http://example.com/redirect?target=https://evil.com",
    ],
)
def test_open_redirect_style_urls_are_not_benign(url: str) -> None:
    """
    URLs that contain obvious open-redirect style parameters with nested URLs
    should not be plain benign. They should be at least 'suspicious' or 'malicious'.
    """
    result = enrich_score(url)
    assert result["final_label"] in {"suspicious", "malicious"}

@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/admin",
        "http://192.168.1.10/login",
        "http://10.0.0.5/test",
        "http://172.20.10.5/portal",
        "http://localhost/dashboard",
    ],
)
def test_private_or_local_ip_urls_are_not_benign(url: str) -> None:
    """
    URLs pointing to private or local IPs should not be plain benign.
    They should be at least 'suspicious' due to potential internal exposure.
    """
    result = enrich_score(url)
    assert result["final_label"] in {"suspicious", "malicious"}
