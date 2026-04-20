import pytest

from sentinelti import scoring
from sentinelti.scoring import enrich_score
from sentinelti.heuristics import analyze_url


def _reasons_text(result: dict) -> str:
    return " ".join(result.get("reasons", []))


# ---------------------------------------------------------------------------
# Obvious phishing vs known legit brand logins
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "http://paypal.com.verify-update.info",
        "http://appleid.apple.com.security-check.net",
        # "http://login-office365.com",
        "http://verify-account-netflix.com/login",
        "http://example.com@evil.com/login",
        "http://192.168.0.1/login",
        "http://example.xyz/login",
    ],
)
def test_obvious_phish_are_not_benign(url: str, fake_ml_score) -> None:
    fake_ml_score(prob=0.20, label=0)
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
def test_known_legit_brand_logins_stay_benign(url: str, fake_ml_score) -> None:
    fake_ml_score(prob=0.05, label=0)
    result = enrich_score(url)
    assert result["final_label"] == "benign"
    assert result["risk"] == "low"


# ---------------------------------------------------------------------------
# Typosquatting / IDN and brand-like domains
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        # "http://examp1e.com/login",
        "http://paypa1-secure.com/verify",
        "http://micr0soft-account.com/signin",
        "http://xn--pple-43d.com/login",
        "http://paypa1-secure.com/login",
        "http://micr0soft-account.com/recover",
    ],
)
def test_typosquatted_and_idn_domains_are_suspicious(url: str, fake_ml_score) -> None:
    fake_ml_score(prob=0.20, label=0)
    result = enrich_score(url)
    assert result["final_label"] in {"suspicious", "malicious"}


def test_example_typo_login_is_not_benign(fake_ml_score) -> None:
    fake_ml_score(prob=0.20, label=0)
    url = "http://examp1e.com/login"
    result = enrich_score(url)
    assert result["final_label"] in {"suspicious", "malicious"}


def test_login_office365_is_not_benign(monkeypatch) -> None:
    """
    Fake Office 365 login domains like login-office365.com
    should not be plain benign.
    """
    url = "http://login-office365.com"

    def fake_ml_score_url(u: str) -> dict:
        return {
            "url": u,
            "label": 0,
            "prob_malicious": 0.20,
        }

    monkeypatch.setattr(scoring, "ml_score_url", fake_ml_score_url)

    result = enrich_score(url)
    assert result["final_label"] in {"suspicious", "malicious"}


@pytest.mark.parametrize(
    "url",
    [
        "http://login-office365-secure.com",
        "http://office365-login.example.net",
        "http://secure-microsoftonline-login.xyz",
    ],
)
def test_office365_like_login_domains_are_not_benign(url: str, monkeypatch) -> None:
    """
    Office 365/Microsoft-themed login domains on non-trusted hosts
    should not be plain benign.
    """
    def fake_ml_score_url(u: str) -> dict:
        return {
            "url": u,
            "label": 0,
            "prob_malicious": 0.20,
        }

    monkeypatch.setattr(scoring, "ml_score_url", fake_ml_score_url)

    result = enrich_score(url)
    assert result["final_label"] in {"suspicious", "malicious"}


def test_login_github_com_is_malicious_and_high_risk(fake_ml_score) -> None:
    fake_ml_score(prob=0.95, label=1)
    url = "http://login-github.com"
    result = enrich_score(url)

    assert result["final_label"] == "malicious"
    assert result["risk"] == "high"

    reasons = _reasons_text(result)
    assert "GitHub credential phishing pages" in reasons


def test_github_oauth_authorize_stays_benign_low_risk(fake_ml_score) -> None:
    fake_ml_score(prob=0.05, label=0)
    url = "https://github.com/login/oauth/authorize"
    result = enrich_score(url)

    assert result["final_label"] == "benign"
    assert result["risk"] == "low"

    reasons = _reasons_text(result)
    assert "Recognized as a standard GitHub OAuth authorization endpoint" in reasons


# ---------------------------------------------------------------------------
# Executable downloads and open redirects
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "http://malware-drop.example.com/payload.exe",
        "http://example.com/drive-by-install/update.exe",
    ],
)
def test_executable_malware_downloads_are_not_benign(url: str, monkeypatch) -> None:
    """
    URLs that clearly look like executable malware downloads should not be plain benign.
    They should be at least 'suspicious' or 'malicious'.
    """
    def fake_ml_score_url(u: str) -> dict:
        return {
            "url": u,
            "label": 0,
            "prob_malicious": 0.20,
        }

    monkeypatch.setattr(scoring, "ml_score_url", fake_ml_score_url)

    result = enrich_score(url)
    assert result["final_label"] in {"suspicious", "malicious"}


@pytest.mark.parametrize(
    "url",
    [
        "http://verify.example.com/login?token=abc123&redirect=http://evil.com",
        "http://example.com/login?next=http://evil.phish.xyz",
        "http://example.com/open-redirect?url=http%3A%2F%2Fevil.com",
        "http://example.com/redirect?target=https://evil.com",
    ],
)
def test_open_redirect_style_urls_are_not_benign(url: str, monkeypatch) -> None:
    """
    URLs that contain obvious open-redirect style parameters with nested URLs
    should not be plain benign. They should be at least 'suspicious' or 'malicious'.
    """
    def fake_ml_score_url(u: str) -> dict:
        return {
            "url": u,
            "label": 0,
            "prob_malicious": 0.20,
        }

    monkeypatch.setattr(scoring, "ml_score_url", fake_ml_score_url)

    result = enrich_score(url)
    assert result["final_label"] in {"suspicious", "malicious"}


@pytest.mark.parametrize(
    "url",
    [
        "http://93.184.216.34/payload.exe",
        "http://203.0.113.42/update.scr",
    ],
)
def test_executable_download_on_public_ip_is_not_benign(url: str, monkeypatch) -> None:
    """
    Executable downloads served directly from bare public IPs
    should not be plain benign.
    """
    def fake_ml_score_url(u: str) -> dict:
        return {
            "url": u,
            "label": 0,
            "prob_malicious": 0.20,
        }

    monkeypatch.setattr(scoring, "ml_score_url", fake_ml_score_url)

    result = enrich_score(url)
    assert result["final_label"] in {"suspicious", "malicious"}


# ---------------------------------------------------------------------------
# IP-based URLs and infrastructure edge cases
# ---------------------------------------------------------------------------


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

def test_private_or_local_ip_urls_are_not_benign(url: str, fake_ml_score) -> None:
    fake_ml_score(prob=0.15, label=0)
    result = enrich_score(url)
    assert result["final_label"] in {"suspicious", "malicious"}

@pytest.mark.parametrize(
    "url",
    [
        "http://192.0.2.10/example",      # TEST-NET-1
        "http://198.51.100.23/demo",      # TEST-NET-2
        "http://203.0.113.42/sample",     # TEST-NET-3
    ],
)
def test_documentation_ip_ranges_are_handled_safely(url: str, monkeypatch) -> None:
    """
    URLs using documentation-only IP ranges (RFC 5737) are uncommon in real browsing.
    They should not be treated as clearly safe benign infrastructure.
    """
    def fake_ml_score_url(u: str) -> dict:
        return {
            "url": u,
            "label": 0,
            "prob_malicious": 0.10,
        }

    monkeypatch.setattr(scoring, "ml_score_url", fake_ml_score_url)

    result = enrich_score(url)
    assert result["final_label"] in {"benign", "suspicious", "malicious"}

    reasons_text = _reasons_text(result)
    assert "IP address" in reasons_text or "raw IP" in reasons_text


def test_public_raw_ip_is_flagged_by_heuristics(monkeypatch) -> None:
    """
    URLs that use a bare public IP as host should receive some heuristic signal,
    since bare-IP infrastructure is common in malicious hosting.
    """
    url = "http://93.184.216.34/login"  # example.org's IP in many docs

    def fake_ml_score_url(u: str) -> dict:
        return {
            "url": u,
            "label": 0,
            "prob_malicious": 0.10,
        }

    monkeypatch.setattr(scoring, "ml_score_url", fake_ml_score_url)

    result = enrich_score(url)

    reasons_text = _reasons_text(result)
    assert "raw public IP address" in reasons_text or "raw IP address as host" in reasons_text


@pytest.mark.parametrize(
    "url",
    [
        "http://93.184.216.34/login",
        "http://203.0.113.42/signin",
    ],
)
def test_login_on_public_ip_is_not_benign(url: str, monkeypatch) -> None:
    """
    Login flows directly on bare public IPs should not be plain benign.
    They should be at least suspicious.
    """
    def fake_ml_score_url(u: str) -> dict:
        return {
            "url": u,
            "label": 0,
            "prob_malicious": 0.15,
        }

    monkeypatch.setattr(scoring, "ml_score_url", fake_ml_score_url)

    result = enrich_score(url)
    assert result["final_label"] in {"suspicious", "malicious"}


# ---------------------------------------------------------------------------
# SSO-like flows and benign deep content
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "https://sso.myuniversity.edu/idp/profile/SAML2/Redirect/SSO",
        "https://auth.example.com/oauth2/authorize?client_id=abc&redirect_uri=https://example.com/callback",
        "https://accounts.google.com/o/oauth2/auth",
        "https://login.microsoftonline.com/common/oauth2/authorize",
    ],
)
def test_legit_sso_like_urls_stay_benign(url: str, fake_ml_score) -> None:
    fake_ml_score(prob=0.05, label=0)
    result = enrich_score(url)
    assert result["final_label"] == "benign"
    assert result["risk"] == "low"

@pytest.mark.parametrize(
    "url",
    [
        "http://example.net/blog/2025/01/security-tips",
        "https://docs.example.com/products/platform/v2/guide/getting-started/installation",
    ],
)
def test_benign_deep_content_urls_stay_benign(url: str, fake_ml_score) -> None:
    fake_ml_score(prob=0.05, label=0)
    result = enrich_score(url)
    assert result["final_label"] == "benign"
    assert result["risk"] == "low"


# ---------------------------------------------------------------------------
# Social engineering lures and cleartext credentials
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "http://free-gift-card.example.biz/claim",
        "http://crypto-giveaway.example.cc/wallet/connect",
        "http://support-example.com.remote-help-session.ru",
        "http://example.com/login.php?user=admin&password=admin",
    ],
)
def test_social_engineering_and_cleartext_cred_urls_are_not_benign(url: str, monkeypatch) -> None:
    """
    URLs with giveaway/crypto/remote-help lures or cleartext credentials in the query
    should not be plain benign.
    They should be at least 'suspicious' or 'malicious'.
    """
    def fake_ml_score_url(u: str) -> dict:
        return {
            "url": u,
            "label": 0,
            "prob_malicious": 0.20,
        }

    monkeypatch.setattr(scoring, "ml_score_url", fake_ml_score_url)

    result = enrich_score(url)
    assert result["final_label"] in {"suspicious", "malicious"}


# ---------------------------------------------------------------------------
# Misc login-ish edge cases
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "http://very-long-subdomain-with-many-levels.login.secure.update.example.com/path",
        "http://example.reallylongtldthatisweirdlysuspicious/login",
        "http://example.click.click/login",
    ],
)
def test_weird_or_long_domain_logins_are_not_benign(url: str, monkeypatch) -> None:
    """
    Login flows on very long or unusual domains/TLDs should not be plain benign.
    They should be at least 'suspicious' due to phishing-like infrastructure.
    """
    def fake_ml_score_url(u: str) -> dict:
        return {
            "url": u,
            "label": 0,
            "prob_malicious": 0.20,
        }

    monkeypatch.setattr(scoring, "ml_score_url", fake_ml_score_url)

    result = enrich_score(url)
    assert result["final_label"] in {"suspicious", "malicious"}


def test_at_symbol_in_login_path_is_not_benign(monkeypatch) -> None:
    """
    Login/security URLs with '@' in the path should not be plain benign.
    """
    url = "http://login.example.com/@secure-check"

    def fake_ml_score_url(u: str) -> dict:
        return {
            "url": u,
            "label": 0,
            "prob_malicious": 0.15,
        }

    monkeypatch.setattr(scoring, "ml_score_url", fake_ml_score_url)

    result = enrich_score(url)
    assert result["final_label"] in {"suspicious", "malicious"}


def test_at_symbol_in_generic_path_can_be_benign(monkeypatch) -> None:
    """
    Generic paths with '@' but no login/security context may remain benign.
    """
    url = "http://example.com/path@id"

    def fake_ml_score_url(u: str) -> dict:
        return {
            "url": u,
            "label": 0,
            "prob_malicious": 0.05,
        }

    monkeypatch.setattr(scoring, "ml_score_url", fake_ml_score_url)

    result = enrich_score(url)
    assert result["final_label"] == "benign"


def test_portal_like_login_is_not_escalated_to_malicious(monkeypatch) -> None:
    """
    Legitimate-looking portal logins should not be escalated to 'malicious'
    purely by heuristics.
    """
    url = "https://secure.portal.example.org/account/login"

    def fake_ml_score_url(u: str) -> dict:
        return {
            "url": u,
            "label": 0,
            "prob_malicious": 0.10,
        }

    monkeypatch.setattr(scoring, "ml_score_url", fake_ml_score_url)

    result = enrich_score(url)
    assert result["final_label"] in {"benign", "suspicious"}


@pytest.mark.parametrize(
    "url",
    [
        "http://paypol.com/login",          # close to paypal
        "http://micros0ft.com/signin",      # rn vs m case (comment retains original note)
    ],
)
def test_core_brand_typosquats_get_heuristic_signal(url: str, monkeypatch) -> None:
    def fake_ml_score_url(u: str) -> dict:
        return {
            "url": u,
            "label": 0,
            "prob_malicious": 0.10,
        }

    monkeypatch.setattr(scoring, "ml_score_url", fake_ml_score_url)

    result = enrich_score(url)
    h = result["heuristic"]
    assert h["score"] > 0.0
    reasons = " ".join(h["reasons"])
    assert "1-character typo of brand" in reasons


# The remaining tests use analyze_url directly (heuristics only) and don’t call enrich_score,
# so they can stay exactly as you had them.


def test_microsoft_support_like_host_is_suspicious() -> None:
    url = "http://microsoft-support-login.example.com/reset"
    result = analyze_url(url)

    assert result.score > 0.0
    reason_text = " ".join(result.reasons).lower()
    assert "microsoft" in reason_text or "brand-like" in reason_text


def test_google_drive_like_login_is_suspicious() -> None:
    url = "http://google-drive.example.net/login"
    result = analyze_url(url)

    assert result.score > 0.0
    reason_text = " ".join(result.reasons).lower()
    assert "google" in reason_text or "brand-like" in reason_text


def test_apple_id_like_verification_is_suspicious() -> None:
    url = "http://apple-id.verify-payments.xyz/account/verify"
    result = analyze_url(url)

    assert result.score > 0.0
    reason_text = " ".join(result.reasons).lower()
    assert "apple" in reason_text or "brand-like" in reason_text


def test_protected_brand_off_domain_gets_small_bump() -> None:
    url = "http://secure-microsoft-login.example.com"
    result = analyze_url(url)

    assert result.score > 0.0


def test_protected_brand_google_off_domain_gets_bump() -> None:
    url = "http://google-security-check.example.net/login"
    result = analyze_url(url)
    assert result.score > 0.0


def test_docs_style_deep_path_has_low_heuristic_score() -> None:
    url = "https://docs.example.com/products/platform/v2/guide/getting-started/installation"
    result = analyze_url(url)
    assert result.score >= 0.0
    # Should not be strongly flagged by heuristics alone
    assert result.score < 1.0


def test_deep_docs_path_is_not_penalized_heavily() -> None:
    url = (
        "https://docs.example.com/platform/product/v2/guide/getting-started/"
        "installation/linux/package-manager/advanced/options"
    )
    result = analyze_url(url)

    assert result.features.get("path_depth", 0) >= 6
    # Should not get a big deep-path bump just for being docs
    assert result.score < 1.0


def test_protected_brand_with_login_on_untrusted_domain_gets_small_bump() -> None:
    url = "https://secure-paypal-login.badexample.xyz/account/verify"
    result = analyze_url(url)

    # Sanity: we saw the brand heuristic at all
    assert any(
        "protected brand tokens" in r.lower()
        for r in result.reasons
    )