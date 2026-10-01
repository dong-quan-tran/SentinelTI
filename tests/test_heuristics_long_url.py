from sentinelti.heuristics import analyze_url


def test_long_untrusted_url_does_not_crash():
    url = "https://example.com/" + "a" * 2001

    result = analyze_url(url)

    assert any("unusually long" in reason for reason in result.reasons)


def test_long_trusted_url_does_not_crash():
    url = "https://google.com/" + "a" * 2001

    result = analyze_url(url)

    assert not any("unusually long for a non-trusted" in reason for reason in result.reasons)
