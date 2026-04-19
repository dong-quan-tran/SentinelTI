from sentinelti.ml import service


def test_score_url_basic(monkeypatch):
    def fake_predict_url(url: str):
        assert url == "http://www.example.com/"
        return 0, 0.12

    monkeypatch.setattr(service, "predict_url", fake_predict_url)

    result = service.score_url("http://www.example.com/")
    assert "url" in result
    assert "label" in result
    assert "prob_malicious" in result
    assert isinstance(result["label"], int)
    assert isinstance(result["prob_malicious"], float)


def test_score_urls_list(monkeypatch):
    def fake_predict_url(url: str):
        # Could vary by URL if you want, but constant is fine for shape tests
        return 1, 0.91

    monkeypatch.setattr(service, "predict_url", fake_predict_url)

    urls = ["http://www.example.com/", "http://test.com/"]
    results = service.score_urls(urls)
    assert len(results) == len(urls)
    for r, u in zip(results, urls):
        assert r["url"] == u
        assert "label" in r
        assert "prob_malicious" in r