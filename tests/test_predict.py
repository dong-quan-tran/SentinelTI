from sentinelti.ml.predict import load_model, get_malicious_threshold

def test_get_malicious_threshold_defaults(monkeypatch):
    monkeypatch.delenv("SENTINELTI_MALICIOUS_THRESHOLD", raising=False)
    assert get_malicious_threshold() == 0.75


def test_get_malicious_threshold_from_env(monkeypatch):
    monkeypatch.setenv("SENTINELTI_MALICIOUS_THRESHOLD", "0.85")
    assert get_malicious_threshold() == 0.85


def test_get_malicious_threshold_rejects_invalid_value(monkeypatch):
    monkeypatch.setenv("SENTINELTI_MALICIOUS_THRESHOLD", "nope")
    assert get_malicious_threshold() == 0.75