import json
import sys

import numpy as np
import pandas as pd
import pytest

from sentinelti.ml import train_candidates as c


@pytest.fixture
def reviewed_fixture(tmp_path):
    suffixes = c.tldextract.TLDExtract(
        suffix_list_urls=(), include_psl_private_domains=True
    )
    main = pd.DataFrame([
        ("http://trainalpha.com/base", "benign"),
        ("https://trainalpha.com/other", "benign"),
        ("http://trainbeta.com/bad", "malicious"),
        ("http://testalpha.com/good", "benign"),
        ("https://testbeta.com/bad", "malicious"),
    ], columns=["url", "label"])
    main["normalized_url"] = main.url.map(c.normalize_candidate_url)
    main["group"] = main.normalized_url.map(lambda u: c.domain_group(u, suffixes))
    main["y"] = main.label.map({"benign": 0, "malicious": 1})
    main_path = tmp_path / "main.csv"
    main[["url", "label"]].to_csv(main_path, index=False)
    split_path = tmp_path / "split.csv"
    pd.DataFrame([
        ("trainalpha.com", "train"), ("trainbeta.com", "train"),
        ("testalpha.com", "test"), ("testbeta.com", "test"),
    ], columns=["group", "partition"]).to_csv(split_path, index=False)
    manual_path = tmp_path / "manual.csv"
    pd.DataFrame({"url": ["https://manualfixture.com/"]}).to_csv(manual_path, index=False)
    protected = []
    records = []
    for index in range(2):
        csv_path = tmp_path / f"external{index}.csv"
        manifest_path = tmp_path / f"external{index}.json"
        pd.DataFrame({"url": [f"https://external{index}.com/"]}).to_csv(csv_path, index=False)
        manifest_path.write_text(json.dumps({"evaluation_csv_sha256": c.file_sha256(csv_path)}), encoding="utf-8")
        protected.append((str(csv_path), str(manifest_path), "evaluation_csv_sha256"))
        records.append({
            "csv_path": str(csv_path), "csv_sha256": c.file_sha256(csv_path),
            "manifest_path": str(manifest_path), "manifest_sha256": c.file_sha256(manifest_path),
        })
    supplement_path = tmp_path / "reviewed.csv"
    supplement = pd.DataFrame({
        "url": ["http://alpha-new.com", "https://www.beta-new.com/path"],
        "label": "benign", "label_basis": "historical_source_label",
        "review_status": "approved_for_experiment",
        "review_evidence_url": "https://evidence.example/review",
        "reviewer": "fixture-reviewer", "source_sha256": "a" * 64,
    })
    supplement.to_csv(supplement_path, index=False)
    approval_path = tmp_path / "approval.json"
    approval = {
        "schema_version": "reviewed-new-domains-v1",
        "supplement_csv_sha256": c.file_sha256(supplement_path),
        "baseline_csv_sha256": c.file_sha256(main_path),
        "baseline_split_sha256": c.file_sha256(split_path),
        "manual_fixture_sha256": c.file_sha256(manual_path),
        "preprocessing": c.PREPROCESSING,
        "label_basis": "historical_source_label", "rows": 2,
        "domain_groups": 2, "per_domain_cap": 1,
        "source": {"name": "synthetic fixture", "url": "https://source.example/data", "sha256": "a" * 64},
        "approval": {
            "status": "approved_for_experiment", "reviewer": "fixture-reviewer",
            "reviewed_at_utc": "2026-10-15T00:00:00+00:00",
            "label_policy": "Synthetic historical-label fixture, not real source approval.",
            "not_current_safety_verification": True,
        },
        "protected_evaluations": records,
    }
    approval_path.write_text(json.dumps(approval), encoding="utf-8")
    return dict(main=main, main_path=main_path, split_path=split_path,
                manual_path=manual_path, supplement=supplement,
                supplement_path=supplement_path, approval=approval,
                approval_path=approval_path, suffixes=suffixes, protected=tuple(protected))


def save_approval(f):
    f["approval_path"].write_text(json.dumps(f["approval"]), encoding="utf-8")


def save_supplement(f):
    f["supplement"].to_csv(f["supplement_path"], index=False)
    f["approval"]["supplement_csv_sha256"] = c.file_sha256(f["supplement_path"])
    save_approval(f)


def load(f, **kwargs):
    return c.load_reviewed_supplement(
        f["supplement_path"], f["approval_path"], f["main"],
        {"trainalpha.com", "trainbeta.com"}, {"testalpha.com", "testbeta.com"},
        f["manual_path"], f["suffixes"],
        baseline_csv_sha256=c.file_sha256(f["main_path"]),
        baseline_split_sha256=c.file_sha256(f["split_path"]),
        protected_evaluations=kwargs.get("protected", f["protected"]),
    )


def test_reviewed_loader_accepts_new_roots_and_subdomain_paths(reviewed_fixture):
    f = reviewed_fixture
    before = c.partition_sha256(f["main"])
    result = load(f)
    assert result.normalized_url.tolist() == ["http://alpha-new.com/", "https://www.beta-new.com/path"]
    assert result.group.tolist() == ["alpha-new.com", "beta-new.com"]
    assert result.y.eq(0).all()
    assert c.partition_sha256(f["main"]) == before
    assert result.attrs["reviewed_provenance"]["current_safety_verified"] is False


def test_weak_label_basis_is_explicit_not_implicitly_inferred(reviewed_fixture):
    f = reviewed_fixture
    f["approval"]["label_basis"] = "registry_associated_assumed_benign"
    f["supplement"]["label_basis"] = "registry_associated_assumed_benign"
    save_supplement(f)
    assert load(f).attrs["reviewed_provenance"]["label_basis"] == "registry_associated_assumed_benign"


@pytest.mark.parametrize("case", [
    "schema", "approval_missing", "unapproved", "reviewer", "policy", "safety_claim",
    "timestamp", "naive_timestamp", "source", "source_hash", "source_url",
    "csv_hash", "baseline_hash", "split_hash", "manual_hash", "preprocessing",
    "basis", "rows", "boolean_rows", "groups", "cap", "protected_missing", "protected_hash",
])
def test_reviewed_loader_rejects_manifest_errors(reviewed_fixture, case):
    f = reviewed_fixture
    m = f["approval"]
    if case == "schema": m["schema_version"] = "unknown"
    elif case == "approval_missing": m.pop("approval")
    elif case == "unapproved": m["approval"]["status"] = "unreviewed"
    elif case == "reviewer": m["approval"]["reviewer"] = " "
    elif case == "policy": m["approval"]["label_policy"] = ""
    elif case == "safety_claim": m["approval"]["not_current_safety_verification"] = "true"
    elif case == "timestamp": m["approval"]["reviewed_at_utc"] = "bad"
    elif case == "naive_timestamp": m["approval"]["reviewed_at_utc"] = "2026-10-15"
    elif case == "source": m.pop("source")
    elif case == "source_hash": m["source"]["sha256"] = "bad"
    elif case == "source_url": m["source"]["url"] = "not-a-url"
    elif case == "csv_hash": m["supplement_csv_sha256"] = "0" * 64
    elif case == "baseline_hash": m["baseline_csv_sha256"] = "0" * 64
    elif case == "split_hash": m["baseline_split_sha256"] = "0" * 64
    elif case == "manual_hash": m["manual_fixture_sha256"] = "0" * 64
    elif case == "preprocessing": m["preprocessing"] = "other"
    elif case == "basis": m["label_basis"] = "unassigned"
    elif case == "rows": m["rows"] = 999
    elif case == "boolean_rows": m["rows"] = True
    elif case == "groups": m["domain_groups"] = 999
    elif case == "cap": m["per_domain_cap"] = 20
    elif case == "protected_missing": m["protected_evaluations"] = []
    elif case == "protected_hash": m["protected_evaluations"][0]["csv_sha256"] = "0" * 64
    save_approval(f)
    with pytest.raises(ValueError): load(f)


@pytest.mark.parametrize("case", [
    "unassigned", "malicious", "basis", "corroborated_only", "reviewer", "evidence",
    "evidence_url", "source_hash", "invalid_url", "duplicates", "main_url", "train_domain",
    "test_domain", "manual_domain", "external0", "external1", "diagnostic",
    "ip", "credentials", "port", "internal_host", "domain_cap", "missing_column",
])
def test_reviewed_loader_rejects_row_and_leakage_errors(reviewed_fixture, case):
    f = reviewed_fixture
    d = f["supplement"]
    updates = {
        "unassigned": ("label", "unassigned"), "malicious": ("label", "malicious"),
        "basis": ("label_basis", "unassigned"),
        "corroborated_only": ("review_status", "corroborated"),
        "reviewer": ("reviewer", " "), "evidence": ("review_evidence_url", ""),
        "evidence_url": ("review_evidence_url", "not-a-url"),
        "source_hash": ("source_sha256", "b" * 64), "invalid_url": ("url", "no-scheme.com"),
        "main_url": ("url", "http://trainalpha.com/base"),
        "train_domain": ("url", "https://login.trainalpha.com/new"),
        "test_domain": ("url", "https://login.testalpha.com/new"),
        "manual_domain": ("url", "https://login.manualfixture.com/new"),
        "external0": ("url", "https://login.external0.com/new"),
        "external1": ("url", "https://login.external1.com/new"),
        "diagnostic": ("url", "https://www.example.com/new"),
        "ip": ("url", "http://192.0.2.1/"),
        "credentials": ("url", "http://user:pass@alpha-new.com/"),
        "port": ("url", "http://alpha-new.com:8409/"),
        "internal_host": ("url", "http://localhost/"),
    }
    if case in updates:
        column, value = updates[case]
        d.loc[0, column] = value
    elif case == "duplicates": d.loc[1, "url"] = "http://alpha-new.com/"
    elif case == "domain_cap": d.loc[1, "url"] = "https://www.alpha-new.com/other"
    elif case == "missing_column": f["supplement"] = d.drop(columns=["review_status"])
    save_supplement(f)
    with pytest.raises(ValueError): load(f)


def test_missing_protected_file_fails_closed(reviewed_fixture):
    f = reviewed_fixture
    from pathlib import Path
    Path(f["protected"][0][0]).unlink()
    with pytest.raises(FileNotFoundError): load(f)


def test_no_protected_evaluations_rejected(reviewed_fixture):
    with pytest.raises(ValueError, match="Protected external"):
        load(reviewed_fixture, protected=())


def test_protected_csv_tampering_rejected(reviewed_fixture):
    f = reviewed_fixture
    from pathlib import Path
    Path(f["protected"][0][0]).write_text("url\nhttps://other.com/\n", encoding="utf-8")
    with pytest.raises(ValueError, match="Protected evaluation CSV hash"):
        load(f)


@pytest.mark.parametrize("extra", [
    ["--supplemental-mode", "reviewed-new-domains"],
    ["--supplemental-manifest", "unused.json"],
    ["--supplemental-mode", "reviewed-new-domains", "--supplemental-csv", "unused.csv",
     "--supplemental-manifest", "unused.json", "--split-groups", "unused.csv"],
])
def test_new_mode_cli_fails_before_reading_unapproved_inputs(tmp_path, monkeypatch, extra):
    output = tmp_path / "never-created"
    monkeypatch.setattr(sys, "argv", ["train_candidates", "--output-dir", str(output), *extra])
    with pytest.raises(SystemExit) as error: c.main()
    assert error.value.code == 2
    assert not output.exists()


def test_new_mode_preserves_baseline_test_and_class_weight(reviewed_fixture, tmp_path, monkeypatch):
    f = reviewed_fixture
    real_loader = c.load_reviewed_supplement
    models = []
    def loader(*args, **kwargs):
        kwargs["protected_evaluations"] = f["protected"]
        return real_loader(*args, **kwargs)
    def features(url):
        return {"url_len": float(len(url)), "is_http": float(url.startswith("http:")),
                "is_https": float(url.startswith("https:")), "bad": float("/bad" in url)}
    class FakeClassifier:
        def __init__(self, **kwargs): self.kwargs=kwargs; self.inputs=[]; models.append(self)
        def fit(self, X, y): self.fit_X=np.array(X); self.fit_y=np.array(y); return self
        def predict_proba(self, X):
            self.inputs.append(np.array(X)); p=np.where(np.asarray(X)[:, -1]>0, .9, .1)
            return np.column_stack([1-p,p])
    monkeypatch.setattr(c, "load_reviewed_supplement", loader)
    monkeypatch.setattr(c, "extract_features", features)
    monkeypatch.setattr(c, "XGBClassifier", FakeClassifier)
    monkeypatch.setattr(c.joblib, "dump", lambda artifact,path: path.write_bytes(b"fake-model"))
    def run(output, reviewed=False):
        args=["train_candidates", "--csv-path",str(f["main_path"]),"--output-dir",str(output),
              "--split-groups",str(f["split_path"]),"--variants","full",
              "--manual-eval-path",str(f["manual_path"])]
        if reviewed:
            args += ["--supplemental-mode","reviewed-new-domains","--supplemental-csv",str(f["supplement_path"]),
                     "--supplemental-manifest",str(f["approval_path"])]
        monkeypatch.setattr(sys,"argv",args);c.main()
        return json.loads((output/"full_metrics.json").read_text(encoding="utf-8"))
    baseline=run(tmp_path/"baseline")
    augmented=run(tmp_path/"augmented",True)
    assert len(models)==2
    assert models[0].kwargs==models[1].kwargs
    assert models[1].kwargs["scale_pos_weight"]==pytest.approx(2.)
    assert models[1].fit_y.tolist()==[0,0,1,0,0]
    np.testing.assert_array_equal(models[0].inputs[0],models[1].inputs[0])
    for key in ["baseline_train_partition_sha256","test_partition_sha256","csv_sha256","split_groups_sha256","threshold"]:
        assert baseline[key]==augmented[key]
    assert baseline["train_groups"]==2
    assert augmented["train_groups"]==4
    assert augmented["baseline_train_groups"]==2
    assert augmented["new_training_groups"]==2
    assert augmented["supplemental_domain_cap"]==1
    split=pd.read_csv(tmp_path/"augmented"/"split_groups.csv")
    assert set(split.loc[split.partition.eq("test"),"group"])=={"testalpha.com","testbeta.com"}
    assert set(split.loc[split.partition.eq("train"),"group"])=={"trainalpha.com","trainbeta.com","alpha-new.com","beta-new.com"}
    assert augmented["reviewed_supplement"]["manifest_sha256"]==c.file_sha256(f["approval_path"])


def test_unapproved_manifest_stops_before_output_or_model_creation(reviewed_fixture, tmp_path, monkeypatch):
    f = reviewed_fixture
    f["approval"]["approval"]["status"] = "unreviewed"
    save_approval(f)
    output = tmp_path / "must-not-exist"
    def forbidden_model(**kwargs):
        pytest.fail("Unapproved input must not construct a model.")
    monkeypatch.setattr(c, "XGBClassifier", forbidden_model)
    monkeypatch.setattr(sys, "argv", [
        "train_candidates", "--csv-path", str(f["main_path"]),
        "--output-dir", str(output), "--split-groups", str(f["split_path"]),
        "--variants", "full", "--manual-eval-path", str(f["manual_path"]),
        "--supplemental-mode", "reviewed-new-domains",
        "--supplemental-csv", str(f["supplement_path"]),
        "--supplemental-manifest", str(f["approval_path"]),
    ])
    with pytest.raises(ValueError, match="Explicit experiment approval"):
        c.main()
    assert not output.exists()
