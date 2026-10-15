# Reviewed new-domain supplement contract

## Status

This is experimental loading infrastructure, not approval of ROR or another
training source. It assigns no labels and performs no web/security verification.
Approval records are local researcher declarations, not signatures, independent
security certifications, or an authorization boundary against a malicious user.
Do not manufacture approvals to pass the validator.

The existing loader and default CLI mode remain `legacy-http-apex`: benign
HTTP/apex URLs within existing saved training domains, capped at 20 per domain.
Existing run directories and frozen reports are not rewritten.

## Opt-in mode

The new `reviewed-new-domains` mode requires an explicit supplement CSV,
its manifest, a saved baseline split, and `--variants full`. Missing files or
metadata stop the run. The first new-domain experiment is full-feature only.
No ROR input is approved or trained by installing this code or running its tests.

The production CLI protects both fixed local evaluations without an override:

- `docs/model_metrics/hannousse_external_eval_v1/urls.csv` and its manifest.
- `docs/model_metrics/external_http_path_challenge_v1/urls.csv` and its manifest.

Their CSV hashes must match their existing manifests, and the reviewed supplement
manifest must bind both CSV and manifest hashes in the declared order. These URL
CSVs are local-only; a clone missing them must restore the exact protected inputs
before a reviewed-new-domain run can proceed. Missing files are never skipped.

## Supplement CSV

Every row requires:

- `url`: original explicit HTTP(S) URL; only the versioned empty-path normalization
  is applied. URLs are not upgraded, stripped to roots, or given synthetic variants.
- `label`: explicitly `benign` under the approved experimental label policy.
- `label_basis`: identical to the manifest basis.
- `review_status`: explicitly `approved_for_experiment`; `corroborated`,
  `unreviewed`, and `unassigned` do not count as approvals.
- `review_evidence_url`: nonblank syntactically valid HTTP(S) evidence reference.
- `reviewer`: nonblank row-review attribution.
- `source_sha256`: identical to the manifest source hash.

Source hashes and evidence URLs are recorded declarations. The loader checks
consistency and syntax; it does not retrieve sources or verify evidence content.
Rows representing unresolved or excluded source reviews must not be exported.

## Manifest

Required top-level fields:

- `schema_version`: `reviewed-new-domains-v1`.
- `supplement_csv_sha256`: SHA-256 of the exact CSV bytes.
- `baseline_csv_sha256`, `baseline_split_sha256`, `manual_fixture_sha256`:
  exact fingerprints of the inputs to the proposed run.
- `preprocessing`: `http-empty-path-to-root-v1`.
- `label_basis`: `historical_source_label` or
  `registry_associated_assumed_benign`. Neither means current safety verification.
- `rows`, `domain_groups`: exact integer counts.
- `per_domain_cap`: integer `1`.
- `source`: object with nonblank `name`, HTTP(S) `url`, and lowercase 64-character
  hexadecimal `sha256`.
- `approval`: object with `status` equal to `approved_for_experiment`, a nonblank
  `reviewer`, a timezone-aware ISO `reviewed_at_utc`, a nonblank `label_policy`,
  and the Boolean `not_current_safety_verification` equal to `true`.
- `protected_evaluations`: ordered list of objects with `csv_path`, `csv_sha256`,
  `manifest_path`, and `manifest_sha256`, first Hannousse, then the path challenge.
  Paths must match the fixed repository-relative paths above.

## Rejection rules

The loader rejects missing approval data, incompatible fingerprints, invalid or
repeated normalized URLs, overlap with main-data URLs or any original main-data
domain, saved test domains, manual fixtures, diagnostic domains, and either
protected external evaluation. It permits only new domain groups, with one URL
per group across the whole supplement. IP literals, embedded credentials,
nondefault ports, and hosts without a recognized suffix are outside this trial.

Public-suffix grouping includes private suffix rules, as in the existing
experiments. It is not a guarantee that separate groups have independent ownership.

## Comparison invariants and outputs

The test partition fingerprint, baseline training-partition fingerprint,
threshold, and baseline-training class weight are preserved. The report records
actual post-supplement training-domain counts, baseline group counts, added group
counts, manifest hash, source, approval declaration, and protected-input hashes.

The new run's `split_groups.csv` contains baseline plus supplemental training
groups and the unchanged test assignments. It is not a drop-in replacement for
the original baseline split when loading only the original main CSV. The
`split_groups_path` fingerprint continues to identify that original input split.

Use a new output directory. No code here promotes a candidate or overwrites a
production artifact. Hyperparameter changes, threshold tuning, and additional
feature variants are outside this first controlled intervention.
