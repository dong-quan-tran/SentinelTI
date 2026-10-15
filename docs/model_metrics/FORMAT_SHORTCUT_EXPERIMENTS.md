# Format-shortcut experiments

## Scope and status

These are exploratory URL-classifier experiments, separate from deployed
production models. No candidate was promoted as part of this investigation.

The experiments examine associations between labels and URL formats,
including HTTP/HTTPS, apex/subdomain hosts, and root/path-bearing URLs.
Observed associations do not, by themselves, establish feature-level causality.

The candidate runs use a fixed decision threshold of 0.75. External evaluation
results were inspected during development and are not an untouched final
benchmark. Historical source labels are not current website-safety verdicts.

## Experiment directories

- `format_shortcut_experiment/`: initial grouped-split experiment and canonical
  saved domain assignments.
- `http_apex_supplement_baseline_v1/`: fixed-split baseline full and no-scheme
  candidates.
- `http_apex_supplement_augmented_v1/`: the corresponding candidates trained
  with the original HTTP/apex supplement.
- `scheme_invariant_baseline_v1/`: candidate-only scheme-invariant representation.
- `external_http_path_challenge_v1/`: historical benign HTTP/apex path challenge;
  its flag rates do not measure malicious recall or root-only performance.
- `hannousse_external_eval_v1/`: frozen external evaluation inputs and provenance.
- `hannousse_external_scores_v1/`: five-candidate external evaluation results.

## Findings and limits

Baseline training contained no benign HTTP URLs. The original supplement added
1,779 benign HTTP/apex URLs from 121 existing training domain groups, but no
plain root-only URLs. It therefore did not test benign HTTP/root supplementation.

The Hannousse evaluation retained 7,461 URLs across 5,734 domain groups after
exclusions. Supplemental training-domain overlap was also checked and was zero.

All five candidates showed substantial external format-associated errors.
Scheme-invariant features reduced overall benign false positives, but apex
errors remained high. These candidate results are not direct measurements of
the deployed production artifact.

ROR screening is a separate, unfinished training-source investigation.
Registry website association is not a verified benign-security label.
No ROR training supplement was approved in this investigation.

## Artifact policy

Keep source code, tests, reports, diagnostics, summaries, and provenance visible
for review. Evaluation URL redistribution and attribution must be checked before
those inputs are committed.

The exact generated files listed in the repository's `.gitignore` remain local:

- Five experimental candidate model artifacts.
- Three row-level prediction CSVs.
- Three redundant experiment split CSVs.

The canonical split is:
`docs/model_metrics/format_shortcut_experiment/split_groups.csv`.

Before adding the ignore rules, all three redundant split files were verified
byte-identical to the canonical split. Selected source/configuration files and
all seven experiment directories were archived to a separate local backup,
with per-file SHA-256 hashes and archive verification.

Ignoring a file does not delete or archive it. Keep the backup archive and its
checksum manifest together. A local Downloads backup is not a published artifact
registry or a guarantee against machine loss.

## Reproduction limitations

A fresh clone does not obtain the ignored candidate models or prediction CSVs.
External source archives and the original supplement are not supplied merely by
retaining their paths in reports.

Reproducing a run requires the correct source inputs, recorded split, feature
representation, dependencies, and locally generated or separately restored model
artifacts. Preserve original manifests and hashes; do not silently rewrite paths
or normalize the bytes of archived evidence.

No production model, main dataset, or runtime database is removed or replaced by
this artifact policy.
