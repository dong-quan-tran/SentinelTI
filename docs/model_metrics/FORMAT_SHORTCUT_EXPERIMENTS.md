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

## PhishBenign weak-label candidate

An isolated candidate was trained from the public PhishBenign URL collection
using source label `0` as **pseudo-benign** and source label `1` as
**pseudo-phishing**. The dataset documentation does not establish the labels'
origins, annotation method, or per-row observation dates. These are not
verified benignness or current-safety labels. Of 886,181 source rows, filtering
and protected-domain exclusions left 242,348 one-URL-per-domain pseudo-labeled
training rows. Most source URLs omit their scheme; the candidate's fixed outer
scheme feature representation does not mean these are observed HTTP examples.
The host-declared CC BY-SA 4.0 license also requires separate product-use
review.

At the unchanged 0.75 threshold, the candidate **regressed on the saved test**:
row-level benign FPR rose from 0.91% to 2.14%, and phishing recall fell from
91.72% to 89.40%. Domain-macro FPR rose from 1.09% to 3.49%, and domain-macro
recall fell from 91.86% to 87.16%. On root-only saved-test URLs, row-level FPR
rose from 1.00% to 6.60%, and phishing recall fell from 88.82% to 54.37%.
Paired domain-bootstrap intervals also indicate worse saved-test FPR and recall.

The previously examined Hannousse set improved in row-level FPR (24.86% to
18.70%) and recall (85.77% to 87.13%), but is not an untouched final benchmark
and was not used to select a threshold. On the benign-only historical HTTP/apex
path challenge, FPR fell from 94.07% to 69.78%; that result measures neither
phishing recall nor current website safety. These mixed external results do
not outweigh the saved-test regression.

### Saved-test root-only regression breakdown

The saved test was re-scored with the two already-saved candidates at the
unchanged 0.75 threshold; no model was retrained. Among 16,302 root-only URLs
from 14,351 domain groups, 1,778 rows moved from correct to incorrect and 189
moved from incorrect to correct. The weak-label candidate therefore had 1,589
fewer correct root-only predictions. In total, 1,526 domain groups had a net
increase in root-only errors, 142 improved, and 12,683 had no change in error
count. This is broad format-linked degradation, not just a handful of
multi-URL domains: 13,872 of the 14,351 groups contribute one root-only row.

| Root-only format | Rows / domains | Benign false positives, baseline → candidate | Phishing true positives, baseline → candidate | Correct → wrong / wrong → correct |
|---|---:|---:|---:|---:|
| HTTP apex | 1,445 / 1,441 | Not measurable (no benign rows) | 1,424 → 706 | 721 / 3 |
| HTTP subdomain | 686 / 389 | Not measurable (no benign rows) | 487 → 451 | 107 / 71 |
| HTTPS apex | 209 / 209 | 101 → 14 (87 fixed) | 98 → 39 | 59 / 87 |
| HTTPS subdomain | 13,962 / 12,422 | 38 → 907 (879 added, 10 fixed) | 72 → 78 | 891 / 28 |

The dominant paired failure is a large loss of phishing detections on HTTP
apex roots, alongside newly added benign false positives on HTTPS subdomain
roots. That pattern tracks URL format/host type more strongly than a small
number of domains. The weak source's root-only pseudo-label mix is also
strongly host-type-skewed: apex roots have 108,216 pseudo-benign versus 23,127
pseudo-phishing rows; subdomain roots have 6,637 versus 42,535. This is
consistent with a risky host-type/label association in the supplement, but
does not prove it caused the model changes. The source labels are weak, and
source domains overlapping the saved test were excluded, so test rows cannot
be joined to individual source pseudo-labels. HTTP root-only false-positive
behavior remains unmeasured because the saved test contains no benign HTTP
root-only examples.

Aggregated counts, including per-format domain error changes, are in
[`root_only_regression_by_format.csv`](./phishbenign_weak_label_experiment_v1/root_only_regression_by_format.csv).
The accompanying manifest records the evaluation inputs and report hash.

This candidate is **not suitable for deployment** and does not justify
replacing or retraining the production model. The original dataset, production
artifacts, fixed threshold, and frozen evaluation inputs remain unchanged.
Slice-level, paired, bootstrap, and provenance details are in
[`phishbenign_weak_label_experiment_v1/`](./phishbenign_weak_label_experiment_v1/):
[`summary.csv`](./phishbenign_weak_label_experiment_v1/summary.csv),
[`metrics_by_slice.csv`](./phishbenign_weak_label_experiment_v1/metrics_by_slice.csv),
[`paired_changes_by_slice.csv`](./phishbenign_weak_label_experiment_v1/paired_changes_by_slice.csv),
[`paired_domain_bootstrap.csv`](./phishbenign_weak_label_experiment_v1/paired_domain_bootstrap.csv),
and [`manifest.json`](./phishbenign_weak_label_experiment_v1/manifest.json).

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
