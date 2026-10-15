# Format-shortcut experiment results

## Scope

These results concern five experimental XGBoost candidates, not a fresh evaluation
of the deployed production model. The threshold remained 0.75. No candidate was
promoted. Both external collections were inspected during development; neither
is an untouched final benchmark. Historical source labels are not current-safety
verification.

## Fixed-split main-dataset evaluation

The baseline used 294,749 training URLs and 140,200 test URLs. The supplemented
runs added 1,779 URLs while retaining the recorded test partition and baseline
class weight. Scheme invariance used a separate candidate-only representation.
See the per-run metrics for exact fingerprints and feature order.

## Historical HTTP/apex path challenge

The challenge contains 1,350 historically benign URLs from 101 domain groups,
with a maximum of 20 URLs per group. It contains no malicious examples and no
plain roots. Reported values are historical-label flag rates, not malicious recall.

| Candidate | Flagged URLs | URL flag rate |
|---|---:|---:|
| Baseline full | 1,350 | 100.00% |
| Baseline no-scheme | 1,251 | 92.67% |
| Baseline scheme-invariant | 1,270 | 94.07% |
| Augmented full | 288 | 21.33% |
| Augmented no-scheme | 196 | 14.52% |

Supplemental and challenge domains were disjoint, but both collections came from
the same source. The large improvement here did not establish cross-source
improvement, malicious recall, or HTTP/root performance.

## Hannousse external evaluation

All 7,461 eligible URLs were retained across 5,734 domain groups: 3,637 source-
labeled benign and 3,824 source-labeled phishing. Recorded train/test, manual,
diagnostic, and supplemental training-domain overlap checks were zero.

| Candidate | Benign false-positive rate | Phishing recall | False positives | Misses |
|---|---:|---:|---:|---:|
| Baseline full | 61.01% | 88.78% | 2,219 | 429 |
| Baseline no-scheme | 29.89% | 85.72% | 1,087 | 546 |
| Augmented full | 59.99% | 89.12% | 2,182 | 416 |
| Augmented no-scheme | 28.68% | 85.49% | 1,043 | 555 |
| Baseline scheme-invariant | 24.86% | 85.77% | 904 | 544 |

The baseline full model flagged every HTTP URL. Both full-feature candidates
flagged every benign HTTP root. Scheme invariance improved overall false positives
but still flagged 96.07% of benign HTTP/apex roots and 97.16% of benign HTTPS/apex
roots. Domain-macro results and complete shape slices are retained in the reports.

The training-coverage audit found no benign HTTP URLs in baseline training. The
original supplement contained 1,755 path-bearing URLs and 24 roots with a query
or fragment, but no plain root-only URLs. All 121 supplement groups were existing
training groups. This explains the intervention's limited scope; it does not prove
feature-level causality or identify a complete remedy.

## Sources, attribution, and local-only data

### Hannousse and Yahiouche

Abdelhakim Hannousse and Salima Yahiouche, *Web page phishing detection*, Mendeley
Data, version 3, DOI: 10.17632/c2gw7fy2j4.3, published 25 June 2021. The publisher
lists CC BY 4.0: https://creativecommons.org/licenses/by/4.0/ .

Source: https://data.mendeley.com/datasets/c2gw7fy2j4/3

The run used the mirror and pinned commit recorded in the evaluation manifest.
Mirror integrity was checked; byte identity with the author-hosted file was not.
Changes included empty-path normalization, removal of 10 normalized duplicates,
domain exclusions, and mapping legitimate/phishing to benign/malicious. The
malicious class therefore represents phishing, not all malware categories.

### Historical path challenge

The exact GitHub source URL and checksum are preserved in the challenge manifest.
The source repository attributes its benign list to UNB's ISCX-URL2016 collection:
https://www.unb.ca/cic/datasets/url-2016.html .

Upstream citation: Mohammad Saiful Islam Mamun, Mohammad Ahmad Rathore,
Arash Habibi Lashkari, Natalia Stakhanova, and Ali A. Ghorbani, "Detecting Malicious
URLs Using Lexical Analysis," Network and System Security, pp. 467-482, 2016.

Redistribution permission for the exact mirrored list has not been established
in this review. The challenge URL list and its two domain-level result tables
remain local pending that check. As a conservative publication choice, the
Hannousse URL-level evaluation CSV also remains local; its source attribution
and hashes are retained here and in the manifest. This is not a finding that
CC BY 4.0 prohibits redistribution.

## Reproduction and evidence handling

Original result files and manifests are retained without edits. Some contain
historical absolute Windows paths. Those paths describe the run environment;
they are not portable instructions or available download locations.

The 26 committed report files have exact-path Git attributes disabling line-ending
conversion. Their staged bytes are checked against the reviewed SHA-256 values.
No repository-wide renormalization is performed.

Models, row-level predictions, duplicate split copies, and the four source-level
files noted above remain in their original local locations and verified backup.
Their absence from a clone limits reproduction. The saved standalone challenge
scorer covers the original candidates only; the supplied tooling does not include
a standalone command reproducing every augmented and Hannousse result.

See FORMAT_SHORTCUT_EXPERIMENTS.md for the experiment index and artifact policy.
