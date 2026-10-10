# Model acceptance policy ? proposed v1

## Scope

Improve benign apex and HTTP behavior without weakening threat detection.
Keep production artifacts unchanged until a candidate is accepted.

## Proposed project gates

These are project targets, not industry standards or safety guarantees.

For each adequately covered URL group, and overall:
- Final warning rate on benign URLs: at most 5%.
- Final malicious verdict rate on benign URLs: at most 1%.
- Warning detection on labeled malicious URLs: at least 95%.
- Malicious warning detection must not drop by more than two percentage
  points versus the baseline on the same evaluation set.

A warning means a final label of suspicious or malicious.
Report ML false-positive rate and ML malicious recall separately.
Report malicious-only detection separately from warning detection.

At least 100 distinct domains per class in each evaluated group are required
to mark that group's evidence as adequate under this project policy.
This minimum alone does not establish representativeness or certainty.
Report row counts, distinct-domain counts, rates, and uncertainty intervals.
If coverage is missing, mark insufficient evidence; do not mark passed.
Do not claim HTTP support is validated without adequate HTTP coverage.

## Data and splits

- Use original observed URLs; do not manufacture scheme or www variants.
- Keep provenance and label evidence.
- Reject label conflicts and audit normalized duplicates.
- Keep domain groups separate across training, validation, and final test.
- Keep repeatedly examined diagnostic URLs separate from final-test URLs.
- Select candidate settings using validation only.
- Do not tune on the final test or silently relax gates after seeing results.

## First experiment

Change only training-data coverage.
Keep features, XGBoost settings, ML threshold, and final scoring rules fixed.
Store candidate artifacts outside production paths.

## Promotion

Requires adequate evaluation evidence, passing acceptance checks,
passing code tests, artifact compatibility checks, and a rollback backup.
Passing unit tests alone does not authorize promotion.
