# Detailed to-do list (updated after today's progress)

## What was completed today

- Added / refined explanation-oriented scoring output in the backend so API/UI consumers can use structured explanation fields instead of only raw score data.
- Updated `sentinelti/api.py` and `sentinelti/scoring.py` so explanation data is exposed through the API layer.
- Updated React frontend components (`sentinelti/frontend/src/components/VerdictCard.jsx` and `DetailPanel.jsx`) to support a simpler public-facing verdict view plus expandable technical details.
- Added / updated API tests to cover the newer response contract, including explanation-aware behavior and schema `1.2`.
- Fixed local pytest execution issues by addressing package import / test runner setup, then confirmed all tests are green.
- Improved frontend styling so the verdict/details panels match the dark theme better instead of using harsh white cards.
- Updated the hero copy styling so “Check whether a URL looks safe before you open it.” stays on one line on larger screens.

---

## 1. Sanity-check and inspect ML artifact metadata

Load each artifact in a Python REPL or a small script and inspect `artifact["metadata"]` to confirm:

- `model_type`, `trained_at`, `dataset_name`, `feature_version`, `threshold`, `class_counts`, `metrics`, and `training_params` are present and shaped as expected.
- Values like `class_counts` match your dataset splits reasonably.
- The latest JSON metrics files align with the embedded artifact metadata (no drift between the two sources).
- Decide whether any additional fields would be useful now, such as:
  - `train_size`
  - `test_size`
  - `notes`
  - `model_id` / `version_tag`

## 2. Add unit/integration tests for ML plumbing

Create or expand a focused file such as:

- `tests/test_ml_predict_and_service.py`

Cover:

### Artifact loading
- Loading a freshly trained artifact returns:
  - a model,
  - feature names,
  - normalized metadata with mandatory keys (`model_type`, `threshold`, `feature_version`, `metrics`, `artifact_path`)
- Older artifacts without nested metadata still load and normalize to sensible defaults

### Prediction API
- `predict_url_with_metadata()` returns:
  - `label`
  - `prob_malicious`
  - `threshold`
  - `model_meta`
- Types are correct
- Custom threshold from artifact metadata is honored
- Missing features from `extract_features()` raise the expected error
- Positive test with a mocked model confirms feature ordering is respected

### Service layer
- `score_url()` returns:
  - `url`
  - `label`
  - `prob_malicious`
  - `threshold`
  - `model_meta`
- `score_urls()` preserves ordering and maps cleanly over `score_url()`

## 3. Tighten feature extraction contracts

Review `features.py` and explicitly document feature names plus semantics in either:

- a module docstring, or
- a constant block

Add tests for `extract_features()` covering:

- normal URLs:
  - benign-looking
  - obviously malicious
  - short
  - long
- edge cases:
  - malformed schemes
  - weird ports
  - nested URLs
  - punycode
  - missing host

Assert that:

- extraction does not crash on those cases unless failure is intentionally expected,
- the returned feature set is complete,
- the feature keys match what trained artifacts expect.

Also decide how to evolve `feature_version`:

- current static label: `v2`
- future changes should treat feature version as part of artifact compatibility

## 4. Threshold analysis and selection

Thresholding is still fairly static and should become more principled.

Write an offline analysis script or notebook that:

- loads a trained model artifact,
- reconstructs or reuses the holdout split deterministically,
- computes score distributions for benign vs malicious samples,
- evaluates candidate thresholds (for example `0.50` to `0.99`),
- logs:
  - precision
  - recall
  - F1
  - false-positive rate

From that, choose:

- a default production threshold,
- possibly alternate thresholds later (`strict`, `sensitive`, etc.)

Then update training to:

- compute and store a chosen threshold from analysis,
- optionally record “best F1 threshold” and/or constraint-based thresholds,
- save that threshold into artifact metadata.

Then update `predict.py` to:

- prefer threshold from artifact metadata,
- use environment overrides only as an override mechanism.

## 5. Extend metadata for future API/UI

Think about what the API/UI should display without extra parsing.

Consider adding to metadata:

- `metrics_summary`
- `model_id`
- `version_tag`
- positive-class summary metrics only (`precision`, `recall`, `f1`)
- any lightweight debugging identifiers helpful in logs

Ensure `service.py` passes enough metadata through so the API and UI do not need to reopen artifacts or reconstruct context elsewhere.

Document the metadata schema in:

- `docs/model_artifacts.md`

## 6. Refine the API response schema

This area made progress today, but it should now be stabilized.

Decide on a clear long-term single-URL schema, likely including:

- `url`
- `label`
- `prob_malicious` or `risk_score`
- `threshold`
- `final_label`
- `risk`
- `model_id`
- `model_version`
- `trained_at`
- `feature_version`
- `model_family`
- `metrics_summary`
- `explanation`

For explanation output, standardize fields like:

- `summary`
- `why_flagged`
- `user_action`
- `technical_notes`

For batch responses:

- keep a top-level `{ "results": [...] }` shape

Also decide how API errors should be represented for:

- feature extraction failures
- model loading issues
- invalid URL input

## 7. Plan the explanation / LLM layer

You do not need to implement it immediately, but today’s explanation work means you now have a natural place to plug it in later.

Define the future explainer input payload, including:

- the URL
- model score and label
- threshold
- final verdict
- heuristic reasons
- key explanatory feature values
- model metadata

Decide:

- which explanation fields remain deterministic / rule-based,
- which fields could later be enhanced by Ollama or Gemini,
- whether an LLM should be optional for borderline or high-interest cases only.

A good next artifact here would be a small “reasoning payload” contract the API can emit and a future explainer can consume.

## 8. Continue frontend UX polish

This became an active workstream today and should continue.

Completed today:
- React verdict/details components were updated
- expandable technical details were introduced
- dark-theme styling was improved

Next frontend tasks:

### Request-state polish
- strengthen loading state UX
- improve API error presentation
- improve empty-state behavior before the first scan

### Result clarity
- make safe / warning / malicious states visually more distinct
- tune spacing, badges, and contrast further
- verify advanced details remain easy to scan

### Public vs specialist UX
- keep the default result simple for normal users
- preserve expandable technical details for advanced users
- consider explicit “simple” / “advanced” labeling if needed

### Metadata display
- add a small “about this model” footer or block:
  - model type
  - trained date
  - dataset
  - feature version

## 9. Add frontend/API integration confidence checks

Because the UI now depends on explanation-aware responses, add a small round of integration validation:

- verify frontend handles missing optional explanation fields gracefully
- verify batch and single-result API shapes do not drift
- ensure the UI does not break if metadata is partially missing
- consider one light frontend test later for verdict rendering behavior

## 10. Keep the roadmap order practical

Recommended order from here:

1. Sanity-check embedded model metadata
2. Add ML predict/service tests
3. Tighten feature extraction contracts
4. Stabilize and document API schema
5. Improve request/error/empty frontend states
6. Do threshold analysis
7. Define the future LLM reasoning payload