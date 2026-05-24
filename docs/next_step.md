# SentinelTI Todo

## Current priorities

### Threshold provenance
- [x] Add ML-side effective threshold provenance helpers so effective threshold and `threshold_source` can be derived without scoring a URL.
- [x] Update `/model-info` wiring so it reflects the effective threshold source (`metadata`, `env`, or `default`) instead of only the raw artifact threshold.
- [x] Add and tighten tests to ensure `/model-info` and scoring responses stay consistent.
- [x] Ensure `recommended_threshold` stays advisory-only and is never used as the live decision threshold.
- [x] Double-check React UI threshold display so it uses enriched metadata correctly.

### Predict and train test hardening
- [ ] Add tests that enforce the feature extraction contract, especially that missing features raise a clear `RuntimeError`.
- [x] Add tests that cover threshold and `threshold_source` behavior in env and no-env scenarios.
- [x] Add tests asserting invalid `recommended_threshold` values are ignored and surfaced as `None` while preserving a source string.
- [x] Loosen brittle tests that relied on exact full-dict equality when new metadata keys are added.
- [ ] Mirror any remaining predict-side metadata coverage on the training side so artifacts and consumers stay in sync.

### Model insight in API and UI
- [x] Ensure `/model-info` returns richer metadata including `recommended_threshold`, `recommended_threshold_source`, metrics, top features, and training notes.
- [x] Add API tests that assert `/model-info` and `/score-url` pass through advisory threshold metadata while using the effective threshold for decisions.
- [ ] Add or refine an explicit short `model_summary` block in `/model-info` with model type, dataset name, training date, and top 3 features.
- [x] Add a React “Model insight” panel showing the current model, effective threshold, model quality signals, and top features in plain language.
- [x] Add friendly UI states for model metadata loading, unavailable metadata, and partially missing metrics.

### Training ergonomics
- [x] Detect Logistic Regression convergence warnings and store them as structured training notes instead of leaving them as log-only noise.
- [x] Add a `training_notes` field to metrics artifacts and flow it through `/model-info`.
- [ ] Decide whether Logistic Regression should also be retuned (`max_iter`, solver, scaling strategy) to reduce chronic non-convergence.

### Evaluation and threshold tuning
- [ ] Run the threshold-analysis flow against the default public model and pick a recommended threshold.
- [ ] Store that chosen threshold inside artifact metadata.
- [x] Keep a clear separation between effective classification threshold and advisory `recommended_threshold`.

### UX and API error handling
- [ ] Ensure API scoring error responses are consistently structured with `detail` and `error_type`, and add tests for runtime error paths.
- [x] Ensure `/model-info` handles partial or minimal metadata gracefully and fills sensible defaults.
- [x] In the UI, add friendly messages for missing model metadata.
- [x] In the UI, add friendly messages for partially missing metrics such as ROC-AUC or average precision.
- [ ] Document API error shapes and metadata defaults in a user-visible place such as the README or API docs.

## Structural improvements

### Backend structure
- [ ] Split scoring, model metadata, and explanation concerns more cleanly in the API layer.
- [ ] Add a dedicated service/helper layer for model metadata normalization so API handlers stay thin.
- [ ] Normalize response shaping in one place so `/model-info`, `/score-url`, and `/score-urls` stay consistent by construction.
- [ ] Review current tests and group them more clearly by API, predict, train, and UI contract behavior.

### Frontend structure
- [ ] Split frontend API access into clearer domains such as `modelApi` and `scanApi`.
- [ ] Add a `useModelInfo` hook for model metadata loading, status, and retry logic.
- [ ] Add response normalization on the frontend so components consume stable shapes.
- [ ] Continue moving component-specific styles into colocated CSS files where it improves maintainability.
- [ ] Remove remaining dead frontend files and stale starter code after confirming nothing imports them.

## AI integration roadmap

### Foundation
- [ ] Define where AI fits in SentinelTI: explanation enhancement, URL investigation assistance, analyst summaries, or triage suggestions.
- [ ] Keep deterministic scoring as the source of truth, with AI as optional augmentation rather than the decision engine.
- [ ] Introduce an AI abstraction layer so the core app does not depend directly on one provider or model.
- [ ] Define clear request and response contracts for AI-assisted explanation endpoints before implementation.

### First AI features
- [ ] Add an AI-assisted explanation mode that rewrites technical results into clearer user guidance while preserving the original deterministic scoring output.
- [ ] Add an analyst-facing summary feature that can summarize model reasons, heuristics, and metadata into a short investigation note.
- [ ] Add an optional enrichment workflow for suspicious URLs, gated behind configuration and clear labeling.

### Safety and operations
- [ ] Add feature flags or config toggles so AI features can be enabled without affecting core scoring.
- [ ] Add logging, timeout handling, and graceful fallback behavior when AI providers fail.
- [ ] Document prompt boundaries, redaction rules, and what data is allowed to leave the app.
- [ ] Add tests around fallback behavior so AI failures never break normal scoring.

## Cleanup
- [ ] Delete dead frontend files that were replaced during the UI refactor, such as `ModelInfoCard.jsx`, once confirmed unused.
- [ ] Remove any stale imports of old components or CSS files.
- [ ] Consider adding a dead-code check tool later for frontend cleanup.
