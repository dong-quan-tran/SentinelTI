Finish threshold provenance wiring

Add a helper in the ML layer to compute “effective threshold + source” without needing to score a URL (_effective_threshold_with_source + get_effective_model_metadata).

Update /model-info wiring so it can reflect the effective threshold (metadata vs env vs default), not just the raw artifact value.

Add/tighten tests to ensure /model-info and scoring responses stay consistent, and that recommended_threshold is advisory-only.

Double‑check React UI components (if any) that surface threshold info to make sure they use the enriched metadata correctly.

Tidy ML predict and train tests

Add tests that enforce the contract around feature extraction (missing features give a clear RuntimeError).

Add tests that round‑trip: load artifact → compute effective metadata → ensure threshold and threshold_source behave correctly in env / no-env scenarios.

Add tests asserting invalid recommended_threshold values are ignored and surfaced as None while keeping a source string.

Loosen any remaining overly brittle tests that assert exact dict equality when new keys are added; focus them on required keys and invariants.

Mirror some of the predict-side coverage on the training side (if needed) so artifacts and consumers stay in sync.

Surface more model insight in the API/UI

Ensure /model-info returns richer metadata including recommended_threshold, recommended_threshold_source, metrics, and top features.

Add API tests that assert /model-info and /score-url pass through advisory threshold metadata while using the effective threshold for decisions.

Extend /model-info to expose a short “model summary” block explicitly (model type, dataset name, training date, top 3 features) if not already done.

In the React UI, add a “Model insight” panel using /model-info: current model type, effective threshold, and a couple of top features in plain language.

Convergence warning + training ergonomics

For Logistic Regression: either tune max_iter / solver to avoid chronic non‑convergence, or detect convergence warnings and encode them into metrics instead of logs.

Add a “training notes” field to metrics artifacts (e.g. “logreg did not fully converge; consider tuning”) and ensure it flows through /model-info.

Evaluation and threshold tuning follow‑up

Use the existing threshold-analysis script to pick a public “recommended” threshold for the default model.

Store that threshold inside artifact metadata (and make sure it appears as recommended_threshold in /model-info).

Introduce a clear separation between the effective classification threshold and an advisory recommended_threshold, so you can experiment without editing artifacts each time.

UX polish for error and metadata states

Ensure API error responses for scoring are structured with detail and error_type, and have tests for runtime error paths.

Ensure /model-info handles partial or minimal metadata gracefully and fills in sensible defaults, with tests to pin this.

In the UI, add friendly messages for:

no model loaded / metadata unavailable,

partially missing metrics (e.g., only ROC‑AUC known).

Document API error shapes and metadata defaults somewhere user‑visible (API docs or README).