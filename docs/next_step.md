Finish threshold provenance wiring

Add a small helper in the ML layer to compute “effective threshold + source” without needing to score a URL.

Update /model-info to use that helper so it always reflects the actual effective threshold (metadata vs env vs default), not just the raw artifact value.

Add or tighten tests to ensure /model-info and scoring responses stay consistent.

Tidy ML predict and train tests

Loosen overly brittle tests that assert on exact dict equality when new keys are added; focus them on required keys and invariants.

Add one more test that round-trips: load artifact → call predict → confirm model_meta.threshold and threshold_source match expectations for env / no-env scenarios.

Surface more model insight in the API/UI

Extend /model-info to expose a short “model summary” block (model type, dataset name, training date, top 3 features).

In the React UI, show a small “Model insight” panel using /model-info: current model type, threshold, and a couple of top features in plain language.

Convergence warning + training ergonomics

For Logistic Regression, either:

adjust max_iter and/or solver, or

detect the convergence warning and surface a clean note in metrics JSON rather than raw logs.

Add a short “training notes” field to metrics artifacts (e.g. “logreg did not fully converge; consider tuning”).

Evaluation and threshold tuning follow‑up

Use the existing threshold-analysis script to:

pick a public “recommended” threshold for the default model,

store that inside artifact metadata (and show it in /model-info).

Consider adding a “recommended_threshold” field separate from “operational_threshold” so you can experiment without editing artifacts each time.

UX polish for error and metadata states

Make sure API error responses for scoring and /model-info are consistent and documented (including error_type).

In the UI, add friendly messages for:

no model loaded / metadata unavailable,

partially missing metrics (e.g., only ROC-AUC known).