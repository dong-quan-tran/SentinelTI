AI foundation & provider strategy
Decide initial AI provider setup (stub vs local model vs external hosted API).

Define a strict schema for what deterministic fields may be sent to any external AI provider (e.g., explanation text, risk/label, but not raw logs or user identifiers).

Implement configuration/feature-flag plumbing so AI provider choice and credentials are controlled via env vars.

AI API implementation & testing
AI service module tests

Add unit tests for AI prompt/payload construction (given a deterministic explanation payload, assert the AI request body matches expectations).

Test handling of empty or malformed deterministic payloads (should raise AIExplanationError cleanly).

Test successful stub rewrite independent of HTTP: given a deterministic explanation, ensure a well-formed {"summary", "guidance"} object comes back.

Confirm invariants that AI output does not modify deterministic final_label, risk, threshold, or prob_malicious.

HTTP endpoint / integration

Ensure /ai-explain-score is using shared scoring/explanation helpers where appropriate to avoid duplication.

Add/verify OpenAPI request/response examples (already partially in place for ai_explain_score).

Add integration tests for rate-limit headers on the AI route (similar to /score-url).

Scoring & model architecture
Add LightGBM model

Train a LightGBM model on the existing URL feature set, using the same train/validation splits as XGBoost for fair comparison.

Export the trained model as an artifact and version it (url_classifier_lgbm.joblib or similar).

Extend the model-loading logic and metadata so model_type can be "lightgbm" and include its thresholds, metrics, feature_count, etc.

Update get_loaded_model_metadata and build_model_meta_response to handle LightGBM metadata and tests that assert the fields are populated correctly.

Run the existing evaluation pipeline to compare XGBoost vs LightGBM vs Logistic Regression on ROC AUC, average precision, and calibration; document results in model metadata or a short markdown note.

Decide which model is the default production artifact, but keep the others available for offline evaluation.

Thresholds & calibration

Run threshold analysis on the default model to choose a principled recommended_threshold (optimize phishing recall vs benign precision).

Store the chosen recommended threshold in the model artifact and surface it in model_meta (already supported structurally).

Evaluate probability calibration (e.g., reliability curves) and, if needed, add post-calibration (Platt, isotonic) before threshold tuning.

Heuristics & explanations
Audit the current heuristic features used in enrich_score() and document each heuristic’s meaning in plain language.

Ensure heuristic reasons:

Are stable and deterministic for the same URL.

Are non-empty when heuristics contribute to the verdict.

Are user-readable and map to understandable concepts (e.g., “Login keyword in path” instead of “feature_17 > 0.5”).

Add tests that cover borderline URLs (suspicious but not clearly malicious, short URLs, IP-based URLs, lookalike domains, noisy but benign).

Consider categorizing heuristic evidence (lexical / structural / reputation-style) and exposing that categorization in explanations.

Explore a separate “confidence” or “evidence strength” field distinct from the binary label.

API structure, docs, and quality
Keep refining separation of concerns:

scoring_service for deterministic scoring + explanations.

ai_score_service for AI-assisted rewrites.

Optionally introduce a dedicated AI error response model if current generic error structure becomes confusing.

Review status codes across all endpoints (401, 422, 429, 500, 503) for consistency and ensure docs match real behavior.

Confirm README and OpenAPI docs clearly describe:

Deterministic vs AI layers.

Error types (runtime_error, ai_disabled, ai_explanation_error).

Rate limiting behavior and headers.

Frontend AI & UX
AI availability and error UX

Implement friendly UI messages for ai_disabled (503) and AI provider failures (500), e.g., “AI summary is unavailable; your deterministic verdict is still valid.”

Make the AI summary visually secondary: collapsible section, smaller card, or “Show AI summary” toggle so deterministic explanation remains primary.

Component-level behavior

Ensure that starting a new scan clears any previous AI summary and AI errors (to avoid stale AI text).

Normalize AI responses in aiApi.js so components always see a stable shape ({ summary, guidance } with safe defaults).

Testing (when frontend tests are added)

Add tests for AI loading state (button disabled, “Generating…” text).

Add tests for AI error state rendering.

Add tests for AI success state, verifying both summary and guidance appear.

Frontend structure & polish
Make loading/empty states consistent across Verdict card, Detail panel, Model insight panel, and AI summary card.

Improve responsive/mobile layout (stacking order, spacing, readability for small screens).

Consider adding timestamps or request IDs for each scan to make debugging easier.

Remove dead frontend code (unused components, CSS).

Testing, tooling, CI
Backend tests

Keep organizing tests by concern (test_api.py, test_api_ai.py, test_predict.py, test_train.py, test_model_metadata_service.py, etc.).

Add service-level tests for scoring_service and ai_score_service (not just API layer tests).

Frontend tests

Set up a lightweight test runner (e.g., Vitest + React Testing Library) for hooks and API normalizer functions.

CI & quality

Add CI to run backend tests and build the frontend on every push/PR.

Add linting/formatting (e.g., ruff/flake8 + black for Python; ESLint + Prettier for JS).

Add basic coverage reporting to catch untested changes, especially around AI and scoring services.