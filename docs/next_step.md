# SentinelTI Todo

## Current priorities

### AI foundation
- [ ] Add a backend AI explanation service module (provider-agnostic) so AI logic lives outside API routes.
- [ ] Define a first AI contract for `/ai-explain-score` that returns deterministic explanation data separately from AI-generated text.
- [ ] Keep deterministic scoring as the source of truth and ensure AI output never changes `label`, `risk`, `threshold`, or `prob_malicious`.
- [ ] Introduce an `AIExplanationError` path and document how AI failures degrade gracefully.
- [ ] Add env-based configuration for AI enablement and provider credentials.
- [ ] Decide on initial provider strategy: stub only, local model, or hosted API.
- [ ] Add a small prompt builder that uses deterministic score data, reasons, heuristic info, and model metadata.
- [ ] Define what fields are safe to send to an external AI provider and what should stay local.

### AI API implementation
- [ ] Add `POST /ai-explain-score` with auth, rate limiting, and OpenAPI docs.
- [ ] Add a response model that clearly separates deterministic explanation from AI rewrite output.
- [ ] Add structured error responses for AI failures, ideally distinguishing scoring failures from AI-provider failures.
- [ ] Decide whether `/ai-explain-score` should call `enrich_score()` directly or reuse a shared response-building service.
- [ ] Add an optional feature flag so the endpoint can be disabled without affecting normal scoring routes.
- [ ] Add request/response examples to OpenAPI for the new AI endpoint.

### AI testing
- [ ] Add service-level tests for prompt building from deterministic score payloads.
- [ ] Add tests for the stubbed AI rewrite service success path.
- [ ] Add tests for empty or malformed score payloads raising `AIExplanationError`.
- [ ] Add API tests for `/ai-explain-score` happy path.
- [ ] Add API tests ensuring deterministic explanation fields are passed through unchanged.
- [ ] Add API tests for AI failure paths and graceful structured 500 responses.
- [ ] Add tests that prove AI output does not alter deterministic labels or thresholds.
- [ ] Consider snapshot-style tests for AI contract shape, but avoid brittle tests on wording.

### API improvements
- [ ] Split AI, scoring, and explanation concerns more cleanly in the API layer.
- [ ] Reuse a shared service/helper for building score payloads before API shaping.
- [ ] Add a dedicated error response model for AI-specific failures if generic scoring errors become too vague.
- [ ] Review status-code behavior across all endpoints for consistency (`401`, `422`, `429`, `500`).
- [ ] Add integration tests for rate-limit headers on scoring and AI routes.
- [ ] Add README documentation for AI-assisted explanation endpoints and caveats.
- [ ] Consider versioning or tagging AI endpoints separately in OpenAPI.

### Frontend AI and UX
- [ ] Add a frontend API module for AI endpoints, e.g. `aiApi.js`.
- [ ] Add a UI action to request an AI-assisted explanation after deterministic scoring succeeds.
- [ ] Keep the deterministic explanation visible as primary, with AI text visually labeled as assistant-generated.
- [ ] Add loading, disabled, and retry states for AI explanation requests.
- [ ] Add friendly fallback UI when AI is unavailable or disabled.
- [ ] Add UI copy explaining that AI summaries are advisory and do not change the underlying model verdict.
- [ ] Consider an expandable "AI summary" section rather than making AI the default explanation view.
- [ ] Add component tests for AI explanation UI states if frontend tests are introduced.

### ML follow-ups
- [x] Enforce the predict-side feature extraction contract so missing expected features raise a clear `RuntimeError`.
- [ ] Run threshold-analysis on the default public model and decide on a more principled `recommended_threshold`.
- [ ] Store the chosen recommended threshold in artifact metadata rather than relying on a default constant forever.
- [ ] Evaluate whether the current threshold is optimized for your actual tradeoff between phishing recall and benign precision.
- [ ] Consider probability calibration if score confidence appears poorly calibrated before threshold tuning.
- [ ] Compare current XGBoost and Logistic Regression artifacts on the same evaluation workflow.
- [ ] Decide whether to keep both models as first-class artifacts or designate one as the stable production default.

### Heuristics and scoring
- [ ] Audit current heuristic signals used in `enrich_score()` and document what each reason means in plain language.
- [ ] Add tests that ensure heuristic reasons are stable, non-empty, and user-readable.
- [ ] Review whether any heuristic weights are overly dominant compared with model probability.
- [ ] Add explicit coverage for borderline cases: suspicious-but-not-malicious, short URLs, IP-host URLs, lookalike domains, and noisy benign URLs.
- [ ] Consider separating heuristic evidence into categories such as lexical, structural, and reputation-style indicators.
- [ ] Improve explanation text so it maps reasons to concrete user actions more clearly.
- [ ] Consider a confidence or evidence-strength concept distinct from the binary label.

### Frontend structure and polish
- [x] Split frontend API access by domain (`modelApi`, `scanApi`).
- [x] Add frontend response normalization before rendering.
- [ ] Add `aiApi.js` and normalize AI explanation responses before components consume them.
- [ ] Delete any remaining dead frontend files like unused legacy CSS/components after final confirmation.
- [ ] Add an error boundary for major UI sections so failures don’t blank the whole app.
- [ ] Add component-level loading and empty-state consistency across verdict, detail, and model insight panels.
- [ ] Improve mobile layout and spacing for the results/detail view.
- [ ] Consider adding timestamps or request IDs in the UI for easier debugging.

### Quality and testing structure
- [ ] Split tests more clearly by concern: `test_api.py`, `test_api_ai.py`, `test_predict.py`, `test_train.py`, `test_model_metadata_service.py`.
- [ ] Add a lightweight frontend test setup for hooks and response normalizers.
- [ ] Add CI checks for backend tests and frontend build.
- [ ] Add lint/format enforcement if not already in place.
- [ ] Consider simple coverage reporting so the AI layer does not become undertested.