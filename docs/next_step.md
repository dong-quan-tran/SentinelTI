# SentinelTI Next Steps

## Completed today

### AI foundation & provider strategy
- Chose a provider strategy centered on a safe default `stub` provider plus a real local `ollama` provider.
- Implemented environment-driven provider configuration.
- Added provider selection plumbing with support for:
  - `SENTINELTI_AI_ENABLED`
  - `SENTINELTI_AI_PROVIDER`
  - `SENTINELTI_OLLAMA_ENDPOINT`
  - `SENTINELTI_OLLAMA_MODEL`
- Added fail-fast validation for malformed deterministic payloads and provider configuration.
- Added a provider abstraction so `ai_score_service` is decoupled from concrete AI implementation.
- Confirmed local Ollama availability and verified both `llama3.1:8b` and `deepseek-r1:1.5b` are installed locally.

### AI API implementation & testing
- Added and updated service-level tests for:
  - AI payload validation
  - prompt construction
  - stub provider behavior
  - provider selection
  - Ollama provider success and failure handling
- Updated `ai_score_service` tests to use provider stubs rather than the removed function-based rewrite hook.
- Updated `/ai-explain-score` API tests to match the provider-based architecture.
- Fixed test issues caused by outdated patch points and JSON-module shadowing in mocks.

## Next work items

### AI API implementation & testing
- Add unit tests that assert the exact Ollama request body matches expectations for prompt, model, schema, and low-temperature options.
- Confirm invariants that AI output does not modify deterministic `final_label`, `risk`, `threshold`, or `prob_malicious` when those fields are present.
- Ensure `/ai-explain-score` is using shared scoring/explanation helpers everywhere appropriate to avoid duplication.
- Add or verify OpenAPI request/response examples for the current Ollama-backed AI route.
- Add integration tests for rate-limit headers on the AI route, similar to `/score-url`.
- Add one real local smoke test workflow for Ollama-backed explanation generation during manual QA.

### Ollama model selection
- Add optional per-request model override support so callers can choose between `llama3.1:8b` and `deepseek-r1:1.5b` without changing environment variables.
- Validate requested model names against an allowlist or installed-model query flow.
- Consider adding a lightweight backend helper or endpoint to list installed Ollama models from `/api/tags`.
- Keep a configured default model in env vars and treat request-level model selection as optional.

### Scoring & model architecture
- Add a LightGBM model.
- Train a LightGBM model on the existing URL feature set using the same train/validation splits as XGBoost for fair comparison.
- Export the trained LightGBM model as an artifact and version it.
- Extend model-loading logic and metadata so `model_type` can be `lightgbm`.
- Update model metadata services and tests for LightGBM support.
- Run the evaluation pipeline to compare XGBoost vs LightGBM vs Logistic Regression on ROC AUC, average precision, and calibration.
- Decide which model remains the default production artifact while keeping alternatives for offline evaluation.

### Thresholds & calibration
- Run threshold analysis on the default model to choose a principled `recommended_threshold`.
- Store the chosen threshold in the model artifact and surface it in `model_meta`.
- Evaluate probability calibration and add post-calibration if needed before final threshold tuning.

### Heuristics & explanations
- Audit the current heuristic features used in `enrich_score()` and document each heuristic in plain language.
- Ensure heuristic reasons are:
  - stable and deterministic for the same URL,
  - non-empty when heuristics contribute to the verdict,
  - user-readable.
- Add tests for borderline URLs: suspicious-but-not-clearly-malicious, short URLs, IP-based URLs, lookalike domains, and noisy but benign URLs.
- Consider categorizing heuristic evidence (lexical / structural / reputation-style).
- Explore a separate confidence or evidence-strength field distinct from the binary label.

### API structure, docs, and quality
- Keep refining separation of concerns:
  - `scoring_service` for deterministic scoring + explanations
  - `ai_score_service` for AI-assisted rewrites
- Consider a dedicated AI error response model if the current generic error structure becomes confusing.
- Review status codes across endpoints for consistency (`401`, `422`, `429`, `500`, `503`).
- Update README and OpenAPI docs to clearly describe:
  - deterministic vs AI layers,
  - current AI provider behavior,
  - error types,
  - rate limiting behavior and headers.

### Frontend AI & UX
- Implement friendly UI messages for `ai_disabled` (`503`) and AI provider failures (`500`).
- Make the AI summary visually secondary so deterministic explanation remains primary.
- Ensure new scans clear previous AI summary and AI errors.
- Normalize AI responses in `aiApi.js` so components always receive a stable shape.
- Add frontend tests for AI loading, error, and success states when frontend tests are introduced.

### Frontend structure & polish
- Make loading and empty states consistent across the Verdict card, Detail panel, Model insight panel, and AI summary card.
- Improve responsive/mobile layout.
- Consider adding timestamps or request IDs for scans.
- Remove dead frontend code.

### Testing, tooling, CI
- Keep organizing backend tests by concern.
- Continue expanding service-level tests for `scoring_service` and `ai_score_service`.
- Set up frontend testing with a lightweight runner such as Vitest + React Testing Library.
- Add CI to run backend tests and build the frontend on every push/PR.
- Add linting/formatting (`ruff` or `flake8` + `black`; `ESLint` + `Prettier`).
- Add basic coverage reporting, especially around AI and scoring services.