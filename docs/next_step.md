PROJECT_IMPROVEMENT_PLAN
This project is functionally complete and all current tests are passing. The items below are not required for the current release; they represent a future roadmap for improving model quality, operational maturity, and user experience.

Future roadmap
1. Model improvement and classifier accuracy
Future work can focus on improving the phishing URL classifier beyond the current production-ready baseline.

Planned improvements include:

Expanding dataset freshness and coverage, especially with newer malicious URL samples and better-balanced benign examples.

Adding stronger lexical, structural, and host-derived features, such as entropy, suspicious token patterns, domain-depth signals, and reputation-oriented enrichments.

Running more systematic model comparisons across Logistic Regression, XGBoost, and LightGBM using metrics such as ROC AUC, average precision, recall, and false negatives.

Improving generalization by validating on harder splits that reduce memorization of duplicate or near-duplicate URLs.

Exploring better probability calibration so reported malicious probabilities are more trustworthy and more useful for threshold-based decisions.

2. Calibration and threshold selection
The current system supports thresholded predictions, but future iterations can make threshold selection more principled.

Planned improvements include:

Adding an optional calibration stage during training, such as Platt scaling or isotonic calibration.

Measuring calibration quality with metrics such as Brier score and reliability summaries.

Replacing static default thresholds with thresholds selected from validation results.

Recording the recommended threshold and threshold-selection rationale directly in model artifact metadata.

Keeping environment-based threshold overrides only as an advanced operational control.

3. Model lifecycle and metadata
The model pipeline now supports multiple model types and richer metadata, but lifecycle management can be improved further over time.

Planned improvements include:

Adding a small CLI or helper script to print the active model’s metadata, including model type, feature version, threshold, and evaluation metrics.

Formalizing a simple versioning policy for feature extraction so older artifacts cannot be used with incompatible feature sets.

Making model selection and promotion more explicit for future retraining cycles.

Preserving clearer training provenance for debugging, auditability, and reproducibility.

4. AI provider maturity
AI-assisted explanations are already integrated behind a deterministic scoring pipeline, but the provider layer can be expanded later.

Planned improvements include:

Adding a lightweight AI provider health check and exposing provider readiness more clearly through the API.

Supporting a second provider in addition to the current local-provider path.

Documenting provider configuration, expected failure modes, and disabled/stub/real-AI behavior in greater detail.

Expanding edge-case tests for malformed or adversarial provider outputs.

Continuing to enforce the rule that AI-generated text cannot change the deterministic verdict, risk label, or threshold source.

5. Explanation quality and evidence structure
The current explanation layer is usable and stable, but future versions can make evidence more structured and UI-friendly.

Planned improvements include:

Making heuristic evidence categories explicit, such as lexical, structural, or domain-signal categories.

Ensuring all reason ordering remains deterministic and consistent across repeated scans.

Replacing any remaining internal or technical wording with more user-readable phrasing.

Adding a lightweight confidence or evidence-strength field to help users interpret borderline cases.

Improving how deterministic reasons and AI summaries complement each other in the user experience.

6. Frontend polish
The current UI is sufficient for project completion, but future updates can improve resilience and usability.

Planned improvements include:

Refining AI summary states for disabled, loading, success, and failure scenarios.

Making deterministic explanations and AI-generated summaries visually distinct but clearly related.

Improving mobile responsiveness and consistency across all cards and panels.

Surfacing scan metadata such as timestamps or request identifiers for debugging and traceability.

Removing any remaining dead components, unused styles, or legacy UI paths.

7. Tooling, CI, and production hardening
The project is currently in a strong local-development state, and future work can raise its production readiness.

Planned improvements include:

Adding a CI pipeline that runs backend tests and frontend builds on every push or pull request.

Enforcing linting and formatting for both Python and frontend code.

Adding basic coverage reporting for core backend modules such as ML services, AI services, and API routes.

Extending deployment and observability support if the project is later promoted from portfolio/demo status to a maintained service.

Performing a final production-readiness pass on logging, error handling, and operational diagnostics.
