## ML improvements

The main ML weakness right now is that the classifier only sees a small lexical feature set, while much of the stronger detection logic lives outside the model in heuristics. A good next step is to **expand feature engineering and model metadata**, not replace the classifier outright. [par.nsf](https://par.nsf.gov/servlets/purl/10408623)

### Feature engineering
- Add hostname structure features: subdomain count, registrable-domain length, label count, max label length, average label length, repeated-label patterns. [ieeexplore.ieee](https://ieeexplore.ieee.org/document/11231397/)
- Add lexical risk features: punycode flag, entropy-like score, repeated characters, uppercase ratio, separator density, suspicious extension flags (`.exe`, `.zip`, `.js`, `.scr`, `.bat`). [arxiv](https://arxiv.org/pdf/1910.06277.pdf)
- Add phishing-flow features: redirect-style parameter count, nested URL presence, login token in host vs path, credential-parameter presence, recovery/reset keywords, raw-IP + login combo, uncommon port flag. [onlinelibrary.wiley](https://onlinelibrary.wiley.com/doi/10.1155/2021/8241104)
- Add domain trust features in a lightweight way: trusted-domain exact match, protected-brand-in-host flag, typo-distance-to-brand features, SSO-like endpoint flag, internal/localhost flag. [blog.cloudflare](https://blog.cloudflare.com/50-most-impersonated-brands-protect-phishing/)
- Normalize the TLD feature properly instead of carrying `_tld_raw`; either bucket TLDs into categories or encode them consistently during training and inference so the model can actually use them. [par.nsf](https://par.nsf.gov/servlets/purl/10408623)

### Model pipeline
- Store richer artifact metadata inside each `.joblib`: `model_type`, `trained_at`, `dataset_name`, `metrics`, `feature_names`, `threshold`, `feature_version`.
- Add feature schema validation in `predict.py` so inference fails clearly if the saved artifact expects missing features.
- Add offline evaluation scripts for precision, recall, F1, ROC-AUC, and false-positive review on a fixed holdout set. [norma.ncirl](https://norma.ncirl.ie/8195/1/charandeepchinthalapalli.pdf)
- Compare XGBoost against Random Forest or LightGBM-style boosting equivalents if available; boosted tree models often work well on engineered phishing URL features. [techscience](https://www.techscience.com/iasc/v31n3/44838/html)
- Tune the threshold using validation data instead of a mostly static default of `0.75`, then expose that threshold from artifact metadata rather than environment override alone. [norma.ncirl](https://norma.ncirl.ie/8195/1/charandeepchinthalapalli.pdf)

### ML/heuristics boundary cleanup
Right now some signals are duplicated conceptually across heuristics and what should eventually become model features. A clean split would be:
- ML handles broad pattern recognition from structured features.
- Heuristics keep explicit high-signal rules like raw IP + executable, brand impersonation edge cases, trusted-domain softening, and known dangerous URL structures. [ituonline](https://www.ituonline.com/blogs/mastering-heuristic-methods-for-malware-detection-and-reverse-engineering/)
- `scoring.py` becomes the policy layer that fuses ML, heuristics, infra, and later LLM review.

## AI / LLM additions

The safest and most useful AI upgrade is to use LLMs as a **second-stage explainer and reviewer**, not as the sole detector. Layered systems are generally more robust than relying on one AI component alone. [veridas](https://veridas.com/en/layered-security/)

### Best initial use cases
- Plain-English explanation of why a URL is suspicious or likely safe.
- Rewrite technical reasons into normal-user language.
- Generate user guidance like “Do not sign in”, “Open the company’s official site manually instead”, or “Verify with the sender through another channel”. [cuanschutz](https://www.cuanschutz.edu/offices/iss/iss-newsroom/it-security-action-and-awareness-best-practices-to-protect-against-phishing-and-smishing)
- Review borderline cases where ML and heuristics disagree, for example:
  - ML low, heuristics high
  - ML medium, heuristics low
  - trusted domain with unusual redirect behavior

### Architecture
Add an AI review layer after `enrich_score()`:
- `enrich_score(url)` returns core result.
- `review_with_llm(url, enriched_result, mode="consumer" | "analyst")` adds:
  - `summary`
  - `advice`
  - `confidence_note`
  - optional `llm_observations`

Suggested modules:
- `sentinelti/ai/providers/ollama.py`
- `sentinelti/ai/providers/gemini.py`
- `sentinelti/ai/review.py`
- `sentinelti/ai/prompts.py`

### Provider plan
- **Ollama first** for free, local, privacy-friendly operation.
- **Gemini second** as an optional cloud backend with stronger reasoning and structured response support, while watching current free-tier and rate-limit constraints. [ai.google](https://ai.google.dev/gemini-api/docs/pricing)

### AI todo list
- Add a provider interface: `generate_analysis(prompt, response_schema)`.
- Require structured JSON-only responses from the LLM.
- Add a timeout and fallback so scoring still works if the LLM is unavailable.
- Never let the LLM override a strong malicious verdict from deterministic layers without explicit policy.
- Add red-team tests for prompt injection via malicious URLs and weird query strings, since attacker-controlled input will be sent to the model. [confident-ai](https://www.confident-ai.com/blog/red-teaming-llms-a-step-by-step-guide)
- Add two explanation styles:
  - `consumer`: simple, short, reassuring, action-focused
  - `analyst`: fuller reasoning with signal grouping and caveats

## User-friendly UI

You already have the backend foundation in FastAPI, so the quickest win is to build a simple web app on top of `/score-url`. For public-facing security tools, the UI should reduce confusion and drive safe behavior with clear language and defensive design. [confetti](https://confetti.design/blog/a-better-ui-ux-can-save-your-users-from-security-threats)

### Public / regular-person view
The public mode should answer only three things:
- Is this safe?
- Why?
- What should I do next?

#### Core screen
- Large URL input box.
- One primary button: **Check URL**.
- A result card with:
  - verdict: Safe / Suspicious / Dangerous
  - short one-sentence explanation
  - 2–4 action steps
  - a confidence indicator in plain words, not only probabilities

#### Recommended sections
- “Why we flagged this” with 2–5 simple bullets.
- “What you should do now”:
  - Don’t log in yet
  - Don’t download anything
  - Visit the official site manually
  - Ask the sender through another channel [consumer.ftc](https://consumer.ftc.gov/articles/how-recognize-avoid-phishing-scams)
- “Technical details” collapsed by default.

#### UX principles
- Avoid dumping raw probabilities first.
- Avoid jargon like “lexical anomaly” in public mode.
- Use color carefully: green, amber, red, but always with text labels for accessibility.
- Add copy/paste-friendly results and a “report suspicious URL” action later. [cm-alliance](https://www.cm-alliance.com/cybersecurity-blog/when-poor-ui-becomes-a-security-risk-real-world-examples)

### Specialist / analyst view
Analysts and advanced users will want the raw signals.

#### Specialist panel
- ML block:
  - model type
  - `prob_malicious`
  - threshold
  - model verdict
- Heuristics block:
  - heuristic score
  - triggered rules
  - raw features
- Infrastructure block:
  - resolved IP
  - IP class
  - infra flag
  - reputation source
- AI review block:
  - structured summary
  - reasoning notes
  - disagreement/caveat markers

#### Extra specialist features
- Full JSON response viewer.
- Copy JSON / export JSON.
- Batch upload and batch results table.
- Filter by risk / final label.
- Optional future redirect chain and DNS/ASN enrichment.

## Product roadmap

A practical order would be:

### Phase 1: strengthen detection
- Expand `ml/features.py`
- Add artifact metadata
- Build evaluation scripts and curated test sets
- Refine scoring thresholds in `scoring.py`

### Phase 2: add AI explanation
- Build LLM provider abstraction
- Add Ollama integration first
- Add structured explanation output
- Add optional Gemini provider
- Only use LLM on borderline or explanation paths at first

### Phase 3: launch user UI
- Build a simple single-page frontend
- Public result mode by default
- Collapsible analyst mode
- Hook into existing FastAPI backend

### Phase 4: advanced features
- Batch UI
- redirect-chain inspection
- screenshot preview
- domain age / WHOIS / ASN enrichment
- browser extension
- email/text paste mode that extracts URLs automatically

## Highest-priority next tasks

If you want the fastest meaningful progress, I’d do these next:

1. Expand `ml/features.py` with 10–15 stronger features. [pmc.ncbi.nlm.nih](https://pmc.ncbi.nlm.nih.gov/articles/PMC9436524/)
2. Add model artifact metadata and expose real model info via API instead of hardcoding `"model": "xgb"`. [norma.ncirl](https://norma.ncirl.ie/8195/1/charandeepchinthalapalli.pdf)
3. Build `ai/review.py` with an Ollama provider and strict JSON output. [arxiv](https://arxiv.org/html/2507.18215v2)
4. Add a public-facing `/analyze` web page with:
   - one input,
   - verdict,
   - simple explanation,
   - hidden advanced details. [confetti](https://confetti.design/blog/a-better-ui-ux-can-save-your-users-from-security-threats)

## My recommendation

The best product shape is:

- **ML + heuristics** = actual detection engine  
- **LLM** = explanation and borderline review  
- **UI** = two layers, public and analyst  

