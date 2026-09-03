# SentinelTI

SentinelTI is a full-stack URL threat-scoring platform that combines machine learning, deterministic heuristic analysis, and threat-intelligence ingestion to classify URLs as **benign**, **suspicious**, or **malicious**.

It provides:

- A Python CLI for ingestion and scoring workflows
- A FastAPI REST API with authentication, rate limiting, structured responses, and OpenAPI documentation
- A React frontend for interactive URL investigation
- XGBoost-based URL classification with deterministic heuristic and infrastructure enrichment
- SQLite-backed URLhaus threat-intelligence storage
- Human-readable deterministic explanations and optional AI-assisted summaries

The deterministic scoring pipeline remains the source of truth. Optional AI summaries are advisory only and cannot modify the model score, threshold, final label, or risk level.

## Highlights

- **Hybrid threat detection:** Combines XGBoost classification with deterministic lexical, structural, homoglyph, infrastructure, and reputation-based URL signals.
- **Model quality:** XGBoost achieved **0.9991 ROC-AUC**, **0.9985 average precision**, **99.69% accuracy**, and **99.08% malicious-class recall** on a **135,053-URL held-out test set**.
- **Training scale:** Evaluated Logistic Regression, XGBoost, and LightGBM using **450,175 labeled URLs** across training and held-out evaluation sets.
- **Scoring performance:** A 500-iteration warmed benchmark measured **0.9 ms median** and **1.0 ms p95** core-scoring latency, sustaining **1,110 URLs/second**.
- **End-to-end enrichment:** The complete deterministic path—including DNS resolution, local IP reputation checks, risk fusion, and explanation generation—measured **104.2 ms median** and **123.6 ms p95** latency.
- **Reliability:** Includes **300+ production-style Pytest cases** across API, ML, scoring, CLI, AI-service, and model-metadata behavior.

## Architecture

```text
                    ┌─────────────────────┐
                    │   React Frontend    │
                    └─────────┬───────────┘
                              │ HTTP
                    ┌─────────▼───────────┐
                    │     FastAPI API     │
                    │ Auth + Rate Limits  │
                    └─────────┬───────────┘
                              │
          ┌───────────────────▼────────────────────┐
          │      Deterministic Scoring Pipeline     │
          │                                        │
          │  XGBoost Model + URL Feature Extraction │
          │  Heuristics + Homoglyph Detection       │
          │  DNS Resolution + Local IP Reputation   │
          │  Risk Fusion + Structured Explanations  │
          └───────┬───────────────────────┬────────┘
                  │                       │
        ┌─────────▼─────────┐   ┌────────▼──────────┐
        │ Model Artifacts   │   │ URLhaus + SQLite   │
        │ Metrics/Metadata  │   │ Threat Intelligence│
        └───────────────────┘   └───────────────────┘
```

## Quick start

### Requirements

- Python 3.10+
- Git
- Recommended: a virtual environment
- A trained model artifact in `sentinelti/models/`, or a labeled dataset for training

### 1. Clone the repository

```bash
git clone https://github.com/dong-quan-tran/SentinelTI.git
cd SentinelTI
```

### 2. Create and activate a virtual environment

Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Windows Command Prompt:

```cmd
python -m venv .venv
.\.venv\Scripts\activate.bat
```

Linux or macOS:

```bash
python -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### 4. Run the CLI or API

CLI help:

```bash
python -m sentinelti.cli --help
```

Start the API server:

```bash
python -m uvicorn sentinelti.api.app:app --host 0.0.0.0 --port 8000 --reload
```

Local API resources:

- Base URL: `http://localhost:8000`
- Swagger UI: `http://localhost:8000/docs`

## Frontend

SentinelTI includes a React frontend for interactive URL scoring and explanation review.

From the frontend directory:

```bash
cd sentinelti/frontend
npm install
npm run dev
```

Typical local frontend URL:

```text
http://localhost:5173
```

If needed, create `sentinelti/frontend/.env`:

```env
VITE_API_BASE_URL=http://127.0.0.1:8000
VITE_SENTINELTI_API_KEY=change-me
```

## CLI usage

SentinelTI includes a CLI for database initialization, URLhaus ingestion, and URL scoring.

### Initialize the threat-intelligence database

```bash
python -m sentinelti.cli init
```

This creates the local SQLite database used for threat-intelligence storage.

### Ingest the URLhaus feed

```bash
python -m sentinelti.cli ingest urlhaus
```

This downloads recent URLhaus records and upserts malicious URL indicators into SQLite.

### Score one URL

Human-readable output:

```bash
python -m sentinelti.cli score-url "https://example.com"
```

JSON output:

```bash
python -m sentinelti.cli score-url "https://example.com" --json
python -m sentinelti.cli score-url "https://example.com" --json-pretty
```

### Score multiple URLs

Human-readable output:

```bash
python -m sentinelti.cli score-urls "https://example.com" "http://192.168.0.1/login"
```

JSON output:

```bash
python -m sentinelti.cli score-urls "https://example.com" "http://192.168.0.1/login" --json
python -m sentinelti.cli score-urls "https://example.com" "http://192.168.0.1/login" --json-pretty
```

The CLI and HTTP API share the same scoring pipeline to keep classifications and explanations consistent across interfaces.

## HTTP API

SentinelTI exposes a FastAPI REST API that reuses the CLI scoring pipeline.

### Authentication

Protected endpoints require an `X-API-KEY` header.

Linux or macOS:

```bash
export SENTINELTI_API_KEY="your-secret-key"
```

Windows PowerShell:

```powershell
$env:SENTINELTI_API_KEY="your-secret-key"
```

For local development only, the API falls back to:

```text
change-me
```

Do not use the default API key in a deployed environment.

### Core endpoints

| Method | Endpoint | Auth | Description |
|---|---|---:|---|
| `GET` | `/health` | No | Health and version status |
| `GET` | `/model-info` | Yes | Active model metadata, metrics, thresholds, and top features |
| `POST` | `/score-url` | Yes | Score one URL |
| `POST` | `/score-urls` | Yes | Score a batch of URLs |
| `POST` | `/explain-score` | Yes | Return deterministic explanation only |
| `POST` | `/ai-explain-score` | Yes | Return deterministic and optional AI-assisted explanations |
| `GET` | `/ai-models` | Yes | List configured/available AI models |

### Score one URL

```bash
curl -X POST "http://localhost:8000/score-url" \
  -H "Content-Type: application/json" \
  -H "X-API-KEY: your-secret-key" \
  -d "{\"url\": \"https://example.com\"}"
```

Example response:

```json
{
  "schema_version": "1.2",
  "url": "https://example.com",
  "label": 0,
  "prob_malicious": 0.02,
  "threshold": 0.75,
  "threshold_source": "metadata",
  "heuristic": {
    "score": 0.0,
    "reasons": []
  },
  "final_label": "benign",
  "risk": "low",
  "reasons": [
    "Model predicts benign with probability 0.98 (malicious probability 0.02).",
    "No strong malicious indicators detected by model or heuristics."
  ],
  "explanation": {
    "summary": "This URL currently appears low risk, although no automated check is perfect.",
    "why_flagged": "The machine-learning model found relatively few malicious patterns.",
    "user_action": "Proceed carefully and still verify the domain manually before sharing sensitive information.",
    "technical_notes": [
      "Model predicts benign with probability 0.98 (malicious probability 0.02).",
      "No strong malicious indicators detected by model or heuristics."
    ],
    "risk": "low",
    "final_label": "benign"
  }
}
```

### Score a URL batch

```bash
curl -X POST "http://localhost:8000/score-urls" \
  -H "Content-Type: application/json" \
  -H "X-API-KEY: your-secret-key" \
  -d "{\"urls\": [\"https://example.com\", \"https://phishy.example/login\"]}"
```

The batch endpoint returns a `results` array containing the same scoring schema used by `/score-url`.

### Deterministic explanation

```bash
curl -X POST "http://localhost:8000/explain-score" \
  -H "Content-Type: application/json" \
  -H "X-API-KEY: your-secret-key" \
  -d "{\"url\": \"https://example.com\"}"
```

Example response:

```json
{
  "summary": "This URL currently appears low risk, although no automated check is perfect.",
  "why_flagged": "The machine-learning model found relatively few malicious patterns.",
  "user_action": "Proceed carefully and still verify the domain manually before sharing sensitive information.",
  "technical_notes": [
    "No strong malicious indicators detected by model or heuristics."
  ],
  "risk": "low",
  "final_label": "benign"
}
```

### Model metadata

```bash
curl -X GET "http://localhost:8000/model-info" \
  -H "X-API-KEY: your-secret-key"
```

The response includes:

- Active model type and artifact version
- Training timestamp and dataset source
- Feature version and feature count
- Effective decision threshold and threshold source
- Recommended threshold metadata
- ROC-AUC and average-precision metrics
- Class counts and training parameters
- Top feature-importance entries

## How scoring works

SentinelTI combines model output and deterministic enrichment in one scoring path.

1. **Feature extraction**
   - Extracts lexical and structural URL features, including length, entropy, subdomain depth, host patterns, special characters, path patterns, protocol, risky keywords, and IP-host indicators.

2. **Machine-learning prediction**
   - Uses the preferred model artifact, currently XGBoost, to calculate malicious probability.

3. **Heuristic analysis**
   - Applies deterministic rules for suspicious patterns such as direct IP hosts, login or verification keywords, deep paths, uncommon TLDs, encoded characters, look-alike domains, and known homoglyph patterns.

4. **Infrastructure enrichment**
   - Resolves hostnames, classifies resolved IPs, and checks local IP reputation data when applicable.

5. **Risk fusion**
   - Combines model probability and deterministic signals into `benign`, `suspicious`, or `malicious` labels with `low`, `medium`, or `high` risk levels.

6. **Explanation generation**
   - Produces stable, human-readable reasons, technical notes, and user-action guidance from the deterministic result.

## Model evaluation

SentinelTI supports Logistic Regression, XGBoost, and LightGBM classifiers.

The latest evaluation used 450,175 labeled URLs:

- Training set: 315,122 URLs
- Held-out test set: 135,053 URLs

| Model | ROC-AUC | Average Precision | Accuracy | Malicious Precision | Malicious Recall | Malicious F1 |
|---|---:|---:|---:|---:|---:|---:|
| Logistic Regression | 0.9966 | 0.9958 | 99.37% | 99.46% | 97.82% | 98.63% |
| XGBoost | **0.9991** | **0.9985** | **99.69%** | **99.61%** | 99.08% | **99.34%** |
| LightGBM | 0.9991 | 0.9985 | 99.69% | 99.50% | **99.14%** | 99.32% |

XGBoost is the current preferred model because it achieved the strongest overall ROC-AUC, average precision, accuracy, and malicious-class F1. LightGBM achieved marginally higher malicious recall, so model selection can be revisited if recall becomes the primary operational requirement.

Evaluation artifacts are stored in:

```text
docs/model_metrics/
```

## Training

The training pipeline is located in `sentinelti/ml/`.

### Training prerequisites

Install dependencies:

```bash
pip install -r requirements.txt
```

Provide a labeled CSV such as:

```text
data/urldata.csv
```

Expected columns:

- `url`
- `label`, such as `benign` or `malicious`

### Train XGBoost

```bash
python -m sentinelti.ml.train --model xgb --source kaggle --csv-path data/urldata.csv
```

### Train Logistic Regression

```bash
python -m sentinelti.ml.train --model logreg --source kaggle --csv-path data/urldata.csv
```

### Train LightGBM

```bash
python -m sentinelti.ml.train --model lgbm --source kaggle --csv-path data/urldata.csv
```

### Train with URLhaus-derived malicious data

```bash
python -m sentinelti.ml.train --model xgb --source urlhaus --csv-path data/urldata.csv
```

### Train with the built-in dummy dataset

```bash
python -m sentinelti.ml.train --model logreg --source dummy
```

Training outputs model artifacts under:

```text
sentinelti/models/
```

Metrics and evaluation reports are written under:

```text
docs/model_metrics/
```

## AI-assisted explanations

SentinelTI supports optional AI-assisted rewrites of deterministic explanations.

The AI layer is intentionally separated from deterministic scoring:

- Deterministic scoring remains the decision authority.
- AI output is advisory and intended only to improve readability.
- AI output cannot modify `label`, `prob_malicious`, `threshold`, `risk`, or `final_label`.

### AI endpoint

```bash
curl -X POST "http://localhost:8000/ai-explain-score" \
  -H "Content-Type: application/json" \
  -H "X-API-KEY: your-secret-key" \
  -d "{\"url\": \"https://example.com\"}"
```

Example response shape:

```json
{
  "deterministic_explanation": {
    "summary": "This URL appears suspicious.",
    "why_flagged": "Several phishing-like signals were detected.",
    "user_action": "Avoid opening the link until it is verified.",
    "technical_notes": [
      "Contains suspicious lexical patterns."
    ],
    "risk": "high",
    "final_label": "malicious"
  },
  "ai": {
    "summary": "This link shows several warning signs and should be treated as high risk.",
    "guidance": "Use the deterministic verdict as the primary decision signal. The AI summary is only a helper explanation."
  }
}
```

### AI configuration

AI-assisted explanations use environment variables:

| Variable | Description |
|---|---|
| `SENTINELTI_AI_ENABLED` | Enables or disables AI explanations with `true` or `false` |
| `SENTINELTI_AI_PROVIDER` | Provider name; currently `ollama` or `none` |
| `SENTINELTI_OLLAMA_ENDPOINT` | Ollama base URL, such as `http://localhost:11434` |
| `SENTINELTI_OLLAMA_MODEL` | Default Ollama model, such as `llama3.1:8b` |

Example PowerShell configuration:

```powershell
$env:SENTINELTI_AI_ENABLED="true"
$env:SENTINELTI_AI_PROVIDER="ollama"
$env:SENTINELTI_OLLAMA_ENDPOINT="http://localhost:11434"
$env:SENTINELTI_OLLAMA_MODEL="llama3.1:8b"
```

List available AI models:

```bash
curl -X GET "http://localhost:8000/ai-models" \
  -H "X-API-KEY: your-secret-key"
```

### AI error behavior

| Status | Error type | Meaning |
|---:|---|---|
| `503` | `ai_disabled` | AI explanations are disabled |
| `500` | `ai_explanation_error` | The AI provider failed after deterministic scoring succeeded |
| `422` | `ai_model_unavailable` | The requested AI model is unavailable |

AI failures do not affect deterministic scoring endpoints.

## Error handling

SentinelTI returns JSON error responses for common API failure modes.

| Status | Meaning |
|---:|---|
| `401` | Missing or invalid API key |
| `422` | Invalid request body or unavailable AI model |
| `429` | Rate limit exceeded |
| `500` | Internal scoring or AI-provider error |
| `503` | AI explanations disabled |

Example rate-limit response:

```json
{
  "detail": "Rate limit exceeded. Try again later."
}
```

Rate-limited responses may include:

- `X-RateLimit-Limit`
- `X-RateLimit-Remaining`
- `X-RateLimit-Reset`
- `Retry-After`

## Performance benchmark

SentinelTI includes a reproducible benchmark for deterministic scoring. The benchmark excludes optional AI generation and measures both the compute-oriented scoring path and full deterministic enrichment.

Run the benchmark from the repository root:

```bash
python -m scripts.benchmark_scoring --iterations 500 --warmup 25
```

The benchmark writes results to:

```text
docs/model_metrics/benchmark_scoring.json
```

Current warmed benchmark environment:

- Python 3.11.9
- Windows 10
- Intel64 CPU
- XGBoost model with feature version `v2`
- Malicious threshold: `0.75`

| Path | Median Latency | p95 Latency | Throughput | Includes |
|---|---:|---:|---:|---|
| Core scoring | 0.9 ms | 1.0 ms | 1,110 URLs/sec | Feature extraction, XGBoost inference, heuristic analysis |
| End-to-end deterministic enrichment | 104.2 ms | 123.6 ms | 9.31 URLs/sec | Core scoring, DNS resolution, local IP reputation, risk fusion, deterministic explanations |

End-to-end enrichment is network-sensitive because hostname resolution is included. Use core-scoring results for compute-performance comparison and enriched results for realistic investigation-path latency.

## Testing

Run the full test suite:

```bash
python -m pytest
```

Run focused test modules:

```bash
python -m pytest tests/test_api.py -q
python -m pytest tests/test_api_ai.py -q
python -m pytest tests/test_ml_train.py -q
python -m pytest tests/test_ml_predict_service.py -q
python -m pytest tests/test_model_metadata_service.py -q
python -m pytest tests/test_threshold_analysis.py -q
```

The test suite covers API routes, authentication, rate limiting, CLI behavior, feature extraction, model loading, model metadata, training, predictions, threshold analysis, scoring, reputation, hostname resolution, deterministic explanations, and AI-provider behavior.

## Project structure

```text
SentinelTI/
├── sentinelti/
│   ├── api/
│   │   ├── app.py
│   │   ├── dependencies.py
│   │   ├── routes.py
│   │   └── schemas.py
│   ├── enrich/
│   ├── feeds/
│   │   └── urlhaus.py
│   ├── frontend/
│   ├── ml/
│   │   ├── dataset.py
│   │   ├── evaluate_models.py
│   │   ├── features.py
│   │   ├── predict.py
│   │   ├── threshold_analysis.py
│   │   └── train.py
│   ├── models/
│   ├── services/
│   │   ├── ai_explanations.py
│   │   ├── ai_score_service.py
│   │   ├── model_metadata.py
│   │   └── scoring_service.py
│   ├── cli.py
│   ├── db.py
│   ├── heuristics.py
│   ├── homoglyphs.py
│   ├── reputation.py
│   ├── resolution.py
│   └── scoring.py
├── scripts/
│   ├── __init__.py
│   └── benchmark_scoring.py
├── tests/
├── docs/
│   └── model_metrics/
├── data/
├── requirements.txt
└── README.md
```

### Key modules

- `sentinelti/api/app.py` — FastAPI application setup, middleware, exception handlers, and frontend mounting
- `sentinelti/api/routes.py` — HTTP routes for health, scoring, model metadata, and AI-assisted explanations
- `sentinelti/api/schemas.py` — Pydantic request/response models and OpenAPI documentation
- `sentinelti/api/dependencies.py` — API-key authentication and request rate limiting
- `sentinelti/cli.py` — CLI entry point for database, ingestion, and scoring workflows
- `sentinelti/db.py` — SQLite initialization and connection handling
- `sentinelti/heuristics.py` — deterministic URL heuristics and feature-oriented evidence
- `sentinelti/homoglyphs.py` — look-alike and brand-impersonation signal handling
- `sentinelti/reputation.py` — local IP reputation lookup behavior
- `sentinelti/resolution.py` — hostname-resolution helpers
- `sentinelti/scoring.py` — central ML, heuristic, infrastructure, risk, and explanation enrichment
- `sentinelti/ml/` — URL feature extraction, training, model comparison, prediction, and threshold analysis
- `sentinelti/services/model_metadata.py` — metadata normalization and API response shaping
- `sentinelti/services/ai_explanations.py` — AI-provider abstraction, prompts, and response validation
- `sentinelti/services/ai_score_service.py` — deterministic scoring and optional AI explanation orchestration
- `sentinelti/feeds/urlhaus.py` — URLhaus ingestion helpers
- `scripts/benchmark_scoring.py` — reproducible deterministic scoring benchmark with latency and throughput reporting
- `tests/` — Pytest suite
- `docs/model_metrics/` — persisted model-comparison, threshold-analysis, and benchmark results

## Future improvements

The current implementation is complete for its intended scope. Future iterations may explore:

- Probability calibration and validation-derived threshold selection
- Additional URL, host, DNS, and reputation features
- Expanded threat-intelligence providers and external reputation sources
- Optional asynchronous enrichment and DNS caching for higher batch throughput
- CI-based linting, coverage reporting, and automated benchmark tracking
- Enhanced frontend investigation workflows
- Additional AI-provider adapters and provider-health checks

These items are future enhancements, not prerequisites for the current release.

## Author

SentinelTI is developed and maintained by:

- **Dong Quan Tran (Johnny)**
- Email: [dxt9721@mavs.uta.edu](mailto:dxt9721@mavs.uta.edu)
- Email: [dongquan.tran.johnny@gmail.com](mailto:dongquan.tran.johnny@gmail.com)
- GitHub: [dong-quan-tran](https://github.com/dong-quan-tran)