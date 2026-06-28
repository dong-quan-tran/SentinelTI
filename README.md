# SentinelTI

SentinelTI is a Python-based URL threat scoring tool that combines machine learning, heuristic analysis, and threat-intelligence ingestion to classify URLs as **benign**, **suspicious**, or **malicious**. It supports both a CLI workflow and a FastAPI HTTP API, and returns human-readable explanations alongside model output and metadata.

## Quick start

### Requirements

- Python 3.10+
- Git
- Recommended: a virtual environment
- A trained model artifact in `sentinelti/models/` for scoring, or train one with the commands in the training section below

### 1. Clone the repository

```bash
git clone https://github.com/dong-quan-tran/SentinelTI.git
cd SentinelTI
```

### 2. Create and activate a virtual environment

Windows (PowerShell):

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Windows (cmd):

```cmd
python -m venv .venv
.\.venv\Scripts\activate.bat
```

Linux/macOS:

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

API server:

```bash
python -m uvicorn sentinelti.api.app:app --host 0.0.0.0 --port 8000 --reload
```

FastAPI uses response models to validate and shape outbound API data, so the documented response structures below should closely match the application behavior.

## CLI usage

SentinelTI includes a CLI for database initialization, feed ingestion, and URL scoring.

### Initialize the database

```bash
python -m sentinelti.cli init
```

This creates the local SQLite database used for threat-intelligence storage.

### Ingest the URLhaus feed

```bash
python -m sentinelti.cli ingest urlhaus
```

This downloads recent URLhaus data and upserts malicious URL indicators into the local database.

### Score a single URL

Human-readable output:

```bash
python -m sentinelti.cli score-url "http://example.com"
```

JSON output:

```bash
python -m sentinelti.cli score-url "http://example.com" --json
python -m sentinelti.cli score-url "http://example.com" --json-pretty
```

### Score multiple URLs

Human-readable output:

```bash
python -m sentinelti.cli score-urls "http://example.com" "http://192.168.0.1/login"
```

JSON output:

```bash
python -m sentinelti.cli score-urls "http://example.com" "http://192.168.0.1/login" --json
python -m sentinelti.cli score-urls "http://example.com" "http://192.168.0.1/login" --json-pretty
```

Each CLI result is built from the same central scoring logic used by the API, which helps keep behavior consistent across interfaces.

## HTTP API

SentinelTI exposes a FastAPI HTTP API that reuses the same scoring pipeline as the CLI.

### API key

Protected endpoints require an `X-API-KEY` header.

Linux/macOS:

```bash
export SENTINELTI_API_KEY="your-secret-key"
```

Windows PowerShell:

```powershell
$env:SENTINELTI_API_KEY="your-secret-key"
```

If `SENTINELTI_API_KEY` is not set, the app falls back to `"change-me"`, which is suitable only for local development.

### Start the API server

```bash
python -m uvicorn sentinelti.api.app:app --host 0.0.0.0 --port 8000 --reload
```

Local endpoints:

- Base URL: `http://localhost:8000`
- Swagger UI: `http://localhost:8000/docs`

## Frontend UI

If you are using the React UI, run it separately from the API.

From the frontend directory:

```bash
cd frontend
npm install
npm run dev
```

Typical local frontend URL:

- `http://localhost:5173`

If needed, create `frontend/.env`:

```env
VITE_API_BASE_URL=http://127.0.0.1:8000
VITE_SENTINELTI_API_KEY=change-me
```

## Endpoints

### `GET /health`

No authentication required.

Example response:

```json
{
  "status": "ok",
  "version": "0.1.0"
}
```

### `GET /model-info`

Authentication required.

Example request:

```bash
curl -X GET "http://localhost:8000/model-info" \
  -H "X-API-KEY: your-secret-key"
```

Example response:

```json
{
  "schema_version": "1.1",
  "model_meta": {
    "artifact_version": "1.0",
    "model_type": "xgb",
    "trained_at": "2026-05-23T12:00:00Z",
    "dataset_name": "kaggle",
    "dataset_source": {
      "use_real_data": true
    },
    "feature_version": "v2",
    "threshold": 0.75,
    "threshold_source": "metadata",
    "recommended_threshold": 0.8,
    "recommended_threshold_source": "artifact_metadata",
    "metrics": {
      "roc_auc": 0.999,
      "average_precision": 0.998
    },
    "class_labels": {
      "benign": 0,
      "malicious": 1
    },
    "class_counts": {
      "train_0": 10,
      "train_1": 5,
      "test_0": 4,
      "test_1": 2
    },
    "training_params": {
      "n_estimators": 400
    },
    "training_notes": [
      "logreg did not fully converge; consider tuning max_iter"
    ],
    "top_features": [
      {
        "feature": "url_length",
        "importance": 0.91
      },
      {
        "feature": "has_ip",
        "importance": 0.77
      },
      {
        "feature": "num_dots",
        "importance": 0.63
      }
    ],
    "artifact_path": "sentinelti/models/url_classifier_xgb.joblib",
    "model_summary": {
      "model_type": "xgb",
      "dataset_name": "kaggle",
      "trained_at": "2026-05-23T12:00:00Z",
      "top_features": [
        {
          "feature": "url_length",
          "importance": 0.91
        },
        {
          "feature": "has_ip",
          "importance": 0.77
        },
        {
          "feature": "num_dots",
          "importance": 0.63
        }
      ]
    }
  }
}
```

### `POST /score-url`

Authentication required.

Request body:

```json
{
  "url": "https://example.com"
}
```

Example `curl`:

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
  "heuristic": {
    "score": 0.0,
    "reasons": []
  },
  "final_label": "benign",
  "risk": "low",
  "reasons": [
    "No strong malicious indicators detected by model or heuristics."
  ],
  "explanation": {
    "summary": "This URL currently appears low risk, although no automated check is perfect.",
    "why_flagged": "The machine-learning model found relatively few malicious patterns.",
    "user_action": "Proceed carefully and still verify the domain manually before sharing sensitive information.",
    "technical_notes": [
      "No strong malicious indicators detected by model or heuristics."
    ],
    "risk": "low",
    "final_label": "benign"
  },
  "model_meta": {
    "artifact_version": "1.0",
    "model_type": "xgb",
    "trained_at": "2026-05-23T12:00:00Z",
    "dataset_name": "kaggle",
    "dataset_source": {
      "use_real_data": true
    },
    "feature_version": "v2",
    "threshold": 0.75,
    "threshold_source": "metadata",
    "recommended_threshold": 0.8,
    "recommended_threshold_source": "artifact_metadata",
    "metrics": {
      "roc_auc": 0.999,
      "average_precision": 0.998
    },
    "class_labels": {
      "benign": 0,
      "malicious": 1
    },
    "class_counts": {
      "train_0": 10,
      "train_1": 5,
      "test_0": 4,
      "test_1": 2
    },
    "training_params": {
      "n_estimators": 400
    },
    "training_notes": [
      "logreg did not fully converge; consider tuning max_iter"
    ],
    "top_features": [
      {
        "feature": "url_length",
        "importance": 0.91
      },
      {
        "feature": "has_ip",
        "importance": 0.77
      },
      {
        "feature": "num_dots",
        "importance": 0.63
      }
    ],
    "artifact_path": "sentinelti/models/url_classifier_xgb.joblib",
    "model_summary": {
      "model_type": "xgb",
      "dataset_name": "kaggle",
      "trained_at": "2026-05-23T12:00:00Z",
      "top_features": [
        {
          "feature": "url_length",
          "importance": 0.91
        },
        {
          "feature": "has_ip",
          "importance": 0.77
        },
        {
          "feature": "num_dots",
          "importance": 0.63
        }
      ]
    }
  }
}
```

### `POST /score-urls`

Authentication required.

Request body:

```json
{
  "urls": [
    "https://example.com",
    "https://phishy.example/login"
  ]
}
```

Example `curl`:

```bash
curl -X POST "http://localhost:8000/score-urls" \
  -H "Content-Type: application/json" \
  -H "X-API-KEY: your-secret-key" \
  -d "{\"urls\": [\"https://example.com\", \"https://phishy.example/login\"]}"
```

Example response (truncated to one result for brevity):

```json
{
  "results": [
    {
      "schema_version": "1.2",
      "url": "https://example.com",
      "label": 0,
      "prob_malicious": 0.02,
      "threshold": 0.75,
      "heuristic": {
        "score": 0.0,
        "reasons": []
      },
      "final_label": "benign",
      "risk": "low",
      "reasons": [
        "No strong malicious indicators detected by model or heuristics."
      ],
      "explanation": {
        "summary": "This URL currently appears low risk, although no automated check is perfect.",
        "why_flagged": "The machine-learning model found relatively few malicious patterns.",
        "user_action": "Proceed carefully and still verify the domain manually before sharing sensitive information.",
        "technical_notes": [
          "No strong malicious indicators detected by model or heuristics."
        ],
        "risk": "low",
        "final_label": "benign"
      },
      "model_meta": {
        "artifact_version": "1.0",
        "model_type": "xgb",
        "trained_at": "2026-05-23T12:00:00Z",
        "dataset_name": "kaggle",
        "dataset_source": {
          "use_real_data": true
        },
        "feature_version": "v2",
        "threshold": 0.75,
        "threshold_source": "metadata",
        "recommended_threshold": 0.8,
        "recommended_threshold_source": "artifact_metadata",
        "metrics": {
          "roc_auc": 0.999,
          "average_precision": 0.998
        },
        "class_labels": {
          "benign": 0,
          "malicious": 1
        },
        "class_counts": {
          "train_0": 10,
          "train_1": 5,
          "test_0": 4,
          "test_1": 2
        },
        "training_params": {
          "n_estimators": 400
        },
        "training_notes": [
          "logreg did not fully converge; consider tuning max_iter"
        ],
        "top_features": [
          {
            "feature": "url_length",
            "importance": 0.91
          },
          {
            "feature": "has_ip",
            "importance": 0.77
          },
          {
            "feature": "num_dots",
            "importance": 0.63
          }
        ],
        "artifact_path": "sentinelti/models/url_classifier_xgb.joblib",
        "model_summary": {
          "model_type": "xgb",
          "dataset_name": "kaggle",
          "trained_at": "2026-05-23T12:00:00Z",
          "top_features": [
            {
              "feature": "url_length",
              "importance": 0.91
            },
            {
              "feature": "has_ip",
              "importance": 0.77
            },
            {
              "feature": "num_dots",
              "importance": 0.63
            }
          ]
        }
      }
    }
  ]
}
```

### `POST /explain-score`

Authentication required.

Request body:

```json
{
  "url": "https://example.com"
}
```

Example `curl`:

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

## AI-assisted explanations

SentinelTI includes an optional AI-assisted explanation endpoint:

- `POST /ai-explain-score`

This endpoint returns:

- the existing deterministic explanation generated from the model score and heuristic analysis
- a separate AI-generated rewrite intended to make the result easier to understand

### Important behavior

The deterministic score remains the source of truth.

AI output does **not** change any of the following fields:

- `label`
- `risk`
- `threshold`
- `prob_malicious`
- `final_label`

The AI summary is advisory only and should be treated as a readability enhancement, not a decision engine.

The AI block may include:

- `summary`: a plain-language restatement of the deterministic explanation
- `guidance`: user-facing actionable guidance derived from the deterministic verdict

### Example response

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

AI-assisted explanations are controlled via environment variables:

- `SENTINELTI_AI_ENABLED` — master on/off switch for the AI endpoint (`true` or `false`)
- `SENTINELTI_AI_PROVIDER` — provider name (currently `ollama` or `none`)
- `SENTINELTI_OLLAMA_ENDPOINT` — base URL for the Ollama HTTP endpoint, for example:

  ```bash
  export SENTINELTI_OLLAMA_ENDPOINT="http://localhost:11434"
  ```

- `SENTINELTI_OLLAMA_MODEL` — default Ollama model name used when the request does not specify `ai_model`, for example:

  ```bash
  export SENTINELTI_OLLAMA_MODEL="llama3.1:8b"
  ```

The `GET /ai-models` endpoint returns:

- `provider`: current provider name
- `default_model`: the configured default model when using Ollama
- `models`: a list of locally available models when using Ollama

Example request:

```bash
curl -X GET "http://localhost:8000/ai-models" \
  -H "X-API-KEY: your-secret-key"
```

Example response:

```json
{
  "provider": "ollama",
  "default_model": "llama3.1:8b",
  "models": [
    "llama3.1:8b",
    "llama3.1:70b",
    "codellama:13b"
  ]
}
```

### AI feature flag

AI-assisted explanations can be enabled or disabled with:

- `SENTINELTI_AI_ENABLED=true`
- `SENTINELTI_AI_ENABLED=false`

When AI is disabled, `POST /ai-explain-score` short-circuits and returns:

- HTTP `503 Service Unavailable`
- error payload:

  ```json
  {
    "detail": "AI explanations are currently disabled.",
    "error_type": "ai_disabled"
  }
  ```

The deterministic scoring endpoints remain fully functional:

- `POST /score-url`
- `POST /score-urls`
- `POST /explain-score`

### AI error behavior

If deterministic scoring succeeds but the AI explanation step fails, the endpoint returns:

- HTTP `500 Internal Server Error`
- error payload:

  ```json
  {
    "detail": "AI provider unavailable",
    "error_type": "ai_explanation_error"
  }
  ```

If a client requests an AI model that is not available, the endpoint returns:

- HTTP `422 Unprocessable Entity`
- error payload:

  ```json
  {
    "detail": "Requested AI model is not available",
    "error_type": "ai_model_unavailable"
  }
  ```

These failures do not affect the standard scoring endpoints such as:

- `POST /score-url`
- `POST /score-urls`
- `POST /explain-score`

## Error responses

SentinelTI returns JSON error responses for common failure modes, and documenting those shapes alongside the happy path makes the API easier to consume.

### `401 Unauthorized`

Returned when `X-API-KEY` is missing or invalid.

Example response:

```json
{
  "detail": "Unauthorized"
}
```

### `422 Unprocessable Entity`

Returned when the request body is missing required fields or has the wrong shape. FastAPI’s default validation handler returns a `detail` list describing the validation issue.

Example response:

```json
{
  "detail": [
    {
      "type": "missing",
      "loc": ["body", "url"],
      "msg": "Field required",
      "input": {}
    }
  ]
}
```

### `429 Too Many Requests`

Protected endpoints are rate-limited per client IP, and exceeding the limit returns:

```json
{
  "detail": "Rate limit exceeded. Try again later."
}
```

Responses may also include:

- `X-RateLimit-Limit`
- `X-RateLimit-Remaining`
- `X-RateLimit-Reset`
- `Retry-After`

### `500 Internal Server Error`

Returned when the scoring pipeline raises a runtime error. SentinelTI uses a structured JSON response for these scoring-time failures.

Example response:

```json
{
  "detail": "Internal scoring error",
  "error_type": "runtime_error"
}
```

## Rate limiting and auth

Protected endpoints require a valid `X-API-KEY` header and are rate-limited by client IP in the application layer. Protected responses may include rate-limit headers such as `X-RateLimit-Limit`, `X-RateLimit-Remaining`, and `X-RateLimit-Reset`.

## Core response fields

SentinelTI uses a few core fields consistently across scoring responses:

- `label`: raw ML prediction, where `0` means benign and `1` means malicious
- `prob_malicious`: model-estimated malicious probability between 0 and 1
- `threshold`: effective malicious threshold used for live classification
- `heuristic.score`: numeric score from rule-based URL checks
- `heuristic.reasons`: list of triggered heuristic explanations
- `final_label`: final combined decision, one of `benign`, `suspicious`, or `malicious`
- `risk`: human-friendly risk bucket, one of `low`, `medium`, or `high`
- `reasons`: top-level explanation list
- `explanation`: structured end-user explanation payload
- `model_meta`: model artifact and training metadata returned by the API

## Model metadata notes

The `model_meta` block distinguishes between **effective** threshold values used for decisions and **advisory** threshold values included for guidance.

- `threshold`: the effective classification threshold currently used by the application
- `threshold_source`: where the effective threshold came from, such as `metadata`, `env`, or `default`
- `recommended_threshold`: an advisory threshold stored in model metadata
- `recommended_threshold_source`: where that advisory value came from
- `training_notes`: optional notes captured during training, including convergence warnings when present
- `top_features`: the fuller feature-importance payload when available
- `model_summary`: a compact summary block for UI and quick inspection

If partial metadata is loaded, SentinelTI fills in sensible defaults instead of failing the endpoint. For example, missing metrics can remain `null`, and missing lists default to empty arrays.

## How it works

SentinelTI combines machine learning, heuristic scoring, and threat-intelligence data into one scoring pipeline.

1. **Threat-intelligence ingestion**
   - SentinelTI can ingest recent malicious URL indicators from URLhaus into a local SQLite database.
   - This local store supports enrichment, analysis, and training workflows.

2. **Machine-learning classifier**
   - A URL classifier is trained on labeled data such as Kaggle datasets and URLhaus-derived malicious samples.
   - The trained artifact is saved in `sentinelti/models/` and used by the prediction layer.

3. **Heuristic analysis**
   - SentinelTI applies hand-crafted URL checks for patterns often associated with phishing or malware, such as raw IP hosts, suspicious tokens, uncommon TLDs, very long domains, and deep paths.
   - These checks contribute a heuristic score and readable reasons.

4. **Central enrichment**
   - A central scoring function combines ML output and heuristic analysis into a unified result.
   - That result includes the final label, risk bucket, reasons, explanation payload, and model metadata.

5. **Shared interfaces**
   - The CLI and FastAPI API both rely on the same scoring logic, which helps keep outputs consistent across interfaces.

## Training the model

SentinelTI includes an ML pipeline under `sentinelti/ml/` for training URL-classification models.

### Training prerequisites

- Install project dependencies:

```bash
pip install -r requirements.txt
```

- Provide a labeled CSV such as:

```text
data/urldata.csv
```

Expected columns:

- `url`
- `label` with values like `benign` or `malicious`

### Example training commands

Train XGBoost on a Kaggle CSV:

```bash
python -m sentinelti.ml.train --model xgb --source kaggle --csv-path data/urldata.csv
```

Train Logistic Regression on a Kaggle CSV:

```bash
python -m sentinelti.ml.train --model logreg --source kaggle --csv-path data/urldata.csv
```

Train XGBoost on URLhaus malicious data plus benign Kaggle data:

```bash
python -m sentinelti.ml.train --model xgb --source urlhaus --csv-path data/urldata.csv
```

Use a small built-in dummy dataset:

```bash
python -m sentinelti.ml.train --model logreg --source dummy
```

### Model artifacts

Training outputs are saved under `sentinelti/models/`. Artifacts may include both the trained model and metadata consumed by the API’s `model_meta` response payload.

### Metrics output

Training runs can also save evaluation metrics under `docs/model_metrics/`.

Typical contents include:

- model type
- training source
- train/test class counts
- classification metrics and reports

## Project structure

```text
sentinelti/
├── api/
│   ├── app.py
│   ├── routes.py
│   ├── schemas.py
│   └── dependencies.py
├── cli.py
├── db.py
├── heuristics.py
├── scoring.py
├── services/
│   ├── ai_explanations.py
│   ├── ai_score_service.py
│   ├── model_metadata.py
│   └── scoring_service.py
├── feeds/
│   └── urlhaus.py
├── frontend/
│   └── ...
├── ml/
│   ├── predict.py
│   ├── train.py
│   └── ...
├── models/
│   └── ...
tests/
docs/
data/
```

High-level responsibilities:

- `sentinelti/api/app.py` — FastAPI application setup (app instance, middleware, exception handlers, SPA mounting)
- `sentinelti/api/routes.py` — HTTP routes for health, scoring, model-info, and AI-assisted explanations
- `sentinelti/api/schemas.py` — Pydantic request/response models and OpenAPI examples
- `sentinelti/api/dependencies.py` — API key authentication and rate limiting
- `sentinelti/cli.py` — CLI entry point
- `sentinelti/db.py` — SQLite initialization and connection logic
- `sentinelti/heuristics.py` — heuristic URL analysis
- `sentinelti/scoring.py` — central score enrichment logic
- `sentinelti/services/model_metadata.py` — model metadata normalization and shaping
- `sentinelti/services/ai_explanations.py` — AI provider abstraction and prompt/response handling
- `sentinelti/services/ai_score_service.py` — glue between deterministic scoring and AI explanations
- `sentinelti/feeds/urlhaus.py` — URLhaus ingestion helpers
- `sentinelti/ml/` — training, prediction, and model-service utilities
- `tests/` — pytest suite
- `docs/` — notes, metrics, and supporting documentation

## Testing

Run the full test suite:

```bash
python -m pytest
```

Run focused files:

```bash
python -m pytest tests/test_api.py -q
python -m pytest tests/test_api_ai.py -q
python -m pytest tests/test_model_metadata_service.py -q
```

## Roadmap

Near-term planned improvements:

- stronger structured API error coverage
- clearer metadata normalization contracts
- additional frontend polish around metadata and explanation states
- richer AI-assisted explanation and investigation features layered on top of deterministic scoring

## Author

SentinelTI is developed and maintained by:

- **Dong Quan Tran (Johnny)**
- Role: Owner / Collaborator
- Email: dxt9721@mavs.uta.edu / dongquan.tran.johnny@gmail.com
- GitHub: dong-quan-tran
