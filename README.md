# SentinelTI

SentinelTI is a Python-based URL threat scoring tool that combines machine learning, heuristic analysis, and threat-intelligence ingestion to classify URLs as **benign**, **suspicious**, or **malicious**.[web:526] It supports both a CLI workflow and a FastAPI HTTP API, and returns human-readable explanations alongside model output and metadata.[web:526]

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
.venv\Scripts\Activate.ps1
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
uvicorn sentinelti.api:app --host 0.0.0.0 --port 8000 --reload
```

FastAPI uses response models to validate and shape outbound API data, which is why the documented response structure below should match the actual app behavior closely.[web:526]

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

Each CLI result is built from the same central scoring logic used by the API, which helps keep behavior consistent across interfaces.[web:526]

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
uvicorn sentinelti.api:app --host 0.0.0.0 --port 8000 --reload
```

Local endpoints:

- Base URL: `http://localhost:8000`
- Swagger UI: `http://localhost:8000/docs`

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
  "schema_version": "1.0",
  "model_meta": {
    "artifact_version": "1.0",
    "model_type": "xgb",
    "trained_at": "2026-05-18T03:55:05Z",
    "dataset_name": "kaggle",
    "dataset_source": {
      "use_real_data": true
    },
    "feature_version": "v2",
    "threshold": 0.75,
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
    "artifact_path": "sentinelti/models/url_classifier_xgb.joblib"
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
    "trained_at": "2026-05-18T03:55:05Z",
    "dataset_name": "kaggle",
    "dataset_source": {
      "use_real_data": true
    },
    "feature_version": "v2",
    "threshold": 0.75,
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
    "artifact_path": "sentinelti/models/url_classifier_xgb.joblib"
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

Example response:

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
        "trained_at": "2026-05-18T03:55:05Z",
        "dataset_name": "kaggle",
        "dataset_source": {
          "use_real_data": true
        },
        "feature_version": "v2",
        "threshold": 0.75,
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
        "artifact_path": "sentinelti/models/url_classifier_xgb.joblib"
      }
    },
    {
      "schema_version": "1.2",
      "url": "https://phishy.example/login",
      "label": 1,
      "prob_malicious": 0.91,
      "threshold": 0.75,
      "heuristic": {
        "score": 0.82,
        "reasons": [
          "Suspicious login keyword",
          "Nested redirect parameter"
        ]
      },
      "final_label": "malicious",
      "risk": "high",
      "reasons": [
        "Model score above threshold",
        "Multiple phishing indicators"
      ],
      "explanation": {
        "summary": "This URL looks likely malicious and should be treated as unsafe.",
        "why_flagged": "The machine-learning model assigned a very high malicious probability.",
        "user_action": "Do not open the link or enter credentials.",
        "technical_notes": [
          "Model score above threshold",
          "Multiple phishing indicators"
        ],
        "risk": "high",
        "final_label": "malicious"
      },
      "model_meta": {
        "artifact_version": "1.0",
        "model_type": "xgb",
        "trained_at": "2026-05-18T03:55:05Z",
        "dataset_name": "kaggle",
        "dataset_source": {
          "use_real_data": true
        },
        "feature_version": "v2",
        "threshold": 0.75,
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
        "artifact_path": "sentinelti/models/url_classifier_xgb.joblib"
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

## Rate limiting and auth

Protected endpoints require a valid `X-API-KEY` header and are rate-limited by client IP in the application layer. The API also returns rate-limit headers such as `X-RateLimit-Limit`, `X-RateLimit-Remaining`, and `X-RateLimit-Reset` on protected requests.[web:592]

## Core response fields

SentinelTI uses a few core fields consistently across scoring responses:

- `label`: raw ML prediction, where `0` means benign and `1` means malicious
- `prob_malicious`: model-estimated malicious probability between 0 and 1
- `threshold`: configured malicious threshold used by the model layer
- `heuristic.score`: numeric score from rule-based URL checks
- `heuristic.reasons`: list of triggered heuristic explanations
- `final_label`: final combined decision, one of `benign`, `suspicious`, or `malicious`
- `risk`: human-friendly risk bucket, one of `low`, `medium`, or `high`
- `reasons`: top-level explanation list
- `explanation`: structured end-user explanation payload
- `model_meta`: model artifact and training metadata returned by the API

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
   - The CLI and FastAPI API both rely on the same scoring logic, which helps keep outputs consistent across interfaces.[web:526]

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

Training outputs are saved under `sentinelti/models/`. Depending on your current training and loading flow, artifacts may include model-specific files and metadata used by the API’s `model_meta` response payload.[web:596]

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
├── api.py
├── cli.py
├── db.py
├── heuristics.py
├── scoring.py
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

- `sentinelti/api.py` — FastAPI application and response models
- `sentinelti/cli.py` — CLI entry point
- `sentinelti/db.py` — SQLite initialization and connection logic
- `sentinelti/heuristics.py` — heuristic URL analysis
- `sentinelti/scoring.py` — central score enrichment logic
- `sentinelti/feeds/urlhaus.py` — URLhaus ingestion helpers
- `sentinelti/ml/` — training, prediction, and model-service utilities
- `tests/` — pytest suite
- `docs/` — notes, metrics, and supporting documentation

## Testing

Run the test suite with:

```bash
python -m pytest
```

Run a focused file:

```bash
python -m pytest tests/test_api.py -q
```

## Author

SentinelTI is developed and maintained by:

- **Dong Quan Tran (Johnny)**
- Role: Owner / Collaborator
- Email: [dxt9721@mavs.uta.edu](mailto:dxt9721@mavs.uta.edu)
- GitHub: [dong-quan-tran](https://github.com/dong-quan-tran)