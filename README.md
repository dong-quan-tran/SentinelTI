# SentinelTI

SentinelTI is a Python-based URL threat scoring tool. It ingests threat intelligence feeds (currently URLhaus), stores indicators in SQLite, and scores URLs using a trained ML model plus heuristic rules. You can interact with SentinelTi via a CLI or a FastAPI HTTP API to classify URLs as benign, suspicious, or malicious with human-readable explanations.

## Quick start

### Requirements

- Python 3.10+
- Git
- Recommended: virtual environment for dependencies
- Trained model file at `sentinelti/models/url_classifier.joblib` (or train one; see “Training the model” below)

### 1. Clone the repository

```bash
git clone https://github.com/dong-quan-tran/SentinelTI.git
cd SentinelTI
```

### 2. Create and activate a virtual environment

On Windows (PowerShell):

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

On Windows (cmd):

```cmd
python -m venv .venv
.\.venv\Scripts\activate.bat
```

On Linux/macOS:

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

CLI:

```bash
python -m sentinelti.cli --help
```

API: see **HTTP API usage** below for running the FastAPI server.


## CLI usage

SentinelTi ships with a CLI for initializing the database, ingesting threat intel, and scoring URLs.

### Initialize the database

```bash
python -m sentinelti.cli init
```

This creates the local SQLite database used to store URLhaus indicators.

### Ingest URLhaus feed

```bash
python -m sentinelti.cli ingest urlhaus
```

This downloads the recent URLhaus feed and upserts malicious URL indicators into the database.

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

Each result includes:

- `url`
- `label` (raw ML label: `0` benign, `1` malicious)
- `prob_malicious` (model probability the URL is malicious)
- `heuristic` (score and reasons from rule-based analysis)
- `final_label` (`benign` / `suspicious` / `malicious`)
- `risk` (`low` / `medium` / `high`)
- `reasons` (human-readable explanations)

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

This returns a list of enriched results, one per URL, with the same fields as above.

## HTTP API usage

SentinelTi exposes a FastAPI HTTP API that reuses the same `enrich_score(url)` logic as the CLI.

### Environment variable

Set an API key for protected endpoints:

```bash
# Linux/macOS
export SENTINELTI_API_KEY="your-secret-key"

# PowerShell
$env:SENTINELTI_API_KEY="your-secret-key"
```

If not set, the app falls back to a default `"change-me"` key (for local dev only).

### Start the API server

From the project root:

```bash
uvicorn sentinelti.api:app --host 0.0.0.0 --port 8000 --reload
```

- Base URL: `http://localhost:8000`
- Docs (Swagger UI): `http://localhost:8000/docs`

### `GET /health`

Simple health check, no auth required.

```json
{
  "status": "ok",
  "version": "0.1.0"
}
```

Use this for local or external uptime checks.

### `POST /score-url`

Score a single URL.

- Auth: requires `X-API-KEY` header with a valid key.
- Request body:

```json
{
  "url": "https://example.com"
}
```

Example `curl` (Windows-friendly quoting):

```bash
curl -X POST "http://localhost:8000/score-url" ^
  -H "Content-Type: application/json" ^
  -H "X-API-KEY: your-secret-key" ^
  -d "{\"url\": \"https://example.com\"}"
```

Response (simplified):

```json
{
  "schema_version": "1.0",
  "url": "https://example.com",
  "label": 0,
  "prob_malicious": 0.02,
  "heuristic": {
    "score": 0.0,
    "reasons": []
  },
  "final_label": "benign",
  "risk": "low",
  "reasons": [
    "No strong malicious indicators detected by model or heuristics."
  ],
  "meta": {
    "model": "xgb",
    "source": "kaggle+urlhaus"
  }
}
```

Key fields:

- `label`: raw model output (`0` benign, `1` malicious)
- `prob_malicious`: model probability the URL is malicious
- `heuristic`: structural URL checks (score + reasons)
- `final_label`: combined decision (`"benign" | "suspicious" | "malicious"`)
- `risk`: human-friendly risk bucket (`"low" | "medium" | "high"`)
- `reasons`: explanation list tying together model and heuristics

### `POST /score-urls`

Batch scoring for multiple URLs.

- Auth: requires `X-API-KEY`.
- Request body:

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
curl -X POST "http://localhost:8000/score-urls" ^
  -H "Content-Type: application/json" ^
  -H "X-API-KEY: your-secret-key" ^
  -d "{\"urls\": [\"https://example.com\", \"https://phishy.example/login\"]}"
```

Response:

```json
{
  "results": [
    { /* ScoreResponse for first URL */ },
    { /* ScoreResponse for second URL */ }
  ]
}
```

Each item in `results` has the same shape as the `/score-url` response.

## Concepts

SentinelTi responses use a few core fields consistently:

- `label` – raw ML prediction (`0` = benign, `1` = malicious).
- `prob_malicious` – model probability that the URL is malicious (between 0 and 1).
- `heuristic.score` – numeric score from rule-based checks (IP host, suspicious tokens, TLDs, etc.); higher means more suspicious.
- `heuristic.reasons` – short text fragments describing which heuristic rules fired.
- `final_label` – combined decision from ML + heuristics: `"benign"`, `"suspicious"`, or `"malicious"`.
- `risk` – human-friendly risk bucket derived from `final_label` and scores: `"low"`, `"medium"`, or `"high"`.
- `reasons` – high-level explanation list summarizing why the URL was classified that way (model confidence + key heuristic indicators).


## How it works (high level)

SentinelTi combines a trained ML classifier with rule-based heuristics to decide whether a URL is benign, suspicious, or malicious.

1. **Threat intel ingestion (URLhaus)**  
   - SentinelTi ingests recent malicious URL data from the URLhaus feed and stores it in a local SQLite database.  
   - The database tracks indicators (URLs, timestamps, tags, etc.) that can be used for model training, updating, and analysis.

2. **Machine learning URL classifier**  
   - A Python-based ML model is trained to classify URLs as benign or malicious using labeled datasets (e.g., Kaggle benign URLs + URLhaus malicious URLs).  
   - The model is saved to disk (for example, at `sentinelti/models/url_classifier.joblib`) and loaded by a small service layer that exposes a `score_url(url)` function returning `url`, `label`, and `prob_malicious`.

3. **Heuristic analysis layer**  
   - On top of the ML model, SentinelTi applies hand-crafted heuristics that look for patterns common in phishing and malware URLs, such as:
     - Raw IP addresses used as hosts.  
     - `@` in the authority part of the URL.  
     - Suspicious tokens in the path or query (like `login`, `verify`, `account`, `paypal`, `payment`, etc.).  
     - Uncommon or abuse-heavy TLDs (for example, `.xyz`, `.top`, `.club`, `.click`).  
     - Unusually long domains or very deep paths.  
   - Each heuristic contributes to a numeric heuristic score and a list of human-readable reasons explaining why the URL looks risky.

4. **Central scoring and enrichment**  
   - A central function `enrich_score(url)` combines:
     - ML output (`label`, `prob_malicious`), and  
     - heuristic score and reasons.  
   - It then derives:
     - `final_label`: `"benign"`, `"suspicious"`, or `"malicious"`,  
     - `risk`: `"low"`, `"medium"`, or `"high"`,  
     - a unified list of `reasons` suitable for CLI/API responses.  
   - This enriched result is the single source of truth used by both the CLI and the HTTP API.

5. **Interfaces (CLI and API)**  
   - **CLI**: commands to initialize the DB, ingest URLhaus, and score single or multiple URLs in human-readable or JSON formats.  
   - **FastAPI HTTP API**: endpoints like `/health`, `/score-url`, and `/score-urls` that reuse `enrich_score(url)` for programmatic access.

   ## Training the model

SentinelTi includes an ML pipeline under `sentinelti/ml/` that trains a URL classifier from either a Kaggle dataset or a combination of URLhaus + benign URLs.

### Prerequisites

- Dependencies installed:

```bash
pip install -r requirements.txt
```

- A labeled URL CSV (for example, Kaggle “malicious and benign URLs”) placed at:

```text
data/urldata.csv
```

Required columns:

- `url`
- `label` with values `benign` or `malicious`

### Training commands

Training is controlled via `--model` and `--source` flags:

- Train **XGBoost** on Kaggle:

```bash
python -m sentinelti.ml.train --model xgb --source kaggle --csv-path data/urldata.csv
```

- Train **Logistic Regression** on Kaggle:

```bash
python -m sentinelti.ml.train --model logreg --source kaggle --csv-path data/urldata.csv
```

- Train **XGBoost** on URLhaus malicious + Kaggle benign:

```bash
python -m sentinelti.ml.train --model xgb --source urlhaus --csv-path data/urldata.csv
```

- Use the small built-in dummy dataset (for quick tests):

```bash
python -m sentinelti.ml.train --model logreg --source dummy
```

Model artifacts are saved to:

```text
sentinelti/models/url_classifier.joblib
```

These are loaded by the SentinelTi ML scoring service (`score_url`) and the central `enrich_score(url)` logic.

### Model metrics

Each training run saves metrics to `docs/model_metrics/`:

- Filename format: `url_model_<model>_<source>_<timestamp>.json`
- Contains:
  - Model type (`logreg` or `xgb`)
  - Data source (`kaggle`, `urlhaus`, or `dummy`)
  - Train/test class counts
  - Full `classification_report` as a JSON dict

***

## Project structure

High-level layout of the repository:

- `sentinelti/`
  - `cli.py` – CLI entry point (init, ingest, `score-url`, `score-urls`).
  - `heuristics.py` – rule-based URL analysis (IP hosts, suspicious tokens, TLDs, etc.).
  - `scoring.py` – central `enrich_score(url)` that combines ML and heuristics into a final result.
  - `ml/` – ML model loading and `score_url()` service plus training scripts.
  - `db.py` – SQLite initialization and connection logic.
  - `feeds/urlhaus.py` – URLhaus ingestion utilities.
  - `api.py` – FastAPI application exposing `/health`, `/score-url`, and `/score-urls`.
- `tests/` – pytest test suite.
- `docs/` – progress logs, design notes, screenshots, and model metrics.

Author
SentinelTi is developed and maintained by:

Name: Dong Quan Tran (Johnny)

Role / Affiliation: Owner, Collaborator

Contact (optional): dxt9721@mavs.uta.edu (University of Texas at Arlington)

GitHub: https://github.com/dong-quan-tran