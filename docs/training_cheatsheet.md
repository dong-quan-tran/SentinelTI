# SentinelTI Training Cheatsheet

This cheatsheet is a quick reference for training, validating, and checking SentinelTI URL-classification models.

## Purpose

Use this guide when you want to:

- train a new model artifact
- compare XGBoost vs Logistic Regression
- switch data sources
- verify that metadata and scoring still work after retraining

## Prerequisites

- Python 3.10+
- Virtual environment activated
- Dependencies installed from `requirements.txt`
- A labeled CSV for Kaggle-style training, usually `data/urldata.csv`

Expected CSV columns:

- `url`
- `label`

Typical label values:

- `benign`
- `malicious`

## Setup

### Create and activate a virtual environment

Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Linux/macOS:

```bash
python -m venv .venv
source .venv/bin/activate
```

### Install dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

## Common training commands

### Train XGBoost with Kaggle CSV

```bash
python -m sentinelti.ml.train --model xgb --source kaggle --csv-path data/urldata.csv
```

### Train Logistic Regression with Kaggle CSV

```bash
python -m sentinelti.ml.train --model logreg --source kaggle --csv-path data/urldata.csv
```

### Train XGBoost with URLhaus malicious data plus benign Kaggle data

```bash
python -m sentinelti.ml.train --model xgb --source urlhaus --csv-path data/urldata.csv
```

### Train with the built-in dummy dataset

```bash
python -m sentinelti.ml.train --model logreg --source dummy
```

## When to use which option

### `--model xgb`

Use when you want the strongest general nonlinear classifier and feature interaction handling.

### `--model logreg`

Use when you want a simpler baseline model that is easier to interpret and compare.

### `--source kaggle`

Use when training directly from a labeled CSV dataset.

### `--source urlhaus`

Use when you want to combine malicious URLhaus-style signal with benign examples from your CSV.

### `--source dummy`

Use only for smoke tests, development, or quick pipeline checks.

## Expected outputs

After training, check these locations:

- `sentinelti/models/` for trained artifacts
- `docs/model_metrics/` for saved evaluation summaries, if enabled by your training flow

Typical useful outputs include:

- model artifact files such as `.joblib`
- metadata consumed by the API
- evaluation summaries or reports

## Fast sanity checks after training

### 1. Confirm the artifact exists

PowerShell:

```powershell
Get-ChildItem sentinelti/models
```

Linux/macOS:

```bash
ls -la sentinelti/models
```

### 2. Start the API

```bash
python -m uvicorn sentinelti.api.app:app --host 0.0.0.0 --port 8000 --reload
```

### 3. Check model metadata

```bash
curl -X GET "http://localhost:8000/model-info" \
  -H "X-API-KEY: change-me"
```

Things to verify in the response:

- `model_type`
- `dataset_name`
- `trained_at`
- `threshold`
- `threshold_source`
- `recommended_threshold`
- `top_features`
- `training_notes`

### 4. Score a safe-looking URL

```bash
curl -X POST "http://localhost:8000/score-url" \
  -H "Content-Type: application/json" \
  -H "X-API-KEY: change-me" \
  -d '{"url": "https://example.com"}'
```

### 5. Score a suspicious-looking URL

```bash
curl -X POST "http://localhost:8000/score-url" \
  -H "Content-Type: application/json" \
  -H "X-API-KEY: change-me" \
  -d '{"url": "http://192.168.0.1/login/verify/account"}'
```

### 6. Run tests

```bash
python -m pytest -q
```

Focused checks:

```bash
python -m pytest tests/test_api.py -q
python -m pytest tests/test_model_metadata_service.py -q
python -m pytest tests/test_api_ai.py -q
```

## How to read the metadata

### Effective vs advisory threshold

- `threshold` is the effective threshold currently used by the app for live decisions.
- `threshold_source` tells you where that live value came from.
- `recommended_threshold` is advisory metadata stored with the artifact.
- `recommended_threshold_source` tells you where that advisory value came from.

### Training notes

Look at `training_notes` for useful warnings, including convergence warnings for simpler linear models.

### Top features

`top_features` helps confirm whether the trained model is reacting to intuitive URL characteristics such as URL length, IP-host usage, suspicious path structure, or punctuation-heavy domains.

## Troubleshooting

### No model found at runtime

Check that the artifact was saved under `sentinelti/models/` and that the application is loading the expected file.

### Metadata missing fields

Partial metadata may still load successfully. Missing lists may default to empty arrays, and missing metrics may remain `null`.

### Logistic Regression convergence warning

If training notes mention convergence issues, consider increasing `max_iter`, reviewing feature scaling, or treating the model as a baseline rather than the preferred production candidate.

### Results look too optimistic or too noisy

Check:

- label balance in training data
- threshold values
- train/test split quality
- whether benign and malicious examples are realistic
- whether URLhaus-derived malicious samples changed recently

## Suggested retraining workflow

1. Update or verify the dataset.
2. Train `logreg` as a baseline.
3. Train `xgb` as the stronger candidate.
4. Compare metrics and feature importance.
5. Validate `/model-info` and `/score-url` locally.
6. Run the test suite.
7. Keep the better artifact and document the training date, data source, and threshold behavior.

## Handy commands block

```bash
python -m sentinelti.ml.train --model logreg --source kaggle --csv-path data/urldata.csv
python -m sentinelti.ml.train --model xgb --source kaggle --csv-path data/urldata.csv
python -m sentinelti.ml.train --model xgb --source urlhaus --csv-path data/urldata.csv
python -m uvicorn sentinelti.api.app:app --host 0.0.0.0 --port 8000 --reload
python -m pytest -q
```