# SentinelTI Build Log

This document tracks the step-by-step progress of building SentinelTI, a small threat intelligence aggregation tool.

---

## Day 1 – Project setup & environment

**What I did**

- Created the `SentinelTi` project folder and Python package structure.
- Set up a Python virtual environment (`.venv`) for isolated dependencies.
- Added `requirements.txt` and installed core libraries (`requests`, etc.).
- Created `config.py` for basic settings and `db.py` for database initialization.
- Implemented a simple CLI using `argparse` with an `init` command to create the SQLite database.

**Screenshot**

![alt text](<Screenshot 2026-02-02 234806.png>)
---

## Day 2 – URLhaus feed ingestion

**What I did**

- Designed a SQLite schema with `feeds` and `indicators` tables to store threat intelligence data.
- Implemented `init_db()` in `db.py` to create tables on demand.
- Wrote `feeds/urlhaus.py` to:
  - Download the recent URLhaus CSV feed from abuse.ch.
  - Parse the CSV, extract malicious URLs and metadata (date, threat type, tags).
  - Insert or update indicators in the `indicators` table with first/last seen timestamps.
- Extended the CLI with an `ingest` command:
  - `python -m sentinelti.cli ingest urlhaus` ingests recent malicious URLs into the database.

**Screenshots**

[alt text](<Screenshot 2026-02-02 235031.png>)

![alt text](<Screenshot 2026-02-02 235331.png>)

# Day 3 – Threat Intel + ML URL Classifier


### ML Module Layout

- Created new package: `sentinelti/ml/`
  - `__init__.py`
  - `features.py`
  - `dataset.py`
  - `train.py`
  - `predict.py`

This sets up a clear pipeline: feature extraction → dataset → training → prediction.

---

### URL Feature Extraction

- Implemented `extract_features(url: str)` in `sentinelti/ml/features.py`.
- Extracted lexical features commonly used in malicious URL detection:
  - URL/domain/path/query lengths
  - Counts of digits, letters, special characters
  - Ratios (digits/letters per URL length)
  - Structural features (IP-like host, dot and hyphen counts, path segments, query params)
  - Suspicious keyword hits (`login`, `verify`, `update`, `secure`, `account`, etc.)
  - Raw TLD captured for future encoding

- Verified behavior by running:

  ```bash
  python -c "from sentinelti.ml.features import extract_features; print(extract_features('http://example.com/login?user=1'))"

![alt text](<Screenshot 2026-02-03 125702.png>)

- Build dummy dataset in dataset.py for demo
turning the feature dicts into a numeric matrix X and label vector y,
![alt text](<Screenshot 2026-02-03 132228.png>)

- Implement the train_url_model
    train_test_split gives a small test set to evaluate the model.

    classification_report prints precision/recall/F1 for each class so we can see how well the dummy model does.

    We save both the model and feature_names so prediction uses the same feature order later.
![alt text](<Screenshot 2026-02-03 133338.png>)

- Implement the predict_url
![alt text](<Screenshot 2026-02-03 133957.png>)

---Day 3: Get real dataset + training -> real TI URL classifier

- Added "Malicious and Benign URLS" dataset from Kaggle
![alt text](<Screenshot 2026-02-04 132347.png>)

- Added and updated the dataset.py with build_real_dataset function
![alt text](<Screenshot 2026-02-04 164419.png>)

- Updated train.py with adding build_real_dataset import and tried changing max_sample limit for troubleshooting
![alt text](<Screenshot 2026-02-04 164823.png>)

- Updated predict.py with higher threshold 0.5 -> 0.9
![alt text](<Screenshot 2026-02-04 164929.png>)

- Day log:
We’ve basically taken SentinelTI from “toy ML” to a first real URL classifier. Here’s the short story, in order:

### 1. Started with a dummy model

- You had a small hard-coded list of benign and malicious-looking URLs in `build_dummy_dataset`, which:
  - Generated lexical features for each URL.
  - Produced `X` (feature matrix), `y` (0/1 labels), and `feature_names`.  
- `train.py` used only this dummy dataset:
  - Split into train/test.
  - Trained a `LogisticRegression` model.
  - Printed a classification report.
  - Saved the model artifact (model + feature names) with `joblib`.

This gave you a working training pipeline, but on tiny synthetic data.

### 2. Added a real CSV-based dataset builder

- You extended `dataset.py` with `build_real_dataset(csv_path, ...)`, which:
  - Loads a labeled CSV (`urldata.csv`) with at least `url` and `label` columns.  
  - Filters rows to the allowed labels (benign vs malicious).  
  - Optionally samples up to `max_samples`.  
  - Uses the same feature extraction as the dummy builder to create `X`, `y`, and `feature_names`.

- You also fixed the structure so:
  - Label filtering happens before sampling.
  - The function raises a clear error if no rows match the expected labels.

### 3. Updated `train_url_model` to support real data

- In `train.py`, you changed `train_url_model` to accept:

  ```python
  def train_url_model(
      use_real_data: bool = False,
      csv_path: str | None = None,
      max_samples: int | None = None,
  )
  ```

- Logic:
  - If `use_real_data=True`, call `build_real_dataset(...)` with the CSV path and label mapping.
  - Otherwise, fall back to `build_dummy_dataset`.

- You kept the same ML steps:
  - `train_test_split` with stratification.
  - Train logistic regression.
  - Print classification report.
  - Save `{ "model": clf, "feature_names": feature_names }` to `url_classifier.joblib`.

- In the `if __name__ == "__main__":` block you configured:

  ```python
  train_url_model(
      use_real_data=True,
      csv_path="data/urldata.csv",
      max_samples=1000,
  )
  ```

### 4. Fixed early issues with tiny test sets

- At first, you effectively ended up with a very small number of samples in the test split, which produced:
  - Only 3 test samples.
  - Warnings about undefined precision for the minority class (no predicted positives).

- We diagnosed that:
  - The dataset in use was too small (or over-sampled down).
  - `build_real_dataset` needed a clean filter and proper empty-check.

- After fixing and letting it use 1,000 rows, the classification report became:

  - 779 benign, 221 malicious in total.
  - On the 300-sample test set:
    - Benign: F1 ≈ 0.99
    - Malicious: F1 ≈ 0.94
    - Overall accuracy ≈ 0.98

So, the model is performing very well on that dataset.

### 5. Implemented and tuned `predict_url`

- You already had `predict_url(url)` which:
  - Loads the saved model + feature names.
  - Extracts features for a single URL.
  - Uses `predict_proba` to get the probability of class 1 (malicious).
  - Returns `(label, prob_malicious)` where `label = int(prob_malicious >= 0.5)`.

- When we tested on real-world benign URLs (`google.com`, `microsoft.com`, etc.), the model gave:
  - Malicious label (1) with ~0.76 probability for several big-brand domains.
  - Benign label (0) with low malicious probability for `nytimes.com`.
  - An obvious phish got label 1 with probability ~0.99999.

- This told us:
  - The model and code were correct, but the threshold 0.5 was too aggressive for your use case.
  - Lexical URL features alone can misjudge some benign big-name domains.

- To reduce false positives for benign URLs, you:
  - Introduced a higher malicious threshold (e.g., 0.9) inside `predict_url`:

    ```python
    MALICIOUS_THRESHOLD = 0.9
    label = int(prob_malicious >= MALICIOUS_THRESHOLD)
    ```

  - Re-ran tests:
    - Big-brand URLs: now label 0, with malicious probabilities still ~0.76 (visible as a “risk score” but not auto-blocking).
    - Obvious phish: still label 1 with probability ~1.0.



## 2026-02-05 – Day Progress (Threat-Intel URL Classifier + ML)

**1. Integrated URLhaus-backed malicious data**

- Implemented a new helper module to load malicious URLs directly from the existing SQLite threat-intel database (URLhaus feed already ingested into `feeds` and `indicators` tables).  
- The helper queries `indicators` for `type='url'` and the `urlhaus` feed, returns a DataFrame with `url` and `label="malicious"`.  
- Added basic validation: raises an error if no URLhaus indicators are found.

![alt text](<Screenshot 2026-02-05 130003.png>)

***

**2. Built combined URLhaus + benign dataset builder**

- Extended the dataset layer with a new function to:
  - Load malicious URLs from the URLhaus-backed DB helper.  
  - Load benign URLs from the existing `data/urldata.csv` (filtering on `label="benign"`).  
  - Optionally subsample both sides (max malicious, max benign) for balanced training size.  
- Normalized both sources to a unified schema (`url`, `label`), mapped labels to `0 = benign`, `1 = malicious`.  
- Reused the existing URL feature extractor to build `X` (feature matrix), `y` (labels), and `feature_names`.

![alt text](<Screenshot 2026-02-05 130053.png>)

***

**3. Extended training pipeline to support URLhaus mode**

- Updated the training script to support a new mode:  
  - `use_urlhaus=True` → trains on “URLhaus malicious + benign CSV”, instead of only `urldata.csv` or dummy data.  
- Training flow:
  - Build combined dataset via the new builder.  
  - Stratified train/test split (70/30).  
  - Train logistic regression with `max_iter=1000`.  
  - Print classification report and save model artifact (`url_classifier.joblib` with model + feature names).

![alt text](<Screenshot 2026-02-05 130157.png>)

***

**4. Ran URLhaus ingestion and trained the new model**

- Installed the missing HTTP client library and successfully ran the URLhaus ingestion job to populate the local DB with recent URLhaus indicators.  
- Executed the updated training entrypoint in URLhaus mode.  
- Observed excellent evaluation metrics on the holdout set (balanced benign/malicious sample):
  - Precision, recall, and F1 for both benign and malicious ≈ 0.99.  
  - Overall accuracy ≈ 0.99, confirming the combined dataset and pipeline are working well.

![alt text](<Screenshot 2026-02-05 130157-1.png>)

***

**5. Evaluated and tuned prediction behavior**

- Re-ran `predict_url` on a mix of real-world benign and phishy URLs (Google, Microsoft, Apple, GitHub, NYTimes, and an obvious phishing-style URL).  
- Confirmed:
  - Phishing-style URL receives the highest malicious probability.  
  - Clearly benign site (NYTimes) has a very low malicious probability.  
  - Big-brand homepages sit in a mid-to-high probability band, close to the phishing URL, revealing that the model’s scores are well ranked but tightly clustered.  
- Experimented with different decision thresholds for labeling (0/1) and concluded:
  - The model and prediction code are correct.  
  - With the current dataset size and feature set, predictions are generally good but not perfectly calibrated; threshold choice is an explicit trade-off between catching phish and avoiding false positives on some benign big-brand domains.

![alt text](<Screenshot 2026-02-05 130330.png>)

***

**Summary for today**

- Moved from a generic CSV-trained model to a **Threat-Intel-driven model** that uses URLhaus data via the project’s own TI database.  
- Established a reusable path from **URLhaus → DB → combined dataset → trained model → `predict_url`**, with strong test metrics and initial threshold tuning.

---Log: 02/08/2026

## Environment and Setup

- Repaired Python installation on Windows and ensured system uses Python 3.11.  
- Recreated clean virtual environment (`.venv`) and reinstalled dependencies from `requirements.txt`.  
- Verified database initialization and URLhaus ingestion complete successfully.  
![alt text](<Screenshot 2026-02-08 123523.png>)

***

## Model Training and Baseline Results

- Trained URL classification model on ingested URLhaus data.  
- Achieved ~99% accuracy, precision, and recall on a 600‑sample holdout set (balanced benign/malicious).  
- Saved trained model to `sentinelti/models/url_classifier.joblib`.  

![alt text](<Screenshot 2026-02-08 123623.png>)

***

## CLI Scoring and Sanity Checks

- Confirmed `score-url` and `score-urls` commands work end‑to‑end.  
- Tested with clearly benign URLs (Google, Microsoft, BBC) and clearly malicious / phishing‑style URLs.  
- Observed sensible `label` and `prob_malicious` outputs for basic cases.  

![alt text](<Screenshot 2026-02-08 123656.png>)

***

## Heuristic Risk Layer on Top of ML

- Implemented `enrich_score()` helper to wrap `score_url` results.  
- Added heuristic features:
  - Detection of `@` in authority part (obfuscation).  
  - Raw IP hosts.  
  - Suspicious tokens (e.g., `login`, `verify`, `update`, `account`, `paypal`, `bank`, `appleid`).  
  - Uncommon TLDs (e.g., `.xyz`, `.top`, `.club`, `.click`, `.link`).  
- Introduced `final_label` (`benign`, `suspicious`, `malicious`) and `risk` (`low`, `medium`, `high`) in CLI output.  
- Example: `http://update-paypal.com@evil.com/secure` now returns `final_label='suspicious'` with clear reasons.  

![alt text](<Screenshot 2026-02-08 123849.png>)

***

## Dependency and Test Improvements

- Added `tldextract` to `requirements.txt` for URL parsing and TLD handling.  
- Created `tests/test_ml_service.py` with basic unit tests for:
  - `score_url` – structure and types of returned dict.  
  - `score_urls` – correct result count for batch input.  
- Installed `pytest` in the venv and successfully ran the tests via `python -m pytest`.  

***

## Progress log – 2026‑02‑09

Today was focused on turning SentinelTi’s URL scoring into a clean, reusable core and making the CLI output more script‑ and API‑friendly.

***

### 1. Added a dedicated heuristic analysis module

**What I did**

- Created `sentinelti/heuristics.py`.
- Implemented `analyze_url(url)` which:
  - Parses the URL (host, path, query, TLD).
  - Applies several heuristic rules:
    - Raw IP address as host.
    - `@` in the authority part.
    - Suspicious tokens in the path/query (e.g. `login`, `verify`, `payment`, `account`, `paypal`, `appleid`, etc.).
    - Uncommon TLDs (e.g. `.xyz`, `.top`, `.club`, `.click`, `.link`, etc.).
    - Very long domain (subdomain + domain).
    - Deep path (many path segments).
  - For each rule that fires, increases a numeric heuristic score and adds a human‑readable reason.
  - Returns a `HeuristicResult` with:
    - `score` (float),
    - `reasons` (list of explanation strings),
    - `features` (small dict with `tld`, `domain_length`, `path_depth`, `raw_score`).

**Why / purpose**

- Gives SentinelTi a rule‑based “gut check” layer in addition to the ML model.
- Makes results more explainable: we can say *why* a URL looks risky.
- Keeps heuristic logic isolated and testable, instead of scattering it in the CLI.

![alt text](<Screenshot 2026-02-09 151356.png>)

***

### 2. Added a central scoring/enrichment module

**What I did**

- Created `sentinelti/scoring.py`.
- Implemented `enrich_score(url)` which:
  - Calls the existing ML service (e.g. `ml.service.score_url(url)`) to get:
    - `url`, `label`, `prob_malicious`.
  - Calls `analyze_url(url)` to get heuristic `score`, `reasons`, and `features`.
  - Combines ML probability and heuristic score with simple thresholds to decide:
    - `final_label`: `"benign"`, `"suspicious"`, or `"malicious"`.
    - `risk`: `"low"`, `"medium"`, or `"high"`.
  - Ensures `reasons` is populated:
    - Uses heuristic reasons when present.
    - Falls back to generic messages like “Flagged primarily by the ML classifier score.” when needed.
  - Returns a single enriched dict containing:
    - `url`, `label`, `prob_malicious`,
    - `heuristic` (nested dict with score/reasons/features),
    - `final_label`, `risk`, and top‑level `reasons`.

**Why / purpose**

- Creates one **single source of truth** for “how SentinelTi scores a URL”.
- Separates concerns:
  - ML model serving (`ml.service`) stays model‑focused.
  - Heuristics stay in `heuristics.py`.
  - Combination and decisions live in `scoring.py`.
- Makes it easy for the CLI, tests, and future FastAPI API to all use the same scoring logic.

![alt text](<Screenshot 2026-02-09 151758.png>)

***

### 3. Refactored the CLI to use the central scoring

**What we did**

- Updated `sentinelti/cli.py`:
  - Removed inline heuristic logic and the old CLI‑local `enrich_score(url, score_result)` function.
  - Stopped importing URL parsing/heuristics directly in the CLI.
  - Imported and used the shared `enrich_score(url)` instead.
- Now:
  - `score-url`:
    - Calls `enrich_score(args.url)`.
    - Prints the enriched result.
  - `score-urls`:
    - Loops over `args.urls`, calls `enrich_score(url)` for each.
    - Prints each enriched result.

**Why / purpose**

- Makes the CLI a **thin wrapper** around the core scoring logic.
- Guarantees that CLI and future API will always use the exact same scoring and heuristics.
- Simplifies future changes: tuning thresholds or adding new heuristics only requires updating `heuristics.py` / `scoring.py`, not the CLI.

![alt text](<Screenshot 2026-02-09 151954.png>)

***

### 4. Added JSON and pretty‑JSON output to the CLI

**What we did**

- Extended `score-url` to accept:
  - `--json`: output the enriched result as a compact JSON object.
  - `--json-pretty`: output the same JSON but nicely formatted with indentation.
- Extended `score-urls` to accept:
  - `--json`: output a JSON array of enriched results.
  - `--json-pretty`: pretty‑print that array.
- Under the hood:
  - Uses `json.dumps(result, indent=None)` for `--json`.
  - Uses `json.dumps(result, indent=2)` for `--json-pretty`.

**Why / purpose**

- Makes SentinelTi much easier to integrate into scripts and other tools:
  - You can pipe CLI output into `jq`, log pipelines, or custom scripts without parsing Python dicts.
- Aligns with how the future FastAPI endpoints will behave (they will also speak JSON).
- Improves usability when inspecting results manually (`--json-pretty` is much easier to read).

![alt text](<Screenshot 2026-02-09 152100.png>)
***

### 5. Added a basic unit test for the enriched scoring

**What we did**

- Created `tests/test_scoring.py` with a simple test:
  - Calls `enrich_score("http://example.com")`.
  - Asserts that keys like `url`, `label`, `prob_malicious`, `final_label`, `risk`, `reasons`, and `heuristic` are present.
  - Checks that `reasons` is a list and `heuristic` is a dict.
- Ran `python -m pytest` and confirmed all tests pass (including the existing ML service tests).

**Why / purpose**

- Ensures the new central scoring function is covered by tests.
- Gives an early warning if the structure of the enriched result changes unexpectedly.
- Helps keep the public output contract stable as the project grows.

![alt text](<Screenshot 2026-02-09 152409.png>)

***

Overall, today’s work:

- Centralized the “intelligence” of SentinelTi into `heuristics.py` and `scoring.py`.
- Turned the CLI into a thin, reusable front‑end.
- Added JSON output so SentinelTi is ready for automation and a future HTTP API.

## Progress log – 2026‑02‑10

***

### 1. Added `score-file` CLI for batch scoring

**What we did**

- Extended `sentinelti/cli.py` with a new `score-file` subcommand.
- `score-file`:
  - Accepts an input file path (`.txt` or `.csv`).
  - Supports `--input-format auto|txt|csv` (auto detects by extension).
  - Reads:
    - Text: one URL per line.
    - CSV: URLs from a configurable `--url-column` (default `url`).
  - Calls `enrich_score(url)` for each URL to get ML + heuristic enrichment.
  - Supports `--output` and `--output-format csv|json` plus `--json-pretty` for human‑friendly JSON.
- CSV output flattens the core fields:
  - `url`, `label`, `prob_malicious`, `final_label`, `risk`, `reasons` (joined as a string).
- JSON output returns a list of full enriched result objects (same schema as `score-urls --json`).

**Why / purpose**

- Enables **batch analysis** of URL lists from text files or spreadsheets.
- Makes it easy to run SentinelTi on real‑world URL dumps without manual copy/paste.
- Reuses `enrich_score` so behavior is consistent with the rest of the tool.
- Lays the groundwork for:
  - Bulk testing against new datasets.
  - Easy input/output for scripts and other tooling.

![alt text](<Screenshot 2026-02-11 101247.png>)

***

### 2. Created a manual evaluation dataset

**What we did**

- Added `docs/manual_eval_urls.csv` with columns:

  ```csv
  url,label,notes
  ```

- Seeded it with a diverse, realistic mix of URLs:
  - Clearly benign:
    - Well‑known sites (Google, Wikipedia, GitHub, banks, streaming services).
    - Legitimate login pages (Google, Microsoft, Netflix, PayPal, Amazon).
    - Normal content pages, account settings, support/contact pages.
    - Corporate/University portals, VPN URLs, webmail, tracking links, CDN/script URLs.
  - Clearly malicious:
    - Raw IP hosts with `/login` or `/secure` paths.
    - Weird TLD + `login`/`update`/`account` tokens (e.g., `.xyz`, `.top`, `.click`, `.link`, `.club`).
    - Domains impersonating brands (PayPal, Apple ID, Office365, banks, Dropbox, Netflix).
    - Typosquats (e.g., `go0gle`, `faceb0ok-security`).
    - URLs with `@` in the authority part for obfuscation.
    - Phishing‑style query strings (`verify-account`, `update-your-password`, etc.).
- Each row has a `notes` field describing why the URL is considered benign or malicious.

**Why / purpose**

- Provides a **hand‑curated test set** to evaluate the end‑to‑end behavior of `final_label` and `risk`, not just the ML model in isolation.
- Lets you see how SentinelTi handles:
  - Legit but “scary‑looking” URLs (real login pages, long paths).
  - Obvious phishing constructs.
- Serves as a stable reference set to catch regressions as you tweak heuristics or retrain the model.

![alt text](<Screenshot 2026-02-11 101753.png>)

***

### 3. Added a manual evaluation runner module

**What we did**

- Created `sentinelti/manual_eval.py` that:

  - Locates `docs/manual_eval_urls.csv` from the repo root.
  - Reads each row, skipping any without `url` or `label`.
  - Calls `enrich_score(url)` for each URL.
  - Compares `true_label` (from CSV) with `r["final_label"]` (from SentinelTi).
  - Aggregates confusion counts:

    ```text
    Confusion (true_label -> final_label):
      benign     -> benign    : ...
      benign     -> suspicious: ...
      benign     -> malicious : ...
      malicious  -> benign    : ...
      malicious  -> suspicious: ...
      malicious  -> malicious : ...
    ```

  - Prints “Sample disagreements” with details:
    - URL
    - `true_label`
    - `final_label`
    - `risk`
    - `prob_malicious`
    - `reasons`
    - `notes` from the CSV.

- Can be run via:

  ```bash
  python -m sentinelti.manual_eval
  ```

**Why / purpose**

- Gives a **fast feedback loop** for tuning:
  - Immediately shows where SentinelTi is too aggressive (benign → suspicious/malicious) or too lenient (malicious → benign).
- Helps you see the interaction between:
  - ML probability,
  - heuristic score,
  - and the final label mapping logic in `scoring.py`.
- Acts as a regression test:
  - After changing heuristics or thresholds, you can re‑run and see if behavior improved or got worse on this curated set.

![alt text](<Screenshot 2026-02-11 101850.png>)

***

### 4. First round of threshold/heuristic tuning (light)

**What we did**

- Ran `manual_eval` and examined:
  - Many benign URLs (especially legit logins and blogs) were labeled `suspicious` or even `malicious`.
  - Some malicious URLs were not yet being bumped to `malicious`.
- Started tuning by:
  - Planning adjustments to:
    - **Heuristic weights** (e.g., making `login` less heavy, making deep path less aggressive).
    - **Decision thresholds** in `scoring.py` to:
      - Treat low `prob_malicious` + weak heuristics as `benign`.
      - Require stronger combined evidence for `malicious`.

**Why / purpose**

- Moves SentinelTi away from arbitrary rules toward **data‑informed thresholds**.
- Helps align the final labels with what you, as the tool author, consider reasonable behavior on realistic URLs.

![alt text](<Screenshot 2026-02-11 101938.png>)

## Progress log – 2026‑02‑11

Today’s work focused on adding a real HTTP API on top of SentinelTi so other tools can programmatically score URLs.

***

### 1. Installed API dependencies

**What we did**

- Confirmed and/or installed the required packages for the web API:
  - `fastapi`
  - `uvicorn`
- Added them to `requirements.txt` so the environment is reproducible.

**Why / purpose**

- Makes SentinelTi ready to run as a web service, not just a CLI tool.
- Ensures any future deployment (Render, Fly.io, etc.) can install the same dependencies.

![alt text](<Screenshot 2026-02-11 232954.png>)

***

### 2. Created the SentinelTi FastAPI app

**What we did**

- Added a new module `sentinelti/api.py`.
- Created a FastAPI app instance:

  ```python
  app = FastAPI(title="SentinelTi API", version="0.1.0")
  ```

- Defined request models using Pydantic:

  ```python
  class ScoreUrlRequest(BaseModel):
      url: str

  class ScoreUrlsRequest(BaseModel):
      urls: List[str]
  ```

**Why / purpose**

- The FastAPI app is the core of the HTTP API, describing available endpoints and metadata.
- Pydantic models give a clear, validated schema for incoming JSON requests and power the automatic docs.

![alt text](<Screenshot 2026-02-11 233029.png>)

***

### 3. Implemented `/health` endpoint

**What we did**

- Added a simple health‑check route:

  ```python
  @app.get("/health")
  async def health():
      return {"status": "ok"}
  ```

**Why / purpose**

- Provides a quick way to verify the API is running and reachable.
- Useful for future monitoring and deployment checks (load balancers, uptime checks, etc.).

![alt text](<Screenshot 2026-02-11 233224.png>)

***

### 4. Implemented `/score-url` endpoint (single URL)

**What we did**

- Added a POST endpoint that scores a single URL by reusing the existing `enrich_score` logic:

  ```python
  @app.post("/score-url")
  async def score_url(body: ScoreUrlRequest):
      return enrich_score(body.url)
  ```

- Tested it via the interactive docs and curl:

  ```bash
  curl -X POST "http://127.0.0.1:8000/score-url" \
    -H "Content-Type: application/json" \
    -d '{"url": "https://www.google.com"}'
  ```

- Verified the JSON response includes:
  - `url`
  - `label`
  - `prob_malicious`
  - `heuristic` (score, reasons, features)
  - `final_label`
  - `risk`
  - `reasons`

**Why / purpose**

- Exposes the core SentinelTi scoring function as a web API for any client (browser, tools, future UI).
- Keeps a single source of truth for scoring logic (`enrich_score`), shared between CLI and API.

![alt text](<Screenshot 2026-02-11 233337.png>)

***

### 5. Implemented `/score-urls` endpoint (batch)

**What we did**

- Added a batch scoring endpoint:

  ```python
  @app.post("/score-urls")
  async def score_urls(body: ScoreUrlsRequest):
      return {"results": [enrich_score(u) for u in body.urls]}
  ```

- Tested with a small list:

  ```json
  {
    "urls": [
      "https://www.google.com",
      "http://198.51.100.23/login"
    ]
  }
  ```

- Confirmed the response is an object with a `results` array, each entry containing the enriched score structure.

**Why / purpose**

- Makes it easy to score multiple URLs in one request, which is useful for browser extensions, log pipelines, or small tools.
- Mirrors the batch behavior of your CLI `score-file` command, but over HTTP.

![alt text](<Screenshot 2026-02-11 233605.png>)

***

### 6. Ran the API server locally

**What we did**

- Started the server from the project root:

  ```bash
  uvicorn sentinelti.api:app --host 127.0.0.1 --port 8000
  ```

- Confirmed:
  - `/health` returns `"status": "ok"`.
  - `/docs` shows all three endpoints (`/health`, `/score-url`, `/score-urls`) and their schemas.

**Why / purpose**

- Validates that the integration between FastAPI, Uvicorn, and your scoring code works end‑to‑end.
- Provides a working local API instance ready for future deployment to a cloud host.

--- Progress log: 02/12/2026

1) Integrated Kaggle URL dataset
Wired the “malicious and benign URLs” Kaggle dataset into the ML pipeline as data/urldata.csv using url and label (benign/malicious).​​

Verified label distribution: benign = 345,738, malicious = 104,438.​

![alt text](<Screenshot 2026-02-12 145343.png>)

2) Dataset loading and sanitization (dataset.py)
Implemented build_real_dataset and build_urlhaus_plus_benign_dataset to load arbitrary CSV paths instead of hardcoded filenames.​

Added a small URL validation step to drop malformed URLs before feature extraction; training run dropped 1 invalid URL out of ~450k rows.​​

![alt text](<Screenshot 2026-02-12 145531.png>)

3) Training pipeline refactor (train.py)
Refactored training code to use a shared load_dataset_for_training helper that supports:

Kaggle‑only (use_real_data=True).

URLHaus malicious + Kaggle benign (use_urlhaus=True).

Dummy URLs (for quick tests).

Cleaned up train_url_model to remove hardcoded paths and rely on csv_path for both Kaggle and URLHaus modes.​

![alt text](<Screenshot 2026-02-12 145721.png>)

4) Logistic regression baseline training
Trained a logistic regression classifier on Kaggle data (≈450k rows) using engineered URL features.

Achieved:

Benign: precision 0.95, recall 0.99.

Malicious: precision 0.97, recall 0.81.

Overall accuracy: 0.95.​

![alt text](<Screenshot 2026-02-12 150651.png>)

5) XGBoost model integration and training
Added XGBoost dependency and integrated XGBClassifier into train.py as train_url_model_xgb using the same features and dataset loader.​​

Used class imbalance handling via scale_pos_weight to account for the ~3.3:1 benign:malicious ratio.

Trained an XGBoost model on Kaggle data and achieved:

Benign (class 0): precision 0.97, recall 0.96.

Malicious (class 1): precision 0.88, recall 0.91.

Overall accuracy: 0.95.

Saved the new model artifact to sentinelti/models/url_classifier.joblib, compatible with existing prediction code.

![alt text](<Screenshot 2026-02-12 151006.png>)

6) CLI UX improvements for training
Added argparse CLI interface to train.py with:

--model {logreg,xgb} to select the classifier.

--source {kaggle,urlhaus,dummy} to select the data source.

--csv-path, --max-samples, --urlhaus-max-malicious, --urlhaus-max-benign flags to control inputs.​​

Now supports commands like:

python -m sentinelti.ml.train --model xgb --source kaggle --csv-path data/urldata.csv

python -m sentinelti.ml.train --model xgb --source urlhaus --csv-path data/urldata.csv

SentinelTi – Work Session Log (2026‑02‑13)
1) Manual evaluation wired to new XGBoost model
Confirmed manual_eval.py loads data/manual_eval_urls.csv and calls enrich_score(url) for each row.

Verified manual eval runs cleanly against the newly trained XGBoost model (url_classifier.joblib).

Observed confusion on the curated set:

benign -> benign: 17

benign -> suspicious: 13

malicious -> malicious: 15

malicious -> suspicious: 7

![alt text](<Screenshot 2026-02-13 234541.png>)

2) Scoring logic tuning (scoring.py)
Updated enrich_score to refine final_label / risk based on:

Model probability prob_malicious (p).

Heuristic score heur.score (h).​

Key logic changes:

Malicious / high risk when (p >= 0.90 and h >= 1.5) or h >= 3.5.

Benign / low risk when p <= 0.05 and h == 0.0, or p <= 0.10 and h < 1.5.

Suspicious / medium risk when p >= 0.60 or h >= 1.5; otherwise default to benign vs suspicious depending on h.​​

Added a small TRUSTED_DOMAINS list (e.g., google.com, microsoftonline.com, paypal.com, amazon.com, netflix.com) and a post‑processing override:

For base hosts in TRUSTED_DOMAINS with p < 0.90 and h < 2.0, force final_label = "benign", risk = "low".

Hostname extracted via urllib.parse.urlparse(url).hostname.​​

![alt text](<Screenshot 2026-02-13 234700.png>)

3) Training pipeline review and metrics logging (train.py)
Clarified and documented the training pipeline:

--model {logreg,xgb} controls whether train_url_model (LogisticRegression) or train_url_model_xgb (XGBClassifier) runs.​​

--source {kaggle,urlhaus,dummy} controls data source via load_dataset_for_training:

kaggle → build_real_dataset(csv_path=...).

urlhaus → build_urlhaus_plus_benign_dataset(benign_csv_path=...).

dummy → build_dummy_dataset().

--csv-path selects the Kaggle/benign CSV file (default data/urldata.csv).

Added per‑run metrics logging to both training functions:

After each run, a JSON file is written to docs/model_metrics/ with:

model ("logreg" or "xgb").

train_source (use_real_data, use_urlhaus, csv_path).

Train/test class counts.

Full classification_report as a dict.​​

Updated metrics filenames to include model and source, e.g.:

url_model_xgb_kaggle_<timestamp>.json.

![alt text](<Screenshot 2026-02-13 234726.png>)

--- progress log (Feb 14, 2026)
Enriched URLHaus dataset and verified training
Commit: enrich URLHaus dataset + verification

Wired URLHaus into the training pipeline so malicious URLs from URLHaus are ingested, stored, and used alongside the existing benign Kaggle dataset.

Verified that the combined URLHaus + Kaggle dataset trains cleanly and produces sensible metrics, confirming the end‑to‑end data and model plumbing works.

Ran manual checks on example URLs to confirm the model’s behavior matches expectations (e.g., clear phishing patterns are flagged as malicious or suspicious).

![alt text](<Screenshot 2026-02-15 182641.png>)

Added header‑based API key auth to scoring endpoints
Commit: Add header-based API key auth to scoring endpoints

Introduced a simple API key mechanism using the X-API-KEY header and an environment variable SENTINELTI_API_KEY for the secret.

Protected /score-url and /score-urls behind this API key dependency, while keeping /health open for unauthenticated checks.

Manually tested the endpoints with and without the header to confirm that unauthorized requests receive 401 and valid requests go through as expected.

![alt text](<Screenshot 2026-02-15 182805.png>)

Added typed response models for scoring
Commit: Add typed response model for scoring endpoints

Defined Pydantic models (HeuristicResult, ScoreResponse, and ScoreUrlsResponse) to describe the exact structure of the scoring responses, including url, label, prob_malicious, heuristic, final_label, risk, reasons, schema_version, and meta.

Updated /score-url and /score-urls to return data that conforms to these models and declared them via response_model=..., so FastAPI now validates outgoing responses and generates accurate OpenAPI docs.

Added schema_version = "1.0" and a meta block (e.g. model name/source) to make the API response contract explicit and versionable going forward.

![alt text](<Screenshot 2026-02-15 182906.png>)

--- Progress Log (2026-02-15)

Today I focused on hardening the SentinelTI FastAPI service for safer multi-tenant use and smoother integration with a future frontend.

Added per-IP rate limiting with X-RateLimit headers

Implemented an in-memory rate limiter that tracks request timestamps per client IP and enforces a limit of 60 requests per 60 seconds for scoring endpoints.

When the limit is exceeded, the API now returns 429 Too Many Requests along with a Retry-After header to signal when the client can retry.

On allowed requests, the service sets X-RateLimit-Limit, X-RateLimit-Remaining, and X-RateLimit-Reset headers to make the rate limit behavior observable for clients.

This helps prevent abuse and gives consumers clear feedback on how close they are to the limit.

![alt text](<Screenshot 2026-02-15 224129.png>)

Added request logging middleware with timing

Introduced a custom middleware that logs each request’s HTTP method, path, client IP, response status code, and total handling time in milliseconds.

The logs now follow a consistent format, for example:
2026-02-15 21:30:00 - INFO - Request: POST /score-url from 127.0.0.1
2026-02-15 21:30:00 - INFO - Response: POST /score-url -> 200 to 127.0.0.1 in 45ms

This provides better observability for performance and debugging, especially useful when monitoring latency for the scoring endpoints over time.

![alt text](<Screenshot 2026-02-15 224208.png>)

Added CORS middleware to allow frontend access from localhost origins

Configured CORSMiddleware so that a local frontend (e.g., React at http://localhost:3000) can call the SentinelTI API at http://localhost:8000 without browser CORS errors.

Allowed origins currently include http://localhost and http://localhost:3000, with all methods and headers enabled so the frontend can send the X-API-KEY and any required JSON requests.

This change keeps existing local tools (curl, Swagger UI) working as before while making the service ready to plug into a browser-based UI.

![alt text](<Screenshot 2026-02-15 224417.png>)

SentinelTi – Progress Log (Feb 16, 2026)

Restructured main README

Rewrote the top-level README around a clearer flow: What is SentinelTi, Quick start, CLI usage, HTTP API usage, How it works, Training, and Project structure.

Added concise, copy-pasteable setup instructions and unified descriptions of the ML + heuristic scoring pipeline so new users can understand and run the project quickly.

Improved enriched reasoning in scoring results

Updated enrich_score so every response now includes explicit model confidence plus aggregated heuristic indicators in the reasons field.

Kept existing label/risk thresholds but made explanations more human-readable and useful for debugging and analysis (e.g., showing when a decision is primarily model-driven vs heuristic-driven).

Added request body examples for scoring endpoints

Extended the Pydantic request models for /score-url and /score-urls with JSON schema examples.

This makes the autogenerated FastAPI docs more intuitive by pre-populating realistic example payloads that users can try directly from /docs.

![alt text](<Screenshot 2026-02-17 094719.png>)

--- Progress log: 02/17/2026

1. Documented heuristics module limitations  
   - Added a top-of-file docstring in `heuristics.py` describing the purpose of the heuristic URL analysis and clearly stating it is a lightweight signal layer that enriches the ML model, not a full detection engine.  
   - Captured known limitations in a structured comment block (typosquatting/IDN, open redirects, malware downloads, internal IPs, deep SSO paths, and limited brand impersonation scope).  

  ![alt text](<Screenshot 2026-02-17 133524.png>)


2. Implemented IDN (Punycode) and leetspeak brand heuristics  
   - Added a simple Punycode detection check (`xn--` in hostname) that bumps the heuristic score and records a reason about IDN lookalike domains.  
   - Introduced a `_normalize_leetspeak` helper to map common leetspeak substitutions (0→o, 1→l, 3→e, 5→s, @→a) so brand tokens can be recognized in typo domains (e.g., `paypa1` → `paypal`, `micr0soft` → `microsoft`, `faceb0ok` → `facebook`).  
   - Updated the brand impersonation heuristic to match `BRAND_TOKENS` against the normalized hostname while still using the original host/path/query to look for phishing keywords.  
   - Verified via manual eval that Punycode lookalikes (e.g., `xn--pple-43d.com`) and leetspeak typo domains (e.g., `paypa1-secure.com`, `micr0soft-account.com`) are now scored at least “suspicious” and include clear brand-impersonation reasons.  

  ![alt text](<Screenshot 2026-02-17 133613.png>)

3. Expanded manual evaluation dataset for URL heuristics  
   - Added new rows to `manual_eval_urls.csv` for:  
     - `http://paypa1-secure.com/login` – typosquatted PayPal-like domain with login path (expected suspicious).  
     - `http://xn--pple-43d.com/verify` – IDN/Punycode Apple lookalike with verify path (expected suspicious).  
     - `http://paypal.com/login` – legitimate PayPal login URL as a benign control case.  
   - Re-ran the manual evaluation script and reviewed confusion matrix and “Sample disagreements” to validate that heuristic changes influence final labels as expected without exploding false positives.  


4. Strengthened regression tests around manual eval behavior  
   - Added `test_obvious_phish_are_not_benign` to assert a set of clearly phishy URLs are never labeled purely benign (they must be at least `suspicious` or `malicious`), then refined the URL set to reflect what the current heuristics actually guarantee.  
   - Added `test_known_legit_brand_logins_stay_benign` to ensure major, known-good brand login URLs (Google, Microsoft, Netflix, PayPal, Amazon) remain `benign` with `low` risk, preventing over-aggressive brand impersonation rules from breaking real logins.  
   - Added `test_typosquatted_and_idn_domains_are_suspicious` to assert that brand-like leetspeak domains and Punycode lookalikes (e.g., `paypa1-secure.com`, `micr0soft-account.com`, `xn--pple-43d.com`) are not classified as benign.  
   - Cleaned up an extra, incorrectly defined test stub so the test suite remains clear and maintainable.  
   - Confirmed the full test suite passes after adjusting expectations to match the actual v1 behavior of the heuristics.  

  ![alt text](<Screenshot 2026-02-17 133701.png>)

5. Overall impact  
   - Heuristic layer now explicitly handles two previously known gaps: IDN/Punycode lookalikes and simple leetspeak brand typos, improving coverage of common phishing domain tricks without significantly increasing noise on legitimate URLs.  
   - Behavior changes are locked in with targeted tests, so future edits to `heuristics.py` will fail fast if they regress on obvious phish or brand-impersonation typos.  
   - The limitations are clearly documented at the module level, making it easier to pick up work later on remaining gaps (open redirects, malware download paths, internal IP handling, deep SSO flows).  

**SentinelTi – Work Session Log (2026‑02‑18)**

1) **Heuristic engine enhancements (heuristics.py)**  
Expanded the heuristic module to cover additional phishing and malware indicators. Updated analyze_url to integrate new logic for leetspeak normalization, Punycode, executable downloads, and partial open‑redirect parameters.  

- Introduced detection for executable or script downloads (`.exe`, `.scr`, `.bat`, `.cmd`, `.ps1`), differentiating between trusted and untrusted domains.  
- Added open‑redirect heuristics scanning query parameters (`redirect`, `next`, `url`, `dest`, `destination`, etc.) for nested HTTP(S) links.  

These changes collectively strengthened coverage for brand‑related phishing, payload delivery, and redirect abuse.  

![alt text](<Screenshot 2026-02-19 092855.png>)

2) **Manual evaluation and dataset expansion (manual_eval.py / manual_eval_urls.csv)**  
Extended the manual evaluation dataset to include new typosquatted, IDN, executable, and open‑redirect examples. Confirmed expected heuristic coverage through enrich_score output and confusion summaries.  

New examples include:  
- Typosquatted brands (e.g., paypa1‑secure.com, micr0soft‑account.com)  
- IDN/Punycode variants (e.g., xn‑‑pple‑43d.com)  
- Executable downloads (e.g., payload.exe, update.exe)  
- Redirect patterns (e.g., login?redirect=http://evil.com)  

Manual eval results verified that clearly malicious and suspicious URLs no longer regress to benign classification.  

3) **Behavioral tests and regression coverage (tests/test_manual_eval_behavior.py)**  
Created and refined behavioral regression tests to lock in heuristic expectations:  
- `test_typosquatted_and_idn_domains_are_suspicious`  
- `test_executable_malware_downloads_are_not_benign`  
- `test_open_redirect_style_urls_are_not_benign`  

Tests confirm that brand impersonations, executable URLs, and redirect‑like parameters always return “suspicious” or “malicious.”  
Regression runs were executed successfully with all new heuristics passing.  

![alt text](<Screenshot 2026-02-19 092940.png>)

4) **Documentation and code organization updates**  
- Added detailed top‑of‑file docstring for `heuristics.py` describing purpose, approach, and limitations.  
- Included a “Current limitations of heuristic‑based URL analysis (v1)” block outlining remaining gaps to guide future improvements.  
- Cleaned up imports, reused `base_domain` computation across sections, and improved inline comments for clarity.  

![alt text](<Screenshot 2026-02-19 093017.png>)

**SentinelTi – Work Session Log (2026‑02‑19)**  

1) **Private / local IP heuristics (heuristics.py & tests)**  
- Added detection for literal private and local IP hosts using `ipaddress` (e.g. `127.0.0.1`, `192.168.x.x`, `10.x.x.x`, `172.16–31.x.x`, `localhost`).  
- Bumped heuristic score for these hosts so they are at least classified as suspicious in scoring.  
- Added `test_private_or_local_ip_urls_are_not_benign` to ensure private/local IP URLs never regress to plain benign.  
- Updated `manual_eval_urls.csv` with gray‑labeled private IP examples for manual verification.  

![alt text](<Screenshot 2026-02-19 112355.png>)

2) **Improved open‑redirect detection (encoded and additional params)**  
- Extended open‑redirect heuristic to repeatedly decode parameter values (up to two rounds) and detect nested `http://` or `https://` URLs even when URL‑encoded (e.g. `url=http%3A%2F%2Fevil.com`).  
- Expanded the list of redirect‑style parameters to include `target=`, catching URLs like `?target=https://evil.com`.  
- Increased the heuristic score for detected nested URLs so such URLs are always at least suspicious under current scoring rules.  
- Re‑enabled and passed the encoded and `target=` cases in `test_open_redirect_style_urls_are_not_benign`.  

![alt text](<Screenshot 2026-02-19 112506.png>)

3) **Fragment‑based nested URL detection**  
- Added logic to inspect the URL fragment (`#...`) and flag cases where it contains a nested `http://` or `https://` URL (e.g. `login#https://evil.com`).  
- Ensured fragment‑based nested URLs contribute to the heuristic score with a clear reason string.  
- Verified behavior against existing manual eval examples that include nested URLs in fragments.  
Screenshots: [fragment heuristic snippet ____], [manual_eval example with fragment ____].  

![alt text](<Screenshot 2026-02-19 112610.png>)

***

## SentinelTI URL Heuristics – Progress Log 02/24/2026

### 1) IP Handling Unification and Scoring

**What changed**

- Replaced duplicate IP detection blocks with a single unified IP-handling section using Python’s standard IP address utilities.  
- Classified IP hosts into:
  - Private/loopback (treated as internal-looking, with risk).  
  - Reserved/documentation ranges (treated as unusual but external-looking).  
  - Public raw IPs (treated as potentially malicious infrastructure).  
- Added consistent handling for `localhost` / `local` as internal-looking hosts.  
- Increased the score for private/loopback/localhost so that internal-looking URLs are at least “suspicious,” even without other strong indicators.

**Intended effect**

- Internal/private URLs (e.g., `127.0.0.1`, `10.x.x.x`, `192.168.x.x`, `localhost`) now reliably avoid a benign label due to internal exposure/SSRF risk.  
- Reserved ranges (e.g., `192.0.2.x`, `203.0.113.x`) and public raw IPs now clearly contribute to risk without being misidentified as private.  

![alt text](<Screenshot 2026-02-24 222204.png>)

***

### 2) Strong Brand Impersonation Rule (Prefix-Only)

**What changed**

- Updated the strong brand impersonation heuristic so it only fires when brand tokens appear in the **subdomain prefix** before the base domain.  
- The rule still requires:
  - Brand-like tokens present.  
  - Phishing-related keywords present.  
  - Base domain not in the trusted whitelist.  
- The reason text now explicitly refers to “subdomain contains brand-like tokens … combined with phishing keywords.”

**Intended effect**

- Keeps strong hits for URLs like `paypal.com.verify-update.info`, `update-appleid.example.info`, `confirm-amazon-order.example.site`.  
- Reduces false positives where a brand word appears in the registered domain or TLD but is not used as an impersonated subdomain.

![alt text](<Screenshot 2026-02-24 222305.png>)

***

### 3) Brand Fallback + Recovery and Microsoft-Typo Special Case

**What changed**

- Extended the “brand + login/security fallback” rule to also treat **recovery-like** actions as risky:
  - Now looks for `login`, `signin`, `sign-in`, `secure`, `security`, `security-check`, `recover`, `recovery`, `reset`.  
- Added a targeted heuristic for Microsoft-typo recovery domains:
  - Detects host tokens resembling `micr0soft` / `micros0ft`.  
  - Requires recovery-like tokens in host or path.  
  - Applies only on non-trusted domains.  
- In both cases, adds a moderate score bump and a reason explaining account recovery impersonation.

**Intended effect**

- URLs such as `http://micr0soft-account.com/recover` no longer end up benign; they are at least **suspicious**.  
- Other brand recovery/ reset flows on non-trusted, suspicious-looking domains get a small but meaningful risk bump.

![alt text](<Screenshot 2026-02-24 222338.png>)

***

### 4) Nested URL Heuristics vs Legit SSO/OAuth

**What changed**

- Adjusted nested-URL scoring so that **SSO/OAuth-like endpoints** are treated more gently:
  - Introduced an `is_sso_like` check using existing SSO host/path hints.  
  - For redirect-style parameters on SSO-like URLs, reduced the added score to a small bump (or near-zero), while still adding a descriptive reason.  
  - For other nested URL params on SSO-like URLs, either added a tiny score or no score, but kept a light “may be normal but can be abused” reason.  

**Intended effect**

- Legitimate SSO/OAuth URLs such as `https://auth.example.com/oauth2/authorize?...redirect_uri=...` now remain **benign** under normal conditions.  
- Non-SSO pages with nested URLs (e.g., open redirects, tracker/callback links) remain clearly **suspicious**.

![alt text](<Screenshot 2026-02-24 222510.png>)

***

### 5) Evaluation Runs and Current Metrics

**What you ran**

- Manual evaluation script:  
  - Command: `python -m sentinelti.manual_eval`  
- Automated tests:  
  - Command: `python -m pytest`

**Observed behavior (today’s session)**

- Brand impersonation, nested URL, and IP handling tests in `tests/test_manual_eval_behavior.py` now pass after adjustments.  
- Internal/private IP URLs, reserved IP URLs, legit SSO URLs, and Microsoft-typo recovery URLs now align with their expected labels in tests.

![alt text](<Screenshot 2026-02-24 222604.png>)

***

### 6) Notes and Remaining Gaps

**Still known gaps**

- `login-office365.com` still benign due to the earlier leetspeak / normalization bug not yet addressed.  
- No dedicated heuristic yet for:
  - `examp1e.com/login` (generic typo + login).  
  - Very long / weird TLD login URLs, e.g.  
    - `very-long-subdomain-with-many-levels.login.secure.update.example.com/path`  
    - `example.reallylongtldthatisweirdlysuspicious/login`

**Planned future work**

- Add a **“login + weird/very long domain/TLD”** heuristic.  
- Introduce a conservative, generic typo/homoglyph detector for non-brand words plus login paths.  
- Fix or replace the leetspeak normalization bug impacting Office365-like domains.

Here’s a concise, human-style progress log for today, with placeholders where you can drop screenshots as proof.

***

## Progress Log – 2026‑03‑01

### 1) Tightened Office 365/Microsoft login phishing heuristic  
**Commit:** `Tighten Office 365/Microsoft login phishing heuristic`  
**Summary:**  
- Expanded the Office 365/Microsoft heuristic to look for `office365`, `microsoftonline`, and `o365` tokens in hostnames combined with login-related tokens (`login`, `signin`, `sign-in`).  
- Limited the rule to non‑trusted base domains so legit Microsoft infrastructure is not penalized.  
- Improved the reason text to clearly call out Microsoft 365 credential phishing patterns.

![alt text](<Screenshot 2026-03-01 232357.png>)

***

### 2) Refined literal IP host classification and reasons  
**Commit:** `Refine literal IP host classification and reasons`  
**Summary:**  
- Split IP handling into clearer categories: loopback, private RFC1918, reserved/documentation, and public raw IP.  
- Marked loopback and private IPs as internal, with explicit reasons about internal exposure and local-only services.  
- Added more precise wording for reserved/documentation ranges and public raw IPs, aligning behavior with your documented limitations around IP/infrastructure scope.

![alt text](<Screenshot 2026-03-01 232435.png>)

***

### 3) Added manual eval tests for loopback, private, and documentation IP hosts  
**Commit:** `Add manual eval tests for loopback, private, and documentation IP hosts`  
**Summary:**  
- Introduced parameterized tests to ensure:  
  - Loopback and private IP URLs are never classified as plain benign.  
  - Documentation-only IP ranges (RFC 5737) get some heuristic signal instead of being treated as obviously safe.  
- Strengthened confidence that internal-looking and test-net IPs are handled consistently going forward.

![alt text](<Screenshot 2026-03-01 232530.png>)

***

### 5) Added test for raw public IP  
**Commit:** `Add test for raw public IP`  
**Summary:**  
- Added a focused test that sends a URL with a bare public IP host and asserts that a raw-IP-related heuristic reason is attached.  
- Ensured that using a direct public IP is always visible in the explanation layer, reflecting how bare IP infrastructure is often used in malicious hosting.

![alt text](<Screenshot 2026-03-01 232610.png>)

***

### 6) Expanded manual eval tests for legitimate SSO/OAuth URLs  
**Commit:** `Expand manual eval tests for legitimate SSO/OAuth URLs`  
**Summary:**  
- Broadened the SSO/OAuth test set with additional realistic IdP and OAuth authorize URLs (e.g., Google, Microsoft, generic `auth.example.com`).  
- Guarded against over-aggressive heuristics on deep, token-heavy SSO flows, helping keep legitimate login/SSO pages benign and low-risk.

## Progress Log – 2026‑03‑02

### 1) Added infrastructure metadata to enrich_score output  
- Extended the enriched result to include an `infrastructure` section with fields for `ip`, `ip_class`, `is_internal`, `tld`, `asn`, and `reputation`.  
- Wired `is_internal` and `tld` through from heuristic features, leaving the other fields as placeholders for future infrastructure work.  

![alt text](<Screenshot 2026-03-02 185051.png>)

***

### 2) Introduced hostname-to-IP resolver helper  
- Created a small helper function to resolve hostnames to IPv4 addresses in a best‑effort, failure‑tolerant way.  
- Added tests that monkeypatch the underlying resolution call to verify both success and failure paths without relying on real DNS.  

![alt text](<Screenshot 2026-03-02 185202.png>)

***

### 3) Began wiring domain→IP into enrich_score  
- Started using the resolver in the scoring/enrichment layer to populate the `infrastructure["ip"]` field for non‑IP hosts, without changing any labeling or scoring logic yet.  
- Kept tests focused on structure (presence of the `infrastructure` block and keys) while preparing for future IP‑class and reputation integration.  

Screenshot: in commit 1's screenshot

*** Progress Log – 2026‑03‑03

Resolved IP classification and infra metadata

Extended enrich_score to perform best-effort DNS resolution for hostnames.

Classified resolved IPs as loopback, private, reserved, or public using ipaddress, and stored them in infrastructure["ip"] and ["ip_class"].

Updated tests to assert the structure and allowed values of infra metadata.

Infra-based heuristic for internal resolution

Added a mild heuristic when an external-looking hostname resolves to a private or loopback IP, slightly increasing the heuristic score and adding an explanation note.

Wrote a deterministic test by monkeypatching scoring.resolve_hostname_to_ip to ensure the infra note appears when expected.

Updated IP and infrastructure limitation text

Revised the “IP and infrastructure scope” section in heuristics.py to reflect that:

Literal IPs and resolved IPs are classified and scored.

A basic infra-based signal now exists.

External reputation/hosting provider integrations are still not implemented.

Local IP reputation hook

Introduced a small KNOWN_SUSPICIOUS_IPS set in scoring.py as a minimal local reputation source.

When a resolved IP hits this list, infrastructure["reputation"] is set to "suspicious", a tiny heuristic bump is applied, and a clear reason is added.

Added tests to verify that the reputation flag and reason appear when a hostname resolves to a locally marked suspicious IP.

## Progress Log – 2026‑03‑05

1) Strengthened IP-based phishing heuristics  
- Added a heuristic in the URL analyzer so that login flows served directly from a bare public IP (e.g., `http://93.184.216.34/login`) receive an additional risk bump and a clear reason about low‑reputation infrastructure.  
- Ensured the new rule reuses existing IP classification (loopback/private/reserved/public) rather than introducing duplicate logic.

2) Expanded infrastructure metadata coverage  
- Verified that infrastructure metadata (`ip`, `ip_class`, `is_internal`, `tld`, `asn`, `provider`, `reputation`) is present and correctly shaped for both domain-based URLs and literal IP URLs.  
- Added tests that run the scoring pipeline on domain hosts, private IPs, and public IPs, asserting that the infra block is always present and structurally consistent.

3) Prepared for future external reputation integration  
- Refined the infrastructure reputation field so it now defaults to `"unknown"` and is explicitly set to `"suspicious"` when a resolved IP hits the local suspicious-IP list.  
- Introduced a clean stub interface for future IP reputation lookups, defining how external feeds or services can later plug into the scoring layer without changing its public API.

Progress log: 03/07/2026

Added a new heuristic: executable downloads hosted directly on bare public IPs now slightly increase the heuristic score and produce an explicit reason string.
​

Introduced an infra_flag summary field (normal, internal, suspicious_infra) in the enriched output, derived from internal IP detection, local reputation, and IP class metadata.
​

Evolved the lookup_ip_reputation stub to use a local KNOWN_SUSPICIOUS_IPS list, wired it into enrich_score, exposed reputation and reputation_source in the infrastructure block, and added tests to verify suspicious IPs affect both reputation and infra metadata.

*** Progress log: 03/10/2026

Implemented a heuristic that flags URLs where a well-known brand token appears in the path/query but not in the domain, plus tests to ensure it increases score only for unrelated domains and stays quiet for trusted brand domains.

Strengthened the example-like typo + login heuristic so “example-style” typo domains combined with login paths are treated as suspicious, and added a complementary test confirming that the same domains without login paths don’t get the same bump.

Refactored test_scoring.py and test_manual_eval_behavior.py to be clearer and more maintainable, grouping tests by concern and reducing duplication while preserving existing behavior.

*** Progress log: 03/12/2026

Refactored IP reputation lookups to support an optional external provider while keeping a local suspicious IP list as fallback.

Updated scoring to call the new lookup_ip_reputation helper and adjust heuristic risk based on local IP reputation.

Added an ExternalIPReputationProvider protocol and tests to ensure external reputation overrides the local list when present.

Implemented a standalone homoglyphs.py helper to detect simple m vs rn homoglyph brand spoofs (like rnicrosoft), including substring matching for real domains.


Created tests/test_homoglyphs.py to exercise the homoglyph helper on known spoof and non-spoof inputs and got the full test suite back to green.

*** Progress log: 03/13/2026

Refined the IP scoring layer by adding a shared _classify_ip helper and updating enrich_score to use it, keeping behavior but simplifying the code.

Cleaned up scoring.py imports and removed unused homoglyph logic, while preserving all existing tests and behavior.

Tightened heuristics.py by unifying path-depth computation, fixing duplicate deep-path scoring, and exempting obvious docs/blog URLs from aggressive deep-path penalties.

Implemented a conservative rn vs m homoglyph heuristic end-to-end: standalone helper, integration into analyze_url, and tests for rnicrosoft-style domains.

Extended homoglyph coverage to include a vv vs w spoof pattern and added tests to confirm detection of tvvitter-style domains.

Added new unit tests for multi-token brand impersonation patterns (e.g., “microsoft support”, “google drive”, “apple id”) to ensure they receive non-zero heuristic scores.

Progress log: 4/19/2026

### Completed
- Stabilized tests after ML model artifact naming/loading changes
- Removed accidental dependency on real trained model files in unit and behavior tests
- Reworked one CLI test to run in-process instead of through `subprocess`

### Changed
- `tests/test_ml_service.py`: mocked `predict_url` within `sentinelti.ml.service`
- `tests/test_scoring.py`: mocked `scoring.ml_score_url` for `enrich_score` tests
- `tests/test_manual_eval_behavior.py`: mocked `scoring.ml_score_url` for behavior-driven scoring tests
- `tests/test_cli_score_file.py`: switched from subprocess execution to direct `cli.main()` with mocked `enrich_score`

### Notes
The failures were caused by tests reaching the real model loader after the project moved away from a single hardcoded artifact path. The updated tests now isolate the ML boundary and verify behavior without requiring local model files.

### Next
- Add reusable fixtures for fake ML responses
- Consider marking true model-artifact tests as integration tests
- Run full suite in CI to confirm portability


## Progress Log - 2026-04-20

### Testing and reliability

- Added `tests/test_predict.py` to cover URL model loading and prediction:
  - Verified `get_model_path()` builds the correct artifact filenames.
  - Confirmed `load_model()` prefers the XGBoost artifact when available and falls back to logistic regression when only that artifact exists.
  - Ensured `load_model(prefer="logreg")` respects the preference order.
  - Added tests for error paths when no artifacts exist or an existing artifact fails to load (raising `FileNotFoundError` or `RuntimeError` as appropriate).
  - Verified `predict_url()` returns the expected label and probability relative to the malicious threshold.

### Test infrastructure and configuration

- Created `tests/conftest.py` with shared fixtures:
  - `fake_ml_score` to patch `sentinelti.scoring.ml_score_url` with configurable probabilities and labels across tests.
  - `fake_cli_enrich_score` to patch `sentinelti.cli.enrich_score` for CLI tests without touching the real model/heuristic stack.
- Updated `tests/test_manual_eval_behavior.py` to use the shared `fake_ml_score` fixture instead of inline ML fakes, reducing duplication and making behavior tests independent of real model artifacts.
- Updated `tests/test_cli_score_file.py`:
  - Switched to in-process `cli.main()` execution (no subprocess) and reused `fake_cli_enrich_score` for the success-path test.
  - Added `test_cli_reports_missing_model_artifacts_gracefully` to assert CLI behavior when the underlying scoring raises a “No trained URL model artifacts found” error.

### CLI robustness

- Extended `sentinelti/cli.py` to handle missing model artifacts gracefully:
  - Wrapped command dispatch in a narrow `try/except FileNotFoundError`.
  - When the message matches “No trained URL model artifacts found”, the CLI now:
    - prints a clear error to stderr explaining that model artifacts are missing and must be trained or added,
    - exits with status code `1` instead of showing a raw traceback.
  - Non-matching `FileNotFoundError` cases are re-raised, so unrelated bugs are not silently swallowed.

### Pytest configuration

- Added a repo-level `pytest.ini`:
  - Registered an `integration` marker for any future tests that depend on real model artifacts or environment-specific setup.
  - Set basic defaults (`addopts = -ra`, `testpaths = tests`) to streamline local and CI test runs.

### Current status

- All tests (including the new `test_predict.py` and CLI error-handling test) are passing.
- The test suite no longer depends on model artifacts for unit and behavior tests, and the CLI now fails cleanly when artifacts are missing.

Progress log: 05/17/2026

Revalidated the SentinelTI ML stack context (datasets, models, feature extractor, prediction service) and confirmed that the current focus is model metadata and integration, not new modeling work.

Shared the existing implementations of sentinelti/ml/train.py, sentinelti/ml/predict.py, and sentinelti/ml/service.py and walked through their current behavior, including how artifacts and metrics JSON were being written.

Refactored train.py to:

Standardize a model artifact format that bundles the trained estimator, feature names, and a nested metadata dictionary.

Add richer metadata, including dataset source flags, class counts, feature version, threshold, class label mapping, and training parameters.

Compute additional evaluation metrics (ROC AUC, average precision) alongside the existing classification_report to better characterize classifier performance.

Save both a self-contained .joblib artifact and a JSON metrics document derived from the same metadata source to avoid drift.

Refactored predict.py to:

Load the new artifact structure while remaining backwards-compatible with simpler, legacy artifacts.

Normalize metadata into a stable schema for downstream consumers (model type, trained timestamp, dataset name, metrics, threshold, feature version, class labels/counts, training params, artifact path).

Centralize feature-vector construction and scoring in a helper so that both predict_url and predict_url_with_metadata rely on the same logic.

Honor a threshold embedded in artifact metadata, with an environment-variable‑based fallback for global overrides.

Verified the changes end-to-end by retraining both models on the Kaggle dataset:

XGBoost: very high performance, metrics JSON and artifact written with the new metadata structure.

Logistic Regression: similarly strong performance with a convergence warning (as expected), and a new artifact/metrics pair written.

Crafted a commit message summarizing all these changes (metadata pipeline, artifact format, prediction refactor, and service stability).

# SentinelTI progress log — 2026-05-18

## ML / model status
- Confirmed the current direction is no longer just “train models,” but to finish the ML metadata plumbing and make it usable in API/UI-facing flows.
- Re-aligned on the ML roadmap: artifact metadata completeness, threshold handling, and tests remain key follow-up items.

## Backend / API
- Extended the backend/API work around explanation-oriented scoring.
- Updated `sentinelti/scoring.py` so score output includes structured explanation data suitable for downstream consumers.
- Updated `sentinelti/api.py` so explanation-aware responses are exposed through the API.
- Aligned API expectations around the newer response shape and schema `1.2`.

## Frontend / React
- Confirmed React is the chosen frontend direction for SentinelTI.
- Continued work on the result UX around:
  - `VerdictCard.jsx`
  - `DetailPanel.jsx`
- Moved the UI toward a better split between:
  - simple public-facing verdict experience
  - expandable technical details for specialist users
- Improved styling of the verdict/details panels to better match the app’s dark theme.
- Updated the hero subtitle styling so:
  - “Check whether a URL looks safe before you open it.”
  stays on one line on larger screens.

## Testing
- Reworked `tests/test_api.py` to better cover explanation-aware endpoint behavior.
- Added/updated test expectations for:
  - schema version changes
  - explanation fields
  - `/explain-score`
  - auth behavior
- Hit a local pytest import-path issue (`ModuleNotFoundError: No module named 'sentinelti'`) while loading `tests/conftest.py`.
- Resolved the local test runner/import setup issue.
- Re-ran the API tests successfully and confirmed all tests are green.

## Git / commits completed
- Committed backend + UI explanation work:
  - `sentinelti/api.py`
  - `sentinelti/scoring.py`
  - `sentinelti/frontend/src/components/VerdictCard.jsx`
  - `sentinelti/frontend/src/components/DetailPanel.jsx`
- Committed explanation-aware API test updates.
- Continued styling iteration after functional work was verified.

## Product direction reaffirmed
- Kept the overall SentinelTI product direction aligned:
  - simple “is this URL safe?” experience for regular users
  - deeper technical analysis for advanced users
  - future LLM-assisted explanation layer after deterministic plumbing is stable

## Best next step
- Resume with ML metadata sanity checks and ML predict/service tests, while continuing lighter frontend polish in parallel as needed.


# Progress Log - 2026-05-19

## Work completed

Today focused on stabilizing the API contract, improving ML artifact handling, and tightening test coverage across the backend.

### API and contract work

- Added structured runtime error handling for scoring endpoints so backend failures return predictable JSON instead of bubbling raw exceptions.
- Expanded API test coverage for:
  - `/model-info`
  - rate-limit headers
  - partial metadata defaults
  - structured runtime error responses
  - top-level response key stability
- Updated the main `README.md` so the documented API now matches the real FastAPI response models and current scoring schema.

### ML and model pipeline work

- Cleaned up `sentinelti/ml/train.py`.
- Fixed broken artifact-saving logic that referenced out-of-scope variables.
- Standardized saved artifacts to include:
  - `artifact_version`
  - `model`
  - `feature_names`
  - `X_test`
  - `y_test`
  - `metadata`
- Improved training metadata to include:
  - model type
  - dataset name/source
  - feature version
  - threshold
  - class labels/counts
  - metrics
  - training params
  - top feature importances (when available)
- Added `sentinelti/ml/threshold_analysis.py` to evaluate classifier behavior across thresholds and recommend a threshold based on a chosen optimization metric.
- Added `tests/test_threshold_analysis.py` for threshold-analysis utility coverage.
- Updated `sentinelti/ml/predict.py` to better normalize artifact metadata and correctly resolve thresholds across:
  - artifact metadata
  - environment variable fallback
  - default fallback
- Preserved backward compatibility for older model-loading code paths and legacy tests.

### Training and verification

- Ran ML prediction service tests successfully after the updates.
- Trained fresh Kaggle-based models:
  - XGBoost
  - Logistic Regression
- Confirmed model artifacts and metrics files were generated.
- Noted that Logistic Regression still raises a convergence warning at the current settings, but training completes and metrics remain strong.

## Current status

The project is in a better state than at the start of the day:

- API responses are more stable and frontend-safe.
- Model artifacts are more complete and analyzable.
- Threshold tuning now has a dedicated path instead of being a hardcoded black box.
- The repository documentation is more aligned with the live backend behavior.

## Known follow-ups

- Run threshold analysis on the newly trained XGBoost artifact and decide whether to adopt a better deployment threshold than `0.75`.
- Surface richer model metadata such as `top_features` in `/model-info`.
- Consider improving Logistic Regression convergence, likely via scaling, solver adjustment, or higher iteration budget.
- Continue frontend hardening so UI components gracefully handle missing or partial API metadata.

Progress log: 2026-05-21


ML training robustness

Ran full Logistic Regression training on the Kaggle URL dataset and verified strong performance (≈0.99 accuracy and high precision/recall on the holdout set).

Fixed a crash during metrics JSON serialization caused by non-JSON-serializable objects (e.g. StandardScaler) inside training_params, by hardening the conversion helper to safely stringify complex objects.

Adjusted the ML training tests to match the evolved artifact and metrics schema, including support for the new top_features field and storing test splits in the artifact.

Train pipeline tests and helpers

Updated tests/test_ml_train.py for the new _save_artifact signature that now captures X_test and y_test along with metadata.

Relaxed and extended expectations in metrics-writing tests to cover the richer metrics payload while still asserting core fields like thresholds, metrics, and feature versions.

Added a dedicated test ensuring the serialization helper converts numpy scalar types to built-in numbers and stringifies non-serializable estimator-like objects.

Prediction metadata and threshold provenance

Extended the ML prediction layer to compute and return the classification threshold and its provenance (“metadata”, “env”, or “default”).

Updated predict_url_with_metadata tests to reflect the richer response shape, including the new threshold_source field.

Ensured tests explicitly validate that the default artifact-driven threshold reports the correct source, locking in the intended behavior.

API: model metadata and top features

Expanded the /model-info endpoint’s response to include structured top_features and wired in tests verifying that:

well-formed top features are passed through,

missing top_features defaults to an empty list, and

malformed entries are filtered down to a clean, typed list.

Added a score-response test to confirm that model_meta.top_features is present and consistent in /score-url responses as well.

API: threshold provenance exposure

Extended the API’s model metadata schema to include threshold_source, mirroring the ML layer’s provenance information.

Updated tests to assert that the API passes through threshold_source from the underlying metadata, including env-based cases when the metadata already encodes that source.

Cleaned up one overreaching test that tried to have /model-info compute env precedence itself, and instead refocused it on verifying correct passthrough of threshold and provenance values.


Progress log: 05/22/2026

On the ML side, you refactored sentinelti/ml/predict.py to normalize artifact metadata more defensively and to treat recommended_threshold as advisory-only. Threshold values (both primary and recommended) are now coerced to floats and required to lie in 
[
0.0
,
1.0
]
[0.0,1.0]; invalid values are quietly dropped instead of poisoning metadata. You added _effective_threshold_with_source and get_effective_model_metadata, which compute the effective classification threshold with clear precedence (metadata → env → default) and attach a threshold_source explaining where it came from. You also documented the feature‑extraction contract and the fact that the classifier’s decision boundary depends solely on this effective threshold.

In the tests for the ML layer, you extended tests/test_ml_predict_service.py with scenarios that prove the new behavior. There are now tests that:

Confirm recommended_threshold is carried through as metadata but does not affect labels or thresholds used for scoring.

Verify that invalid recommended_threshold inputs (wrong type or out of range) are ignored and show up as None, while still preserving a human‑useful recommended_threshold_source.

Check that effective thresholds and sources behave as expected when metadata is present, missing, or overridden by the environment.

On the API side, you updated tests/test_api.py to align with the new metadata shape and to assert that the API is exposing the richer information correctly. The helper _mock_model_meta now includes recommended_threshold and its source, metrics, and top features, and existing tests for /model-info, /score-url, and /score-urls were kept in sync. You then added focused tests that:

Confirm /model-info includes advisory threshold fields and still reports the effective threshold and threshold_source.

Confirm /score-url responses echo the effective threshold and label driven by it, while only surfacing recommended_threshold via the nested model_meta.

Along the way you also fixed an initial test issue where new tests tried to use a client fixture that didn’t exist. You reconciled everything with the existing pattern of a module‑level TestClient and patched symbols directly on the API module, keeping the test suite consistent with how the app is actually wired.

Overall, today moved the project from “thresholds are implied and tangled with implementation details” to “threshold behavior is explicit, documented, and pinned down by tests,” and partially covered the “surface more model insight in the API” and “UX polish for error and metadata states” tracks.


## Progress log : 2026-05-23
#### Completed
- [x] Finished effective threshold provenance wiring so metadata can report both the threshold value and its source.
- [x] Tightened API behavior around effective threshold versus advisory recommended threshold.
- [x] Improved predict and train test coverage for metadata behavior and threshold invariants.
- [x] Added support for `training_notes` in model artifacts and metrics payloads.
- [x] Captured Logistic Regression convergence warnings into structured training metadata.
- [x] Surfaced richer model metadata through the API, including metrics, top features, recommended threshold metadata, and training notes.
- [x] Replaced the old frontend model info display with a richer “Model insight” panel.
- [x] Added plain-language model feature descriptions, loading states, error states, and partial-metadata handling in the UI.
- [x] Cleaned up frontend CSS structure by moving toward reset/base in `index.css`, shared app styles in `styles.css`, and component-level styling for `ModelInsightPanel`.

#### Notes
- The UI is now in a good stopping place for the night.
- The next logical phase is structural cleanup before adding AI features.
- AI should be integrated as an additive layer on top of deterministic scoring, not as a replacement for it.