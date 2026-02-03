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