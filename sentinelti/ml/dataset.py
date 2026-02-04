from __future__ import annotations

from typing import List, Tuple

import numpy as np
import pandas as pd
from sentinelti.ml.features import extract_features


# Temporary benign examples; we'll replace with real data later.
BENIGN_URLS = [
    "http://www.google.com/",
    "http://www.microsoft.com/",
    "http://www.apple.com/",
    "http://www.bbc.com/news",
    "http://www.reddit.com/",
    "http://www.github.com/",
]

# Temporary malicious-looking examples if we don't yet query URLhaus here.
MALICIOUS_URLS = [
    "http://192.168.1.10/login.php?user=admin",
    "http://secure-update-account.com/login/confirm",
    "http://paypal.verify-account-secure.com/update",
    "http://banking-secure-login.xyz/account/verify",
]


def build_dummy_dataset() -> Tuple[np.ndarray, np.ndarray, List[str]]:
    """
    Build a small dummy dataset of feature vectors and labels.

    Returns:
        X: numpy array of shape (n_samples, n_features)
        y: numpy array of shape (n_samples,)
        feature_names: list of feature names in column order
    """
    urls: List[Tuple[str, int]] = []
    for u in BENIGN_URLS:
        urls.append((u, 0))
    for u in MALICIOUS_URLS:
        urls.append((u, 1))

    feature_dicts = [extract_features(u) for u, _ in urls]

    # Use all numeric feature keys (ignore helper keys like "_tld_raw").
    numeric_keys = [k for k in feature_dicts[0].keys() if not k.startswith("_")]

    X = np.array([[fd[k] for k in numeric_keys] for fd in feature_dicts], dtype=float)
    y = np.array([label for _, label in urls], dtype=int)

    return X, y, numeric_keys


def build_real_dataset(
    csv_path: str,
    url_column: str = "url",
    label_column: str = "label",
    benign_label_value=0,
    malicious_label_value=1,
    max_samples: int | None = None,
) -> Tuple[np.ndarray, np.ndarray, List[str]]:
    """
    Build a dataset from a labeled CSV of URLs.
    """

    df = pd.read_csv(csv_path)

    # Filter to only benign and malicious labels we care about.
    df = df[df[label_column].isin([benign_label_value, malicious_label_value])]

    if df.empty:
        raise ValueError(
            f"No rows found matching labels {benign_label_value} / {malicious_label_value} in column '{label_column}'"
        )

    if max_samples is not None and len(df) > max_samples:
        df = df.sample(n=max_samples, random_state=42)

    urls = df[url_column].astype(str).tolist()
    labels = df[label_column].apply(
        lambda v: 0 if v == benign_label_value else 1
    ).tolist()

    feature_dicts = [extract_features(u) for u in urls]
    numeric_keys = [k for k in feature_dicts[0].keys() if not k.startswith("_")]

    X = np.array([[fd[k] for k in numeric_keys] for fd in feature_dicts], dtype=float)
    y = np.array(labels, dtype=int)

    print(f"Loaded {len(df)} rows from {csv_path}")
    print(df[label_column].value_counts())

    return X, y, numeric_keys

    df = df[df[label_column].isin([benign_label_value, malicious_label_value])]

    if df.empty:
        raise ValueError(
            f"No rows found matching labels {benign_label_value} / {malicious_label_value} in column '{label_column}'"
        )
