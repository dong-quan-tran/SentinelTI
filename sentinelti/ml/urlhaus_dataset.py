from __future__ import annotations

from typing import Optional

import pandas as pd

from sentinelti.db import get_connection


def fetch_urlhaus_malicious(
    max_samples: Optional[int] = None,
) -> pd.DataFrame:
    """
    Fetch malicious URLs from the local URLhaus-backed indicators table.

    Returns:
        DataFrame with columns:
            - url
            - label = "malicious"
    """
    conn = get_connection()
    query = """
        SELECT value AS url
        FROM indicators
        WHERE type = 'url'
          AND feed_id = (
              SELECT id FROM feeds WHERE name = 'urlhaus'
          )
    """
    if max_samples is not None:
        query += " LIMIT ?"
        df = pd.read_sql_query(query, conn, params=(max_samples,))
    else:
        df = pd.read_sql_query(query, conn)

    conn.close()

    if df.empty:
        raise ValueError("No URLhaus indicators found in the database.")

    df["label"] = "malicious"
    return df[["url", "label"]]
