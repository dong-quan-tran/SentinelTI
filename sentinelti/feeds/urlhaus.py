import csv
import io
from datetime import datetime

import requests

from ..config import URLHAUS_RECENT_CSV
from ..db import get_connection


def ensure_feed_record():
    """
    Ensure a 'urlhaus' feed record exists and return its id.
    """
    conn = get_connection()
    cur = conn.cursor()

    cur.execute(
        """
        INSERT OR IGNORE INTO feeds (name, source_url, description)
        VALUES (?, ?, ?);
        """,
        (
            "urlhaus",
            URLHAUS_RECENT_CSV,
            "abuse.ch URLhaus recent malicious URLs feed",
        ),
    )

    conn.commit()

    cur.execute("SELECT id FROM feeds WHERE name = ?;", ("urlhaus",))
    row = cur.fetchone()
    conn.close()

    return row[0]


def fetch_recent_csv():
    """
    Download the recent CSV from URLhaus and return decoded text.
    """
    resp = requests.get(URLHAUS_RECENT_CSV, timeout=30)
    resp.raise_for_status()
    return resp.text


def parse_urlhaus_csv(csv_text):
    """
    Parse URLhaus CSV text and yield rows as dicts.
    Skips comment lines starting with #.
    """
    f = io.StringIO(csv_text)
    reader = csv.reader(f)
    for row in reader:
        if not row or row[0].startswith("#"):
            continue
        # URLhaus CSV format (simplified):
        # id, dateadded, url, url_status, threat, tags, urlhaus_link, reporter
        if len(row) < 6:
            continue

        yield {
            "dateadded": row[1],
            "url": row[2],
            "threat": row[4],
            "tags": row[5],
        }


def upsert_indicators_from_urlhaus():
    """
    Ingest recent URLhaus data into the indicators table.
    """
    feed_id = ensure_feed_record()
    csv_text = fetch_recent_csv()

    conn = get_connection()
    cur = conn.cursor()

    now_iso = datetime.utcnow().isoformat(timespec="seconds") + "Z"

    for entry in parse_urlhaus_csv(csv_text):
        url = entry["url"].strip()
        if not url:
            continue

        first_seen = entry["dateadded"] or now_iso
        malware_family = entry["threat"] or None
        tags = entry["tags"] or None

        # Check if this URL already exists for this feed
        cur.execute(
            """
            SELECT id, first_seen, last_seen FROM indicators
            WHERE value = ? AND feed_id = ?;
            """,
            (url, feed_id),
        )
        row = cur.fetchone()

        if row:
            ind_id, existing_first_seen, existing_last_seen = row
            # Update last_seen to now, keep earliest first_seen
            cur.execute(
                """
                UPDATE indicators
                SET last_seen = ?
                WHERE id = ?;
                """,
                (now_iso, ind_id),
            )
        else:
            cur.execute(
                """
                INSERT INTO indicators
                (type, value, first_seen, last_seen, feed_id,
                 confidence, malware_family, tags)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    "url",
                    url,
                    first_seen,
                    now_iso,
                    feed_id,
                    80,  # arbitrary confidence for this feed
                    malware_family,
                    tags,
                ),
            )

    conn.commit()
    conn.close()
