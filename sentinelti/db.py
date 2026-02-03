import sqlite3
from .config import DB_PATH

def get_connection():
    return sqlite3.connect(DB_PATH)

def init_db():
    conn = get_connection()
    cur = conn.cursor()

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS feeds (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            source_url TEXT,
            description TEXT
        );
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS indicators (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            type TEXT NOT NULL,
            value TEXT NOT NULL,
            first_seen TEXT,
            last_seen TEXT,
            feed_id INTEGER,
            confidence INTEGER,
            malware_family TEXT,
            tags TEXT,
            enriched INTEGER DEFAULT 0,
            enrich_dns TEXT,
            enrich_whois TEXT,
            FOREIGN KEY(feed_id) REFERENCES feeds(id)
        );
        """
    )

    conn.commit()
    conn.close()
