from __future__ import annotations

import argparse

from .db import init_db
from .feeds.urlhaus import upsert_indicators_from_urlhaus
from sentinelti.ml.service import score_url, score_urls


def main() -> None:
    parser = argparse.ArgumentParser(
        description="SentinelTI - Threat Intelligence Aggregator"
    )

    subparsers = parser.add_subparsers(dest="command")

    # init command
    subparsers.add_parser("init", help="Initialize the SQLite database")

    # ingest command
    ingest_parser = subparsers.add_parser(
        "ingest", help="Ingest data from a threat intel feed"
    )
    ingest_parser.add_argument(
        "feed",
        choices=["urlhaus"],
        help="Feed name to ingest (currently only 'urlhaus')",
    )

    # score-url command
    score_parser = subparsers.add_parser(
        "score-url", help="Score a single URL with the ML classifier"
    )
    score_parser.add_argument(
        "url",
        help="URL to score",
    )

    # score-urls command (optional batch mode)
    score_batch_parser = subparsers.add_parser(
        "score-urls", help="Score multiple URLs (space-separated) with the ML classifier"
    )
    score_batch_parser.add_argument(
        "urls",
        nargs="+",
        help="One or more URLs to score",
    )

    args = parser.parse_args()

    if args.command == "init":
        init_db()
        print("Database initialized.")

    elif args.command == "ingest":
        if args.feed == "urlhaus":
            print("Ingesting URLhaus feed...")
            upsert_indicators_from_urlhaus()
            print("Done.")

    elif args.command == "score-url":
        result = score_url(args.url)
        print(result)

    elif args.command == "score-urls":
        results = score_urls(args.urls)
        for r in results:
            print(r)

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
