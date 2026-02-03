import argparse
from .db import init_db
from .feeds.urlhaus import upsert_indicators_from_urlhaus


def main():
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

    args = parser.parse_args()

    if args.command == "init":
        init_db()
        print("Database initialized.")
    elif args.command == "ingest":
        if args.feed == "urlhaus":
            print("Ingesting URLhaus feed...")
            upsert_indicators_from_urlhaus()
            print("Done.")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
