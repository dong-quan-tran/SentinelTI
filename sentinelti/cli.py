from __future__ import annotations

import json
import argparse

import csv
from pathlib import Path
from typing import List, Optional

from sentinelti.scoring import enrich_score

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
    score_parser.add_argument(
        "--json",
        action="store_true",
        help="Output result as JSON instead of a Python dict.",
    )
    score_parser.add_argument(
        "--json-pretty",
        action="store_true",
        help="Pretty-print JSON output (implies --json).",
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
    score_batch_parser.add_argument(
        "--json",
        action="store_true",
        help="Output results as JSON list instead of line-by-line dicts.",
    )
    score_batch_parser.add_argument(
        "--json-pretty",
        action="store_true",
        help="Pretty-print JSON output (implies --json).",
    )

    # score-file command (batch from file)
    score_file_parser = subparsers.add_parser(
        "score-file",
        help="Score URLs from a text or CSV file using the ML+heuristic classifier",
    )
    score_file_parser.add_argument(
        "input_path",
        type=Path,
        help="Path to input file (.txt or .csv)",
    )
    score_file_parser.add_argument(
        "--input-format",
        choices=["auto", "txt", "csv"],
        default="auto",
        help="Interpret input as txt (one URL per line) or csv; default: auto by extension.",
    )
    score_file_parser.add_argument(
        "--url-column",
        default="url",
        help="Column name containing URLs when input-format=csv (default: url).",
    )
    score_file_parser.add_argument(
        "--output",
        type=Path,
        help="Optional output file path (if omitted, results are printed to stdout).",
    )
    score_file_parser.add_argument(
        "--output-format",
        choices=["csv", "json"],
        default="csv",
        help="Output format for batch results (csv or json).",
    )
    score_file_parser.add_argument(
        "--json-pretty",
        action="store_true",
        help="Pretty-print JSON output (only used when --output-format=json).",
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
        result = enrich_score(args.url)
        
        if args.json or args.json_pretty:
            indent = 2 if args.json_pretty else None               
            print(json.dumps(result, indent=indent))
        else:
            infra = result.get("infrastructure", {})
            infra_flag = infra.get("infra_flag")
            reputation = infra.get("reputation")

            if infra_flag == "internal":
                infra_summary = (
                    "Infrastructure: internal or loopback IP "
                    "(possible SSRF or internal service)."
                )
            elif infra_flag == "suspicious_infra":
                infra_summary = (
                    "Infrastructure: suspicious "
                    "(local bad-IP list or external host resolving internal)."
                )
            else:
                infra_summary = "Infrastructure: normal (no strong infra indicators)."

            if reputation and reputation != "unknown":
                infra_summary += f" IP reputation: {reputation} (local)."

            print(result)
            print(infra_summary)

    elif args.command == "score-urls":
        results = [enrich_score(url) for url in args.urls]

        if args.json or args.json_pretty:
            indent = 2 if args.json_pretty else None
            print(json.dumps(results, indent=indent))
        else:
            for result in results:
                infra = result.get("infrastructure", {})
                infra_flag = infra.get("infra_flag")
                reputation = infra.get("reputation")

                if infra_flag == "internal":
                    infra_summary = (
                        "Infrastructure: internal or loopback IP "
                        "(possible SSRF or internal service)."
                    )
                elif infra_flag == "suspicious_infra":
                    infra_summary = (
                        "Infrastructure: suspicious "
                        "(local bad-IP list or external host resolving internal)."
                    )
                else:
                    infra_summary = "Infrastructure: normal (no strong infra indicators)."

                if reputation and reputation != "unknown":
                    infra_summary += f" IP reputation: {reputation} (local)."

                print(result)
                print(infra_summary)

    elif args.command == "score-file":
        if not args.input_path.exists():
            raise SystemExit(f"Input file not found: {args.input_path}")

        # Resolve input format
        input_format = args.input_format
        if input_format == "auto":
            if args.input_path.suffix.lower() == ".csv":
                input_format = "csv"
            else:
                input_format = "txt"

        # Load URLs from file
        urls: List[str] = []
        if input_format == "txt":
            text = args.input_path.read_text(encoding="utf-8")
            for line in text.splitlines():
                line = line.strip()
                if line:
                    urls.append(line)
        elif input_format == "csv":
            with args.input_path.open("r", encoding="utf-8", newline="") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    value = row.get(args.url_column, "").strip()
                    if value:
                        urls.append(value)
        else:
            raise SystemExit("input-format must be one of: auto, txt, csv")

        # Score URLs
        results = [enrich_score(url) for url in urls]

        # Format output
        if args.output_format == "json":
            indent = 2 if args.json_pretty else None
            output_text = json.dumps(results, indent=indent)
        elif args.output_format == "csv":
            fieldnames = ["url", "label", "prob_malicious", "final_label", "risk", "reasons"]
            from io import StringIO
            buf = StringIO()
            writer = csv.DictWriter(buf, fieldnames=fieldnames)
            writer.writeheader()
            for r in results:
                writer.writerow({
                    "url": r["url"],
                    "label": r["label"],
                    "prob_malicious": f"{r['prob_malicious']:.6f}",
                    "final_label": r["final_label"],
                    "risk": r["risk"],
                    "reasons": "; ".join(r.get("reasons", [])),
                })
            output_text = buf.getvalue()
        else:
            raise SystemExit("output-format must be one of: csv, json")

        # Write or print
        if args.output:
            args.output.write_text(output_text, encoding="utf-8")
        else:
            print(output_text)


    else:
        parser.print_help()


if __name__ == "__main__":
    main()

