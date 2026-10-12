"""Command-line interface for LogSentinel."""

import argparse
import sys
from pathlib import Path

from logsentinel.ingestion import LogIngestionError
from logsentinel.reporting import (
    export_json_report,
    generate_investigation_report,
)


def build_parser() -> argparse.ArgumentParser:
    """Build the command-line argument parser."""
    parser = argparse.ArgumentParser(
        description="Analyze security logs and generate an investigation report."
    )
    parser.add_argument(
        "--input",
        type=Path,
        default=Path("examples/sample_security.log"),
        help="Path to the input security log file.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("investigation_report.json"),
        help="Path where the JSON report will be saved.",
    )
    return parser


def main() -> int:
    """Run LogSentinel and return a process exit code."""
    parser = build_parser()
    args = parser.parse_args()

    try:
        report = generate_investigation_report(args.input)
        export_json_report(report, args.output)
    except (LogIngestionError, OSError, ValueError) as exc:
        print(f"LogSentinel error: {exc}", file=sys.stderr)
        return 1

    summary = report["summary"]

    print("LogSentinel — Security Investigation Report")
    print("=" * 44)
    print(f"Input file:       {args.input}")
    print(f"Output file:      {args.output}")
    print(f"Events analyzed:  {summary['total_events']}")
    print(f"Findings:         {summary['total_findings']}")
    print(f"Unique source IPs: {summary['unique_source_ips']}")
    print(f"Parse errors:     {len(report['parse_errors'])}")

    if report["findings"]:
        print("\nFindings:")
        for finding in report["findings"]:
            print(
                f"  [{finding['severity']}] "
                f"{finding['rule_id']} — {finding['rule_name']}"
            )
            print(f"    Source IP: {finding['source_ip']}")
            print(f"    {finding['description']}")
    else:
        print("\nNo findings matched the configured detection rules.")

    if report["parse_errors"]:
        print("\nMalformed log lines:")
        for error in report["parse_errors"]:
            print(
                f"  Line {error['line_number']}: {error['error']}"
            )

    print("\nReport generated successfully.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
