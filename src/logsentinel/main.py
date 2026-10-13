"""Command-line interface for LogSentinel."""

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from logsentinel.ingestion import LogIngestionError
from logsentinel.reporting import (
    export_json_report,
    generate_investigation_report,
)


def build_parser() -> argparse.ArgumentParser:
    """Build the command-line argument parser."""
    parser = argparse.ArgumentParser(
        prog="logsentinel",
        description=(
            "LogSentinel - Security Log Analysis and Threat Detection.\n"
            "Analyze security logs, detect suspicious activity, and generate reports."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  python -m logsentinel.main
  python -m logsentinel.main --input examples/sample_security.log
  python -m logsentinel.main --output reports/investigation.json
  python -m logsentinel.main --format json
  python -m logsentinel.main --top-ips 10
  python -m logsentinel.main --fail-on-findings

Exit codes:
  0  Analysis completed successfully
  1  Input, output, or analysis error
  2  Invalid arguments, or findings detected with --fail-on-findings
""",
    )
    parser.add_argument(
        "--input",
        type=Path,
        default=Path("examples/sample_security.log"),
        metavar="FILE",
        help="Input security log file (default: examples/sample_security.log).",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("investigation_report.json"),
        metavar="FILE",
        help="Path for the generated JSON report (default: investigation_report.json).",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Terminal output format: text or json (default: text).",
    )
    parser.add_argument(
        "--top-ips",
        type=int,
        default=5,
        metavar="N",
        help="Number of top source IPs to include (default: 5).",
    )
    parser.add_argument(
        "--fail-on-findings",
        action="store_true",
        help="Return exit code 2 when security findings are detected.",
    )
    return parser


def _print_text_report(
    report: dict[str, Any],
    input_path: Path,
    output_path: Path,
) -> None:
    """Print a human-readable investigation summary."""
    summary = report["summary"]

    print("LogSentinel - Security Investigation Report")
    print("=" * 44)
    print(f"Input file:       {input_path}")
    print(f"Output file:      {output_path}")
    print(f"Events analyzed:  {summary['total_events']}")
    print(f"Findings:         {summary['total_findings']}")
    print(f"Unique source IPs: {summary['unique_source_ips']}")
    print(f"Parse errors:     {len(report['parse_errors'])}")

    print("\nTop source IPs:")
    top_ips = summary["top_source_ips"]

    if top_ips:
        for item in top_ips:
            print(f"  {item['source_ip']}: {item['event_count']} events")
    else:
        print("  No source IPs found.")

    if report["findings"]:
        print("\nFindings:")

        for finding in report["findings"]:
            print(
                f"  [{finding['severity']}] "
                f"{finding['rule_id']} - {finding['rule_name']}"
            )
            print(f"    Source IP: {finding['source_ip']}")
            print(f"    {finding['description']}")
    else:
        print("\nNo findings matched the configured detection rules.")

    if report["parse_errors"]:
        print("\nMalformed log lines:")

        for error in report["parse_errors"]:
            print(f"  Line {error['line_number']}: {error['error']}")

    print("\nReport generated successfully.")


def main() -> int:
    """Run LogSentinel and return a process exit code."""
    parser = build_parser()
    args = parser.parse_args()

    if args.top_ips < 1:
        parser.error("--top-ips must be at least 1")

    if not args.input.exists():
        print(
            f"LogSentinel error: Input file does not exist: {args.input}",
            file=sys.stderr,
        )
        return 1

    if not args.input.is_file():
        print(
            f"LogSentinel error: Input path is not a file: {args.input}",
            file=sys.stderr,
        )
        return 1

    try:
        report = generate_investigation_report(
            args.input,
            top_ip_limit=args.top_ips,
        )
        export_json_report(report, args.output)
    except (LogIngestionError, OSError, ValueError) as exc:
        print(f"LogSentinel error: {exc}", file=sys.stderr)
        return 1

    if args.format == "json":
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        _print_text_report(report, args.input, args.output)

    if args.fail_on_findings and report["findings"]:
        return 2

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
