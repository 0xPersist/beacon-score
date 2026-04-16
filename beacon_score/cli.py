#!/usr/bin/env python3
"""
beacon-score: Multi-signal C2 beacon detection from Zeek logs or PCAP.

Usage:
  beacon-score --conn conn.log --dns dns.log --ssl ssl.log
  beacon-score --pcap capture.pcap
  beacon-score --pcap capture.pcap --out report.json
  beacon-score --conn conn.log --config weights.yaml --top 10 --detail
  beacon-score --generate-config weights.yaml
"""

import argparse
import os
import sys


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="beacon-score",
        description=(
            "Multi-signal C2 beacon detector. Correlates Zeek conn.log, dns.log, "
            "and ssl.log to score and rank beacon candidates with ATT&CK mapping."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  beacon-score --conn conn.log --dns dns.log --ssl ssl.log
  beacon-score --pcap capture.pcap --out report.json --detail
  beacon-score --conn conn.log --config weights.yaml --top 5 --min-sessions 10
  beacon-score --generate-config my_weights.yaml
        """
    )

    # Input group
    input_group = parser.add_argument_group("input (choose one)")
    mx = input_group.add_mutually_exclusive_group()
    mx.add_argument(
        "--pcap", metavar="FILE",
        help="Raw PCAP file. Zeek is invoked automatically to generate logs."
    )
    mx.add_argument(
        "--conn", metavar="FILE",
        help="Zeek conn.log path (TSV or JSON format, optionally gzipped)."
    )

    input_group.add_argument(
        "--dns", metavar="FILE", default=None,
        help="Zeek dns.log path (optional but recommended)."
    )
    input_group.add_argument(
        "--ssl", metavar="FILE", default=None,
        help="Zeek ssl.log path (optional but recommended)."
    )

    # Output group
    output_group = parser.add_argument_group("output")
    output_group.add_argument(
        "--out", "-o", metavar="FILE", default=None,
        help="Write JSON report to this file (default: stdout only)."
    )
    output_group.add_argument(
        "--json-only", action="store_true",
        help="Suppress terminal table, print raw JSON to stdout."
    )
    output_group.add_argument(
        "--detail", "-d", action="store_true",
        help="Show per-signal breakdown panel for each candidate."
    )
    output_group.add_argument(
        "--top", "-n", metavar="N", type=int, default=20,
        help="Number of top candidates to show (default: 20)."
    )

    # Scoring group
    score_group = parser.add_argument_group("scoring")
    score_group.add_argument(
        "--config", metavar="FILE", default=None,
        help="YAML or TOML file with custom signal weights."
    )
    score_group.add_argument(
        "--min-sessions", metavar="N", type=int, default=5,
        help="Minimum session count to consider a destination (default: 5)."
    )
    score_group.add_argument(
        "--include-private", action="store_true",
        help="Include RFC1918/loopback destinations (excluded by default)."
    )
    score_group.add_argument(
        "--threshold", metavar="FLOAT", type=float, default=0.0,
        help="Only output candidates with total_score >= threshold."
    )

    # Utility
    util_group = parser.add_argument_group("utility")
    util_group.add_argument(
        "--generate-config", metavar="FILE", default=None,
        help="Write a default weights config file and exit."
    )
    util_group.add_argument(
        "--version", action="version", version="beacon-score 1.0.0"
    )

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    # -- Generate config and exit
    if args.generate_config:
        from beacon_score.config import generate_default_config
        fmt = "toml" if args.generate_config.endswith(".toml") else "yaml"
        generate_default_config(args.generate_config, fmt=fmt)
        print(f"Default config written to: {args.generate_config}")
        sys.exit(0)

    # -- Validate input
    if not args.pcap and not args.conn:
        parser.error("Provide either --pcap or --conn (with optional --dns and --ssl).")

    # -- Load weights
    from beacon_score.config import load_weights
    try:
        weights = load_weights(args.config)
    except (FileNotFoundError, ValueError, ImportError) as e:
        print(f"[ERROR] Config: {e}", file=sys.stderr)
        sys.exit(1)

    # -- Resolve log paths
    tmpdir = None
    conn_path = args.conn or ""
    dns_path = args.dns or ""
    ssl_path = args.ssl or ""

    if args.pcap:
        from beacon_score.pcap import generate_logs_from_pcap, cleanup_tmpdir, zeek_available
        if not zeek_available():
            print("[ERROR] Zeek not found. Install Zeek or use --conn/--dns/--ssl directly.", file=sys.stderr)
            sys.exit(1)
        try:
            result = generate_logs_from_pcap(args.pcap)
            tmpdir = result["tmpdir"]
            conn_path = result["conn"]
            dns_path = result["dns"]
            ssl_path = result["ssl"]
            if not conn_path:
                print("[ERROR] Zeek did not produce a conn.log. Check PCAP validity.", file=sys.stderr)
                sys.exit(1)
        except Exception as e:
            print(f"[ERROR] PCAP processing failed: {e}", file=sys.stderr)
            sys.exit(1)

    if not os.path.exists(conn_path):
        print(f"[ERROR] conn.log not found: {conn_path}", file=sys.stderr)
        sys.exit(1)

    # -- Run correlation and scoring
    from beacon_score.correlator import correlate_and_score
    try:
        candidates = correlate_and_score(
            conn_path=conn_path,
            dns_path=dns_path if dns_path and os.path.exists(dns_path) else "",
            ssl_path=ssl_path if ssl_path and os.path.exists(ssl_path) else "",
            weights=weights,
            min_sessions=args.min_sessions,
            exclude_private=not args.include_private,
            top_n=args.top,
        )
    except Exception as e:
        print(f"[ERROR] Scoring failed: {e}", file=sys.stderr)
        if tmpdir:
            from beacon_score.pcap import cleanup_tmpdir
            cleanup_tmpdir(tmpdir)
        sys.exit(1)

    # -- Apply threshold filter
    if args.threshold > 0.0:
        candidates = [c for c in candidates if c.total_score >= args.threshold]

    # -- Render output
    from beacon_score.renderer import render_summary_table, render_candidate_detail, render_json_output

    json_str = render_json_output(candidates)

    if args.json_only:
        print(json_str)
    else:
        try:
            from rich.console import Console
            console = Console()
        except ImportError:
            console = None

        render_summary_table(candidates, console=console)

        if args.detail:
            for c in candidates:
                render_candidate_detail(c, console=console)

        if not candidates:
            msg = (
                "No beacon candidates found above threshold. "
                f"Try --min-sessions {max(1, args.min_sessions - 2)} or --threshold 0."
            )
            if console:
                console.print(f"[dim]{msg}[/dim]")
            else:
                print(msg)

    if args.out:
        with open(args.out, "w") as f:
            f.write(json_str)
        msg = f"JSON report written to {args.out}"
        if not args.json_only:
            try:
                from rich.console import Console
                Console().print(f"[dim]{msg}[/dim]")
            except ImportError:
                print(msg)

    # -- Cleanup Zeek tmpdir if we generated it
    if tmpdir:
        cleanup_tmpdir(tmpdir)


if __name__ == "__main__":
    main()
