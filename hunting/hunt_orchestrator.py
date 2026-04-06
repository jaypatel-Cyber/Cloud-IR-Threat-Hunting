#!/usr/bin/env python3
# Author: Jay Patel
"""
Cloud Threat Hunt Orchestrator — end-to-end CloudTrail investigation pipeline:

  [1] Ingest   — load CloudTrail logs from local file or S3
  [2] Detect   — run all six anomaly detection modules
  [3] Triage   — collect and deduplicate suspect IPs across all findings
  [4] Profile  — optionally print full MITRE-mapped profiles per suspect
  [5] Report   — write a structured JSON investigation report

Usage:
  python hunt_orchestrator.py --input ../sample_data/cloudtrail_logs.json
  python hunt_orchestrator.py --input ../sample_data/cloudtrail_logs.json --profile-suspects
  python hunt_orchestrator.py --s3-bucket my-cloudtrail-bucket --s3-prefix AWSLogs/
  python hunt_orchestrator.py --input ../sample_data/cloudtrail_logs.json --json
"""

import argparse
import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List

import pandas as pd

# Allow running from the hunting/ directory directly
sys.path.insert(0, str(Path(__file__).parent))

from cloudtrail_ingestor import load_from_file, load_from_s3, build_dataframe
from anomaly_detector import run_all_detections
from ip_profiler import profile_ip, profile_ip_json

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger(__name__)

REPORT_DIR = Path(os.environ.get("REPORT_DIR", "reports"))

# AWS service pseudo-IPs to exclude from suspect list
AWS_SERVICE_PATTERNS = frozenset({
    "amazonaws.com", "AWS Internal",
})


def _is_aws_service_ip(ip: str) -> bool:
    return any(p in ip for p in AWS_SERVICE_PATTERNS)


def collect_suspect_ips(results: Dict[str, pd.DataFrame]) -> List[str]:
    """
    Aggregate suspect IPs across all detection modules and deduplicate.
    AWS service pseudo-IPs are excluded.
    """
    suspects: set = set()

    for module_name, result_df in results.items():
        if result_df.empty or "sourceIPAddress" not in result_df.columns:
            continue
        ips = result_df["sourceIPAddress"].dropna().unique().tolist()
        suspects.update(ips)

    suspects = {ip for ip in suspects if not _is_aws_service_ip(ip)}
    return sorted(suspects)


def score_suspects(suspects: List[str], results: Dict[str, pd.DataFrame]) -> Dict[str, int]:
    """
    Assign a simple risk score to each suspect IP: +1 for each detection
    module that flagged it. Higher score = appeared in more detection modules.
    """
    scores: Dict[str, int] = {ip: 0 for ip in suspects}
    for module_name, result_df in results.items():
        if result_df.empty or "sourceIPAddress" not in result_df.columns:
            continue
        for ip in result_df["sourceIPAddress"].dropna().unique():
            if ip in scores:
                scores[ip] += 1
    return dict(sorted(scores.items(), key=lambda x: -x[1]))


def generate_report(
    df: pd.DataFrame,
    results: Dict[str, pd.DataFrame],
    suspects: List[str],
    scores: Dict[str, int],
    report_path: Path,
) -> None:
    """Write a structured JSON investigation report to disk."""
    report = {
        "schema_version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "log_summary": {
            "total_events": len(df),
            "time_range": {
                "start": str(df["eventTime"].min()),
                "end": str(df["eventTime"].max()),
            },
            "unique_source_ips": int(df["sourceIPAddress"].nunique()),
            "unique_users": int(df["userName"].nunique()),
            "unique_regions": df["awsRegion"].dropna().unique().tolist(),
            "error_events": int(df["errorCode"].notna().sum()),
        },
        "detection_summary": {
            k: {"findings": len(v), "has_alerts": not v.empty}
            for k, v in results.items()
        },
        "suspect_ips": [
            {"ip": ip, "risk_score": scores.get(ip, 0)}
            for ip in suspects
        ],
        "ip_profiles": {
            ip: profile_ip_json(df, ip)
            for ip in suspects
        },
        "findings": {
            k: json.loads(v.to_json(orient="records", date_format="iso", default_handler=str))
            for k, v in results.items()
            if not v.empty
        },
    }

    report_path.parent.mkdir(parents=True, exist_ok=True)
    with open(report_path, "w") as fh:
        json.dump(report, fh, indent=2, default=str)
    log.info(f"Report saved -> {report_path}")


def _print_banner(df: pd.DataFrame, results: Dict[str, pd.DataFrame],
                  suspects: List[str], scores: Dict[str, int],
                  report_path: Path) -> None:
    w = 64
    print(f"\n{'='*w}")
    print(f"  HUNT COMPLETE - Cloud IR & Threat Hunting Report")
    print(f"{'='*w}")
    print(f"  Events analyzed  : {len(df):,}")
    print(f"  Time range       : {df['eventTime'].min()}")
    print(f"                     {df['eventTime'].max()}")
    print(f"  Suspect IPs      : {len(suspects)}")
    print(f"\n  Detection Results:")
    for k, v in results.items():
        flag = "[!!]" if not v.empty else "[ OK]"
        print(f"    {flag} {k:<24} {len(v):>3} finding(s)")
    if suspects:
        print(f"\n  Suspect IP Risk Scores:")
        for ip, score in scores.items():
            bar = "#" * score
            print(f"    {ip:<22}  score={score}  {bar}")
    print(f"\n  Report -> {report_path}")
    print(f"{'='*w}\n")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Cloud Threat Hunt Orchestrator — end-to-end CloudTrail investigation"
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--input", metavar="FILE",
                        help="Local CloudTrail JSON (or .json.gz) file")
    source.add_argument("--s3-bucket", metavar="BUCKET",
                        help="S3 bucket containing CloudTrail logs")

    parser.add_argument("--s3-prefix", metavar="PREFIX", default="",
                        help="S3 key prefix (folder) for CloudTrail objects")
    parser.add_argument("--profile-suspects", action="store_true",
                        help="Print full MITRE-mapped profile for each suspect IP")
    parser.add_argument(
        "--report", metavar="FILE",
        default=str(REPORT_DIR / f"hunt_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"),
        help="Output JSON report file path",
    )
    parser.add_argument("--json", action="store_true", dest="json_out",
                        help="Print summary as JSON instead of banner")
    args = parser.parse_args()

    # ── [1] Ingest ────────────────────────────────────────────────────────
    print(f"\n[1/5] Ingesting CloudTrail logs...")
    if args.input:
        records = load_from_file(args.input)
    else:
        records = load_from_s3(args.s3_bucket, args.s3_prefix)
    df = build_dataframe(records)

    # ── [2] Detect ────────────────────────────────────────────────────────
    print(f"[2/5] Running anomaly detection suite...")
    results = run_all_detections(df)

    # ── [3] Triage ────────────────────────────────────────────────────────
    suspects = collect_suspect_ips(results)
    scores = score_suspects(suspects, results)
    print(f"[3/5] Suspect IPs identified: {suspects}")

    # ── [4] Profile ───────────────────────────────────────────────────────
    if args.profile_suspects and suspects:
        print(f"[4/5] Profiling suspects...")
        for ip in suspects:
            profile_ip(df, ip)
    else:
        print(f"[4/5] Skipping profiles (use --profile-suspects to enable)")

    # ── [5] Report ────────────────────────────────────────────────────────
    print(f"[5/5] Generating investigation report...")
    report_path = Path(args.report)
    generate_report(df, results, suspects, scores, report_path)

    if args.json_out:
        out = {
            "suspects": [{"ip": ip, "risk_score": scores.get(ip, 0)} for ip in suspects],
            "detections": {k: len(v) for k, v in results.items()},
            "report": str(report_path),
        }
        print(json.dumps(out, indent=2))
    else:
        _print_banner(df, results, suspects, scores, report_path)


if __name__ == "__main__":
    main()
